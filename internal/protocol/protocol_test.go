package protocol

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/mdrakib/tds-auth-proxy/internal/testutil"
)

func packet(typ PacketType, status uint8, payload []byte) []byte {
	b := make([]byte, HeaderSize, HeaderSize+len(payload))
	Header{Type: typ, Status: status, Length: uint16(HeaderSize + len(payload)), PacketID: 1}.Marshal(b)
	return append(b, payload...)
}

func TestReadMessageMultiPacket(t *testing.T) {
	var in bytes.Buffer
	in.Write(packet(PacketSQLBatch, 0, []byte("hello ")))
	in.Write(packet(PacketSQLBatch, 0, nil)) // empty intermediate packet
	in.Write(packet(PacketSQLBatch, StatusEOM, []byte("world")))
	m, err := ReadMessage(&in, MaxPacketSize, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if m.Type != PacketSQLBatch || string(m.Payload) != "hello world" {
		t.Fatalf("got %+v", m)
	}
}

func TestReadMessageRejectsBadInput(t *testing.T) {
	cases := map[string]struct {
		data    []byte
		wantErr error
	}{
		"length below header": {[]byte{0x12, 1, 0, 4, 0, 0, 1, 0}, ErrPacketTooShort},
		"length above max":    {[]byte{0x12, 1, 0x10, 0x01, 0, 0, 1, 0}, ErrPacketTooLarge},
		"message too large": {append(packet(PacketPrelogin, 0, make([]byte, 600)),
			packet(PacketPrelogin, StatusEOM, make([]byte, 600))...), ErrMessageTooLarge},
		"truncated payload": {packet(PacketPrelogin, StatusEOM, make([]byte, 10))[:12], io.ErrUnexpectedEOF},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ReadMessage(bytes.NewReader(c.data), 4096, 1000)
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("got %v, want %v", err, c.wantErr)
			}
		})
	}
	t.Run("type change", func(t *testing.T) {
		data := append(packet(PacketSQLBatch, 0, []byte("a")), packet(PacketRPC, StatusEOM, []byte("b"))...)
		if _, err := ReadMessage(bytes.NewReader(data), 4096, 1000); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestWriteMessageSplits(t *testing.T) {
	payload := bytes.Repeat([]byte{0xAB}, 1300)
	var out bytes.Buffer
	if err := WriteMessage(&out, PacketReply, 77, payload, 512); err != nil {
		t.Fatal(err)
	}
	raw := out.Bytes()
	var sizes []int
	for r := raw; len(r) > 0; {
		h := ParseHeader(r)
		if h.SPID != 77 {
			t.Fatal("SPID not propagated")
		}
		sizes = append(sizes, int(h.Length))
		if h.EOM() != (len(r) == int(h.Length)) {
			t.Fatal("EOM must be set on the last packet only")
		}
		r = r[h.Length:]
	}
	if !reflect.DeepEqual(sizes, []int{512, 512, 1300 - 2*504 + 8}) {
		t.Fatalf("packet sizes %v", sizes)
	}
	m, err := ReadMessage(bytes.NewReader(raw), 512, 4096)
	if err != nil || !bytes.Equal(m.Payload, payload) {
		t.Fatal("round trip failed", err)
	}
	// Empty payloads still produce one EOM packet.
	out.Reset()
	WriteMessage(&out, PacketReply, 0, nil, 4096)
	if out.Len() != HeaderSize || !ParseHeader(out.Bytes()).EOM() {
		t.Fatal("empty message")
	}
}

func TestPreloginRoundTrip(t *testing.T) {
	p := &Prelogin{Options: []PreloginOption{
		{Token: PreloginVersion, Data: VersionOption(16, 0, 1000)},
		{Token: PreloginEncryption, Data: []byte{EncryptOn | EncryptClientCert}},
		{Token: PreloginInstOpt, Data: []byte("MSSQLSERVER\x00")},
		{Token: PreloginThreadID, Data: nil},
		{Token: PreloginMARS, Data: []byte{1}},
	}}
	b := p.Marshal()
	// Option headers are 5 bytes each plus the terminator.
	if binary.BigEndian.Uint16(b[1:]) != 26 || b[25] != PreloginTerminator {
		t.Fatalf("unexpected layout % x", b[:26])
	}
	q, err := ParsePrelogin(b)
	if err != nil {
		t.Fatal(err)
	}
	if enc, _ := q.Encryption(); enc != EncryptOn || !q.MARS() {
		t.Fatal("options lost")
	}
	if d, _ := q.Get(PreloginInstOpt); string(d) != "MSSQLSERVER\x00" {
		t.Fatal("instance")
	}
}

func TestPreloginMalformed(t *testing.T) {
	for name, b := range map[string][]byte{
		"empty":           {},
		"no terminator":   {0x00, 0x00, 0x06, 0x00, 0x01},
		"truncated":       {0x00, 0x00},
		"out of bounds":   {0x00, 0x00, 0x06, 0x00, 0x09, 0xFF},
		"duplicate":       {0x01, 0x00, 0x0B, 0x00, 0x01, 0x01, 0x00, 0x0B, 0x00, 0x01, 0xFF, 0x00},
		"offset overflow": {0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
	} {
		if _, err := ParsePrelogin(b); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestPasswordEncoding(t *testing.T) {
	// "a" in UCS-2 is 61 00; MS-TDS obfuscation gives B3 A5.
	if got := EncodePassword([]byte{0x61, 0x00}); !bytes.Equal(got, []byte{0xB3, 0xA5}) {
		t.Fatalf("got % x", got)
	}
	for i := 0; i < 256; i++ {
		if DecodePassword(EncodePassword([]byte{byte(i)}))[0] != byte(i) {
			t.Fatalf("round trip failed for %d", i)
		}
	}
}

func sampleLogin() *Login7 {
	return &Login7{
		TDSVersion: TDSVersion74, PacketSize: 8000, ClientProgVer: 7, ClientPID: 1234, ConnectionID: 0,
		OptionFlags1: 0xE0, OptionFlags2: 0x03, TypeFlags: 0x20, OptionFlags3: 0x08,
		ClientTimeZone: -60, ClientLCID: 0x409, ClientID: [6]byte{1, 2, 3, 4, 5, 6},
		HostName: "workstation", UserName: "developer1", Password: "pässwörd ✓",
		AppName: "DBeaver", ServerName: "proxy.example.com", CltIntName: "Microsoft JDBC Driver",
		Language: "us_english", Database: "Sales",
		Features: []Feature{{ID: FeatureSessionRecovery, Data: []byte{1, 2, 3}}, {ID: FeatureUTF8Support}},
	}
}

func TestLogin7RoundTrip(t *testing.T) {
	l := sampleLogin()
	b, err := l.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if int(binary.LittleEndian.Uint32(b)) != len(b) {
		t.Fatal("length field")
	}
	got, err := ParseLogin7(b)
	if err != nil {
		t.Fatal(err)
	}
	want := *l
	want.OptionFlags3 |= Flag3Extension
	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", *got, want)
	}
	// The password is obfuscated on the wire, never in clear.
	if bytes.Contains(b, encodeUCS2(l.Password)) {
		t.Fatal("password stored in clear")
	}
}

func TestLogin7ReplaceVariableFields(t *testing.T) {
	l := sampleLogin()
	b, _ := l.Marshal()
	p, _ := ParseLogin7(b)
	p.UserName = strings.Repeat("u", 128)
	p.Password = ""
	p.SSPI = bytes.Repeat([]byte{0x4E}, 70000) // forces cbSSPILong
	p.OptionFlags2 |= Flag2IntSecurity
	out, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	q, err := ParseLogin7(out)
	if err != nil {
		t.Fatal(err)
	}
	if q.UserName != p.UserName || q.Password != "" || len(q.SSPI) != 70000 || q.Database != "Sales" || len(q.Features) != 2 {
		t.Fatalf("fields not preserved: user=%d pw=%q sspi=%d db=%q", len(q.UserName), q.Password, len(q.SSPI), q.Database)
	}
	if binary.LittleEndian.Uint16(out[offSSPI+2:]) != 0xFFFF || binary.LittleEndian.Uint32(out[offSSPILong:]) != 70000 {
		t.Fatal("cbSSPILong not used")
	}
}

func TestLogin7NoExtension(t *testing.T) {
	l := sampleLogin()
	l.Features = nil
	b, _ := l.Marshal()
	if b[27]&Flag3Extension != 0 {
		t.Fatal("fExtension set without features")
	}
	got, err := ParseLogin7(b)
	if err != nil || got.Features != nil {
		t.Fatal(err, got.Features)
	}
}

func TestLogin7Malformed(t *testing.T) {
	good, _ := sampleLogin().Marshal()
	mutate := func(f func(b []byte) []byte) []byte {
		return f(append([]byte(nil), good...))
	}
	cases := map[string][]byte{
		"too short":       good[:50],
		"length mismatch": mutate(func(b []byte) []byte { binary.LittleEndian.PutUint32(b, 5); return b }),
		"username beyond end": mutate(func(b []byte) []byte {
			binary.LittleEndian.PutUint16(b[offUserName+2:], 0xFFFF)
			return b
		}),
		"offset inside fixed header": mutate(func(b []byte) []byte {
			binary.LittleEndian.PutUint16(b[offHostName:], 10)
			return b
		}),
		"feature offset out of range": mutate(func(b []byte) []byte {
			ib := binary.LittleEndian.Uint16(b[offExtension:])
			binary.LittleEndian.PutUint32(b[ib:], 0xFFFFFF)
			return b
		}),
		"feature length overflow": mutate(func(b []byte) []byte {
			ib := binary.LittleEndian.Uint16(b[offExtension:])
			fo := binary.LittleEndian.Uint32(b[ib:])
			binary.LittleEndian.PutUint32(b[fo+1:], 0xFFFFFFF0)
			return b
		}),
		"feature missing terminator": mutate(func(b []byte) []byte {
			b = b[:len(b)-1]
			binary.LittleEndian.PutUint32(b, uint32(len(b)))
			return b
		}),
		"sspi long overflow": mutate(func(b []byte) []byte {
			binary.LittleEndian.PutUint16(b[offSSPI+2:], 0xFFFF)
			binary.LittleEndian.PutUint32(b[offSSPILong:], 0xFFFFFFFF)
			return b
		}),
	}
	for name, b := range cases {
		if _, err := ParseLogin7(b); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestLoginTokens(t *testing.T) {
	var p []byte
	env := []byte{TokenEnvChange, 0, 0, EnvPacketSize, 4, '8', 0, '0', 0, '0', 0, '0', 0, 4, '4', 0, '0', 0, '9', 0, '6', 0}
	binary.LittleEndian.PutUint16(env[1:], uint16(len(env)-3))
	p = append(p, env...)
	p = append(p, ErrorToken(18456, 1, 14, "Login failed for user 'x'.", "srv")...)
	p = append(p, TokenFeatureExtAck, FeatureUTF8Support, 1, 0, 0, 0, 1, FeatureTerminator)
	p = append(p, TokenSSPI, 3, 0, 'a', 'b', 'c')
	p = append(p, DoneToken(DoneError)...)
	toks, err := ParseLoginTokens(p)
	if err != nil {
		t.Fatal(err)
	}
	types := []uint8{}
	for _, tk := range toks {
		types = append(types, tk.Type)
	}
	if !reflect.DeepEqual(types, []uint8{TokenEnvChange, TokenError, TokenFeatureExtAck, TokenSSPI, TokenDone}) {
		t.Fatalf("types % x", types)
	}
	ec, err := ParseEnvChange(toks[0])
	if err != nil || ec.Type != EnvPacketSize || EnvString(ec.NewValue) != "8000" {
		t.Fatal(ec, err)
	}
	m, err := ParseServerMessage(toks[1])
	if err != nil || m.Number != 18456 || m.Class != 14 || m.Message != "Login failed for user 'x'." || m.ServerName != "srv" {
		t.Fatalf("%+v %v", m, err)
	}
	if string(toks[3].Body()) != "abc" || DoneStatus(toks[4]) != DoneError {
		t.Fatal("sspi/done")
	}
	if _, err := ParseLoginTokens([]byte{0x81, 0, 0}); err == nil {
		t.Fatal("unknown token accepted")
	}
	if _, err := ParseLoginTokens(p[:len(p)-3]); err == nil {
		t.Fatal("truncated stream accepted")
	}
}

// TestHandshakeConn performs a TLS handshake where both ends wrap the
// handshake in TDS PRELOGIN packets, then exchanges data in pass-through mode.
func TestHandshakeConn(t *testing.T) {
	pki := testutil.NewPKI(t)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	errc := make(chan error, 1)
	go func() {
		hc := NewHandshakeConn(b)
		tc := tls.Server(hc, pki.ServerTLS)
		if err := tc.Handshake(); err != nil {
			errc <- err
			return
		}
		if err := hc.EndHandshake(); err != nil {
			errc <- err
			return
		}
		buf := make([]byte, 5)
		if _, err := io.ReadFull(tc, buf); err != nil {
			errc <- err
			return
		}
		_, err := tc.Write(append([]byte("echo:"), buf...))
		errc <- err
	}()

	// Observe the raw client->server bytes: during the handshake they must be
	// PRELOGIN packets.
	rec := &recordConn{Conn: a}
	hc := NewHandshakeConn(rec)
	tc := tls.Client(hc, &tls.Config{RootCAs: pki.Pool, ServerName: "localhost"})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := hc.EndHandshake(); err != nil {
		t.Fatal(err)
	}
	if rec.buf.Len() == 0 || rec.buf.Bytes()[0] != byte(PacketPrelogin) {
		t.Fatalf("handshake not wrapped in PRELOGIN packets: % x", rec.buf.Bytes()[:8])
	}
	tc.Write([]byte("hello"))
	got := make([]byte, 10)
	if _, err := io.ReadFull(tc, got); err != nil || string(got) != "echo:hello" {
		t.Fatalf("got %q %v", got, err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

type recordConn struct {
	net.Conn
	buf bytes.Buffer
}

func (r *recordConn) Write(b []byte) (int, error) {
	r.buf.Write(b)
	return r.Conn.Write(b)
}

func TestHandshakeConnRejectsUnexpectedPacket(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	go b.Write(packet(PacketSQLBatch, StatusEOM, []byte("x")))
	hc := NewHandshakeConn(a)
	if _, err := hc.Read(make([]byte, 10)); err == nil {
		t.Fatal("expected error for non-PRELOGIN packet during handshake")
	}
}
