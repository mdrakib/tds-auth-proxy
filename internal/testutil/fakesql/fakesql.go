// Package fakesql is a minimal in-process SQL Server stand-in for tests. It
// speaks just enough TDS 7.4 to exercise the proxy: PRELOGIN, TLS-over-TDS,
// LOGIN7 with SQL or NTLM authentication (NTLMv2 proofs and channel bindings
// are genuinely verified), simple batches and ATTENTION.
package fakesql

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf16"

	"github.com/microsoft/go-mssqldb/integratedauth"
	"golang.org/x/crypto/md4"

	"github.com/mdrakib/tds-auth-proxy/internal/protocol"
)

// Server is a fake SQL Server. Fields must be set before Start; Password may
// be changed at any time with SetPassword to simulate rotation.
type Server struct {
	TLS      *tls.Config
	Mode     string // "sql" (default) or "ntlm"
	Username string
	Domain   string // ntlm
	// RequireChannelBinding rejects NTLM logins without a matching
	// MsvAvChannelBindings (Extended Protection = Required).
	RequireChannelBinding bool
	// NoEncryption answers PRELOGIN with ENCRYPT_NOT_SUP.
	NoEncryption bool
	// SendRouting adds a routing ENVCHANGE to the login response.
	SendRouting bool

	password atomic.Pointer[string]
	ln       net.Listener
	wg       sync.WaitGroup
	mu       sync.Mutex
	conns    map[net.Conn]bool
	spid     atomic.Uint32

	// Logins records every login attempt (username and outcome).
	LoginsMu sync.Mutex
	Logins   []Login
}

type Login struct {
	User       string
	OK         bool
	Reason     string
	Features   []uint8
	ServerName string
	AppName    string
	Database   string
}

func (s *Server) SetPassword(p string) { s.password.Store(&p) }

// Start listens on 127.0.0.1 with a random port.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	s.ln = ln
	s.conns = map[net.Conn]bool{}
	s.spid.Store(50)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns[c] = true
			s.mu.Unlock()
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.serve(c)
				s.mu.Lock()
				delete(s.conns, c)
				s.mu.Unlock()
				c.Close()
			}()
		}
	}()
	return nil
}

func (s *Server) Addr() *net.TCPAddr { return s.ln.Addr().(*net.TCPAddr) }

// ActiveConns returns the number of open client connections.
func (s *Server) ActiveConns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

func (s *Server) Close() {
	s.ln.Close()
	s.mu.Lock()
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *Server) record(l Login) {
	s.LoginsMu.Lock()
	s.Logins = append(s.Logins, l)
	s.LoginsMu.Unlock()
}

// LastLogin returns the most recent login attempt.
func (s *Server) LastLogin() Login {
	s.LoginsMu.Lock()
	defer s.LoginsMu.Unlock()
	if len(s.Logins) == 0 {
		return Login{}
	}
	return s.Logins[len(s.Logins)-1]
}

func (s *Server) serve(raw net.Conn) {
	msg, err := protocol.ReadMessage(raw, protocol.MaxPacketSize, 4096)
	if err != nil || msg.Type != protocol.PacketPrelogin {
		return
	}
	req, err := protocol.ParsePrelogin(msg.Payload)
	if err != nil {
		return
	}
	enc := byte(protocol.EncryptOn)
	if s.NoEncryption {
		enc = protocol.EncryptNotSup
	}
	mars := byte(0)
	if req.MARS() {
		mars = 1
	}
	resp := protocol.Prelogin{Options: []protocol.PreloginOption{
		{Token: protocol.PreloginVersion, Data: protocol.VersionOption(16, 0, 1000)},
		{Token: protocol.PreloginEncryption, Data: []byte{enc}},
		{Token: protocol.PreloginInstOpt, Data: []byte{0}},
		{Token: protocol.PreloginThreadID},
		{Token: protocol.PreloginMARS, Data: []byte{mars}},
	}}
	if protocol.WriteMessage(raw, protocol.PacketReply, 0, resp.Marshal(), 4096) != nil || s.NoEncryption {
		return
	}
	hc := protocol.NewHandshakeConn(raw)
	tc := tls.Server(hc, s.TLS)
	if tc.Handshake() != nil || hc.EndHandshake() != nil {
		return
	}
	spid := uint16(s.spid.Add(1))

	msg, err = protocol.ReadMessage(tc, protocol.MaxPacketSize, protocol.MaxLogin7Size)
	if err != nil || msg.Type != protocol.PacketLogin7 {
		return
	}
	login, err := protocol.ParseLogin7(msg.Payload)
	if err != nil {
		return
	}
	rec := Login{ServerName: login.ServerName, AppName: login.AppName, Database: login.Database}
	for _, f := range login.Features {
		rec.Features = append(rec.Features, f.ID)
	}
	ok, user, reason := s.authenticate(tc, spid, login)
	rec.User, rec.OK, rec.Reason = user, ok, reason
	s.record(rec)
	if !ok {
		p := protocol.ErrorToken(18456, 1, 14, fmt.Sprintf("Login failed for user '%s'.", user), "fake")
		p = append(p, protocol.DoneToken(protocol.DoneError)...)
		protocol.WriteMessage(tc, protocol.PacketReply, spid, p, 4096)
		return
	}
	pkt := int(login.PacketSize)
	if pkt < protocol.MinPacketSize || pkt > protocol.MaxPacketSize {
		pkt = 4096
	}
	var p []byte
	p = append(p, envChange(protocol.EnvDatabase, "master", "")...)
	p = append(p, envChange(protocol.EnvPacketSize, fmt.Sprint(pkt), "4096")...)
	if s.SendRouting {
		// Value: protocol(1) port(2) server US_VARCHAR(2+0); then empty old value.
		r := []byte{protocol.TokenEnvChange, 0, 0, protocol.EnvRouting, 5, 0, 0, 0x99, 0x05, 0, 0, 0, 0}
		binary.LittleEndian.PutUint16(r[1:], uint16(len(r)-3))
		p = append(p, r...)
	}
	p = append(p, loginAck()...)
	p = append(p, protocol.DoneToken(protocol.DoneFinal)...)
	if protocol.WriteMessage(tc, protocol.PacketReply, spid, p, 4096) != nil {
		return
	}
	s.session(tc, spid, pkt, user)
}

func (s *Server) authenticate(tc *tls.Conn, spid uint16, l *protocol.Login7) (bool, string, string) {
	pw := ""
	if p := s.password.Load(); p != nil {
		pw = *p
	}
	if s.Mode != "ntlm" {
		if l.OptionFlags2&protocol.Flag2IntSecurity != 0 {
			return false, "", "unexpected integrated security"
		}
		if l.UserName != s.Username || l.Password != pw {
			return false, l.UserName, "bad password"
		}
		return true, l.UserName, ""
	}

	if l.OptionFlags2&protocol.Flag2IntSecurity == 0 || !bytes.HasPrefix(l.SSPI, []byte("NTLMSSP\x00\x01")) {
		return false, l.UserName, "expected NTLM negotiate"
	}
	if l.UserName != "" || l.Password != "" {
		return false, l.UserName, "SQL credentials sent with integrated security"
	}
	var challenge [8]byte
	rand.Read(challenge[:])
	tok := ntlmChallenge(challenge, s.Domain)
	sspi := []byte{protocol.TokenSSPI, 0, 0}
	binary.LittleEndian.PutUint16(sspi[1:], uint16(len(tok)))
	sspi = append(sspi, tok...)
	if protocol.WriteMessage(tc, protocol.PacketReply, spid, sspi, 4096) != nil {
		return false, "", "write challenge"
	}
	msg, err := protocol.ReadMessage(tc, protocol.MaxPacketSize, 64*1024)
	if err != nil || msg.Type != protocol.PacketSSPI {
		return false, "", "expected SSPI message"
	}
	cs := tc.ConnectionState()
	return verifyNTLM(msg.Payload, challenge, s.Domain, s.Username, pw, s.RequireChannelBinding, cs)
}

// session answers batches until the client goes away.
func (s *Server) session(tc *tls.Conn, spid uint16, pkt int, user string) {
	for {
		msg, err := protocol.ReadMessage(tc, protocol.MaxPacketSize, 64<<20)
		if err != nil {
			return
		}
		switch msg.Type {
		case protocol.PacketAttention:
			protocol.WriteMessage(tc, protocol.PacketReply, spid, protocol.DoneToken(0x0020), pkt)
		case protocol.PacketSQLBatch:
			text := batchText(msg.Payload)
			switch {
			case strings.HasPrefix(text, "WAITFOR"):
				// Block until ATTENTION arrives, as SQL Server would.
				m, err := protocol.ReadMessage(tc, protocol.MaxPacketSize, 64<<20)
				if err != nil {
					return
				}
				if m.Type == protocol.PacketAttention {
					protocol.WriteMessage(tc, protocol.PacketReply, spid, protocol.DoneToken(0x0020), pkt)
				}
			case strings.Contains(text, "WHOAMI"):
				protocol.WriteMessage(tc, protocol.PacketReply, spid, nvarcharResult(user), pkt)
			case strings.HasPrefix(text, "BIG "):
				var n int
				fmt.Sscanf(text, "BIG %d", &n)
				protocol.WriteMessage(tc, protocol.PacketReply, spid, intRows(n), pkt)
			default:
				protocol.WriteMessage(tc, protocol.PacketReply, spid, intRows(1), pkt)
			}
		default:
			p := protocol.ErrorToken(50000, 1, 16, "fakesql: unsupported request", "fake")
			p = append(p, protocol.DoneToken(protocol.DoneError)...)
			protocol.WriteMessage(tc, protocol.PacketReply, spid, p, pkt)
		}
	}
}

func batchText(p []byte) string {
	if len(p) >= 4 {
		if h := int(binary.LittleEndian.Uint32(p)); h >= 4 && h <= len(p) {
			p = p[h:]
		}
	}
	u := make([]uint16, len(p)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(p[2*i:])
	}
	return strings.TrimSpace(string(utf16.Decode(u)))
}

func ucs2(s string) []byte {
	var b []byte
	for _, c := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	return b
}

func envChange(typ uint8, newV, oldV string) []byte {
	body := []byte{typ, byte(len([]rune(newV)))}
	body = append(body, ucs2(newV)...)
	body = append(body, byte(len([]rune(oldV))))
	body = append(body, ucs2(oldV)...)
	t := []byte{protocol.TokenEnvChange, 0, 0}
	binary.LittleEndian.PutUint16(t[1:], uint16(len(body)))
	return append(t, body...)
}

func loginAck() []byte {
	name := "Microsoft SQL Server"
	body := []byte{1, 0x74, 0, 0, 4, byte(len(name))}
	body = append(body, ucs2(name)...)
	body = append(body, 16, 0, 0x10, 0x00)
	t := []byte{protocol.TokenLoginAck, 0, 0}
	binary.LittleEndian.PutUint16(t[1:], uint16(len(body)))
	return append(t, body...)
}

func doneCount(n uint64) []byte {
	b := protocol.DoneToken(0x0010)
	binary.LittleEndian.PutUint16(b[3:], 0xC1)
	binary.LittleEndian.PutUint64(b[5:], n)
	return b
}

// intRows returns one INT column with values 1..n.
func intRows(n int) []byte {
	p := []byte{0x81, 1, 0, 0, 0, 0, 0, 0, 0, 0x38, 1, 'n', 0}
	for i := 1; i <= n; i++ {
		p = append(p, 0xD1)
		p = binary.LittleEndian.AppendUint32(p, uint32(i))
	}
	return append(p, doneCount(uint64(n))...)
}

func nvarcharResult(v string) []byte {
	p := []byte{0x81, 1, 0, 0, 0, 0, 0, 0, 0, 0xE7, 0, 1, 0x09, 0x04, 0xD0, 0x00, 0x34, 1, 'v', 0}
	p = append(p, 0xD1)
	val := ucs2(v)
	p = binary.LittleEndian.AppendUint16(p, uint16(len(val)))
	p = append(p, val...)
	return append(p, doneCount(1)...)
}

const (
	ntlmUnicode         = 0x00000001
	ntlmNTLM            = 0x00000200
	ntlmExtendedSession = 0x00080000
	ntlmTargetInfo      = 0x00800000
)

func ntlmChallenge(challenge [8]byte, domain string) []byte {
	target := ucs2(domain)
	var info []byte
	info = binary.LittleEndian.AppendUint16(info, 2) // MsvAvNbDomainName
	info = binary.LittleEndian.AppendUint16(info, uint16(len(target)))
	info = append(info, target...)
	info = append(info, 0, 0, 0, 0) // MsvAvEOL
	m := make([]byte, 48)
	copy(m, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(m[8:], 2)
	binary.LittleEndian.PutUint16(m[12:], uint16(len(target)))
	binary.LittleEndian.PutUint16(m[14:], uint16(len(target)))
	binary.LittleEndian.PutUint32(m[16:], 48)
	binary.LittleEndian.PutUint32(m[20:], ntlmUnicode|ntlmNTLM|ntlmExtendedSession|ntlmTargetInfo)
	copy(m[24:], challenge[:])
	binary.LittleEndian.PutUint16(m[40:], uint16(len(info)))
	binary.LittleEndian.PutUint16(m[42:], uint16(len(info)))
	binary.LittleEndian.PutUint32(m[44:], uint32(48+len(target)))
	m = append(m, target...)
	return append(m, info...)
}

func field(m []byte, off int) ([]byte, error) {
	if len(m) < off+8 {
		return nil, errors.New("short")
	}
	n := int(binary.LittleEndian.Uint16(m[off:]))
	o := int(binary.LittleEndian.Uint32(m[off+4:]))
	if o+n > len(m) {
		return nil, errors.New("field out of range")
	}
	return m[o : o+n], nil
}

func hmacMD5(key, data []byte) []byte {
	h := hmac.New(md5.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// verifyNTLM checks an NTLMv2 AUTHENTICATE message (MS-NLMP 3.3.2).
func verifyNTLM(m []byte, challenge [8]byte, domain, user, password string, requireCB bool, cs tls.ConnectionState) (bool, string, string) {
	if !bytes.HasPrefix(m, []byte("NTLMSSP\x00\x03\x00\x00\x00")) {
		return false, "", "not an AUTHENTICATE message"
	}
	nt, err1 := field(m, 20)
	dom, err2 := field(m, 28)
	usr, err3 := field(m, 36)
	if err1 != nil || err2 != nil || err3 != nil || len(nt) < 48 {
		return false, "", "malformed AUTHENTICATE message"
	}
	dec := func(b []byte) string {
		u := make([]uint16, len(b)/2)
		for i := range u {
			u[i] = binary.LittleEndian.Uint16(b[2*i:])
		}
		return string(utf16.Decode(u))
	}
	gotUser, gotDomain := dec(usr), dec(dom)
	identity := gotDomain + `\` + gotUser
	if !strings.EqualFold(gotUser, user) || !strings.EqualFold(gotDomain, domain) {
		return false, identity, "unknown account"
	}
	h := md4.New()
	h.Write(ucs2(password))
	key := hmacMD5(h.Sum(nil), ucs2(strings.ToUpper(gotUser)+gotDomain))
	proof, blob := nt[:16], nt[16:]
	if !hmac.Equal(proof, hmacMD5(key, append(challenge[:], blob...))) {
		return false, identity, "bad password"
	}
	if requireCB {
		cbt, err := integratedauth.GenerateCBTFromTLSConnState(cs)
		if err != nil || cbt == nil {
			return false, identity, "no channel binding available"
		}
		want := cbt.Md5Hash()
		if got := avPair(blob[28:], 0x000A); !bytes.Equal(got, want) {
			return false, identity, "channel binding mismatch"
		}
	}
	return true, identity, ""
}

func avPair(info []byte, id uint16) []byte {
	for len(info) >= 4 {
		aid := binary.LittleEndian.Uint16(info)
		n := int(binary.LittleEndian.Uint16(info[2:]))
		if aid == 0 || 4+n > len(info) {
			return nil
		}
		if aid == id {
			return info[4 : 4+n]
		}
		info = info[4+n:]
	}
	return nil
}
