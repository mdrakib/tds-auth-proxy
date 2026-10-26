package protocol

import (
	"bytes"
	"testing"
)

// The parsers below handle bytes from unauthenticated clients or from the
// network; they must never panic and must bound their allocations.

func FuzzParseLogin7(f *testing.F) {
	good, _ := sampleLogin().Marshal()
	f.Add(good)
	f.Add(good[:94])
	f.Fuzz(func(t *testing.T, b []byte) {
		l, err := ParseLogin7(b)
		if err != nil {
			return
		}
		// Anything we accept must re-encode and re-parse identically.
		out, err := l.Marshal()
		if err != nil {
			return // e.g. oversize after re-layout
		}
		if _, err := ParseLogin7(out); err != nil {
			t.Fatalf("re-encoded LOGIN7 does not parse: %v", err)
		}
	})
}

func FuzzParsePrelogin(f *testing.F) {
	p := &Prelogin{Options: []PreloginOption{{Token: PreloginVersion, Data: VersionOption(1, 2, 3)}, {Token: PreloginEncryption, Data: []byte{1}}}}
	f.Add(p.Marshal())
	f.Fuzz(func(t *testing.T, b []byte) {
		q, err := ParsePrelogin(b)
		if err != nil {
			return
		}
		if _, err := ParsePrelogin(q.Marshal()); err != nil {
			t.Fatalf("re-encoded PRELOGIN does not parse: %v", err)
		}
	})
}

func FuzzParseLoginTokens(f *testing.F) {
	f.Add(append(ErrorToken(1, 2, 3, "m", "s"), DoneToken(DoneError)...))
	f.Add([]byte{TokenFeatureExtAck, 1, 0, 0, 0, 0, 0xFF})
	f.Fuzz(func(t *testing.T, b []byte) {
		toks, err := ParseLoginTokens(b)
		if err != nil {
			return
		}
		var joined []byte
		for _, tk := range toks {
			joined = append(joined, tk.Raw...)
			switch tk.Type {
			case TokenEnvChange:
				ParseEnvChange(tk)
			case TokenError, TokenInfo:
				ParseServerMessage(tk)
			case TokenLoginAck:
				ParseLoginAck(tk)
			}
		}
		if !bytes.Equal(joined, b) {
			t.Fatal("tokens do not cover the input exactly")
		}
	})
}

func FuzzReadMessage(f *testing.F) {
	f.Add(packet(PacketPrelogin, StatusEOM, []byte{0xFF}))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := ReadMessage(bytes.NewReader(b), 4096, 8192)
		if err == nil && len(m.Payload) > 8192 {
			t.Fatal("limit exceeded")
		}
	})
}
