package session

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/mdrakib/tds-auth-proxy/internal/protocol"
)

func baseLogin() *protocol.Login7 {
	return &protocol.Login7{TDSVersion: protocol.TDSVersion74, PacketSize: 8000, UserName: "dev", Password: "pw", ServerName: "proxy", Database: "db"}
}

func TestCheckClientLogin(t *testing.T) {
	if err := checkClientLogin(baseLogin()); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*protocol.Login7){
		"integrated security": func(l *protocol.Login7) { l.OptionFlags2 |= protocol.Flag2IntSecurity },
		"sspi blob":           func(l *protocol.Login7) { l.SSPI = []byte("NTLMSSP") },
		"change password":     func(l *protocol.Login7) { l.ChangePassword = "new" },
		"user instance":       func(l *protocol.Login7) { l.OptionFlags3 |= protocol.Flag3UserInstance },
		"attach db":           func(l *protocol.Login7) { l.AtchDBFile = `C:\x.mdf` },
		"fedauth":             func(l *protocol.Login7) { l.Features = []protocol.Feature{{ID: protocol.FeatureFedAuth}} },
		"tds 7.1":             func(l *protocol.Login7) { l.TDSVersion = protocol.TDSVersion71 },
		"tds 8":               func(l *protocol.Login7) { l.TDSVersion = 0x08000000 },
		"no user":             func(l *protocol.Login7) { l.UserName = "" },
	}
	for name, mut := range cases {
		l := baseLogin()
		mut(l)
		var se *sessionError
		if err := checkClientLogin(l); !errors.As(err, &se) || se.clientNum != errLoginFailed {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestUpstreamLogin(t *testing.T) {
	c := baseLogin()
	c.Features = []protocol.Feature{
		{ID: protocol.FeatureSessionRecovery, Data: []byte{1}},
		{ID: protocol.FeatureUTF8Support, Data: []byte{}},
		{ID: protocol.FeatureAzureSQLDNSCaching},
		{ID: 0x42}, // unknown
		{ID: protocol.FeatureColumnEncryption, Data: []byte{2}},
	}
	u := upstreamLogin(c, "sql-a.internal")
	if u.UserName != "" || u.Password != "" || u.ServerName != "sql-a.internal" || u.Database != "db" || u.PacketSize != 8000 {
		t.Fatalf("%+v", u)
	}
	var ids []uint8
	for _, f := range u.Features {
		ids = append(ids, f.ID)
	}
	if len(ids) != 2 || ids[0] != protocol.FeatureUTF8Support || ids[1] != protocol.FeatureColumnEncryption {
		t.Fatalf("features %v", ids)
	}
	if c.Password != "pw" || c.UserName != "dev" {
		t.Fatal("client login must not be modified")
	}
}

func TestAllowed(t *testing.T) {
	p := func(s string) netip.Prefix { return netip.MustParsePrefix(s) }
	st := &State{
		GlobalAllowed: []netip.Prefix{p("10.0.0.0/8"), p("127.0.0.0/8")},
		Listeners:     map[string]Listener{"a": {Allowed: []netip.Prefix{p("10.1.0.0/16")}}, "b": {}},
	}
	for _, c := range []struct {
		l, ip string
		want  bool
	}{
		{"a", "10.1.2.3", true}, {"a", "10.2.0.1", false}, {"b", "10.2.0.1", true},
		{"b", "192.168.1.1", false}, {"b", "::ffff:127.0.0.1", true},
	} {
		if got := st.Allowed(c.l, netip.MustParseAddr(c.ip)); got != c.want {
			t.Errorf("%s %s: got %v", c.l, c.ip, got)
		}
	}
}
