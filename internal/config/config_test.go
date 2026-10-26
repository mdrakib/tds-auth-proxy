package config

import (
	"os"
	"strings"
	"testing"
)

func TestExampleConfigParses(t *testing.T) {
	b, err := os.ReadFile("../../config.example.yaml")
	if err != nil {
		t.Skip("config.example.yaml not present")
	}
	c, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Listeners) == 0 || len(c.Backends) == 0 {
		t.Fatal("example config is empty")
	}
}

const minimal = `
listeners:
  - {name: a, listen: "14331", backend: sql-a}
client_auth:
  users:
    - {username: dev, password_hash_env: H}
credential_profiles:
  p: {type: sql, username: u, password_file: /run/secrets/x}
backends:
  sql-a: {host: db, credentials: p}
tls: {client_certificate: c.crt, client_private_key: c.key}
`

func TestDefaults(t *testing.T) {
	c, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listeners[0].Listen != "127.0.0.1:14331" {
		t.Fatalf("listen default %q", c.Listeners[0].Listen)
	}
	if c.Backends["sql-a"].Port != 1433 || c.Server.MaxConnections != 200 || c.TLS.MaxVersion != "1.2" {
		t.Fatal("defaults not applied")
	}
	if !c.ClientAuth.Users[0].IsEnabled() {
		t.Fatal("users are enabled by default")
	}
}

func TestLoopbackDefault(t *testing.T) {
	for in, want := range map[string]string{
		"14331": "127.0.0.1:14331", ":14331": "127.0.0.1:14331",
		"0.0.0.0:14331": "0.0.0.0:14331", "[::1]:1": "[::1]:1",
	} {
		if got := LoopbackDefault(in); got != want {
			t.Errorf("%s -> %s, want %s", in, got, want)
		}
	}
}

func TestValidation(t *testing.T) {
	cases := map[string]struct{ from, to, want string }{
		"unknown key":             {"tls:", "bogus: 1\ntls:", "field bogus not found"},
		"unknown backend":         {"backend: sql-a", "backend: nope", `unknown backend "nope"`},
		"unknown profile":         {"credentials: p}", "credentials: q}", `unknown credential profile "q"`},
		"two hash sources":        {"password_hash_env: H}", "password_hash_env: H, password_hash: x}", "exactly one of"},
		"no tls":                  {"tls: {client_certificate: c.crt, client_private_key: c.key}", "", "client_certificate and client_private_key are required"},
		"bad profile type":        {"type: sql", "type: oauth", "unknown type"},
		"ntlm needs domain":       {"type: sql", "type: ntlm", "ntlm profiles require domain"},
		"bad cidr":                {"backend: sql-a}", "backend: sql-a, allowed_cidrs: [nope]}", "invalid CIDR"},
		"unknown allowed backend": {"password_hash_env: H}", "password_hash_env: H, allowed_backends: [zzz]}", "unknown backend"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(strings.Replace(minimal, c.from, c.to, 1)))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
}

func TestParseCIDRs(t *testing.T) {
	p, err := ParseCIDRs([]string{"10.0.0.0/8", "192.168.1.5", "fd00::/8"})
	if err != nil || len(p) != 3 || p[1].Bits() != 32 {
		t.Fatal(p, err)
	}
}
