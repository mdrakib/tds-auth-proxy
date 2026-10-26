// Package config loads and validates the proxy's YAML configuration.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server             Server                       `yaml:"server"`
	Logging            Logging                      `yaml:"logging"`
	Admin              Admin                        `yaml:"admin"`
	Listeners          []Listener                   `yaml:"listeners"`
	ClientAuth         ClientAuth                   `yaml:"client_auth"`
	CredentialProfiles map[string]CredentialProfile `yaml:"credential_profiles"`
	Backends           map[string]Backend           `yaml:"backends"`
	TLS                TLS                          `yaml:"tls"`
}

type Server struct {
	MaxConnections   int           `yaml:"max_connections"`
	HandshakeTimeout time.Duration `yaml:"handshake_timeout"`
	// IdleTimeout closes a session after no bytes flowed in either direction
	// for this long. Zero disables it.
	IdleTimeout     time.Duration `yaml:"idle_timeout"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
	// AllowedCIDRs, when non-empty, restricts which client addresses may
	// connect to any listener.
	AllowedCIDRs []string `yaml:"allowed_cidrs"`
	// AuthFailureDelay is waited before reporting a failed login.
	AuthFailureDelay time.Duration `yaml:"auth_failure_delay"`
	// MaxConcurrentHashes bounds concurrent Argon2id verifications, which
	// are deliberately memory hungry.
	MaxConcurrentHashes int `yaml:"max_concurrent_hashes"`
	// LockoutProtection pauses backend logins with credentials the backend
	// has rejected, so a stale password cannot lock the account.
	LockoutProtection LockoutProtection `yaml:"lockout_protection"`
}

type LockoutProtection struct {
	// Enabled defaults to true.
	Enabled *bool `yaml:"enabled"`
	// MaxParallelLogins bounds concurrent backend logins per credential
	// profile once its credentials are confirmed, and so the failed
	// attempts made if the password expires while logins are in flight.
	// Unconfirmed credentials are always tried one login at a time.
	MaxParallelLogins int `yaml:"max_parallel_logins"`
	// RetryInterval, when non-zero, allows one trial login with rejected,
	// unchanged credentials per interval. Zero waits for the secret to
	// change (or a configuration reload).
	RetryInterval time.Duration `yaml:"retry_interval"`
}

func (l LockoutProtection) IsEnabled() bool { return l.Enabled == nil || *l.Enabled }

type Logging struct {
	Level string `yaml:"level"` // debug, info, warn, error
}

type Admin struct {
	// Listen is the address of the health/metrics/reload HTTP server.
	// Empty disables it.
	Listen string `yaml:"listen"`
}

type Listener struct {
	Name         string   `yaml:"name"`
	Listen       string   `yaml:"listen"`
	Backend      string   `yaml:"backend"`
	AllowedCIDRs []string `yaml:"allowed_cidrs"`
}

type ClientAuth struct {
	Users []User `yaml:"users"`
}

type User struct {
	Username         string `yaml:"username"`
	PasswordHash     string `yaml:"password_hash"`
	PasswordHashEnv  string `yaml:"password_hash_env"`
	PasswordHashFile string `yaml:"password_hash_file"`
	Enabled          *bool  `yaml:"enabled"`
	// AllowedBackends restricts the backends this user may reach. Empty
	// means every backend; "*" may also be listed explicitly.
	AllowedBackends []string `yaml:"allowed_backends"`
}

func (u User) IsEnabled() bool { return u.Enabled == nil || *u.Enabled }

// Credential profile types.
const (
	CredSQL      = "sql"
	CredNTLM     = "ntlm"
	CredKerberos = "kerberos"
)

type CredentialProfile struct {
	Type         string `yaml:"type"`
	Domain       string `yaml:"domain"`
	Username     string `yaml:"username"`
	PasswordFile string `yaml:"password_file"`
	PasswordEnv  string `yaml:"password_env"`

	// NTLM
	Workstation string `yaml:"workstation"`
	// ChannelBinding sends TLS channel bindings (Extended Protection) with
	// NTLM. Defaults to true.
	ChannelBinding *bool `yaml:"channel_binding"`

	// Kerberos
	Realm          string `yaml:"realm"`
	Krb5ConfigFile string `yaml:"krb5_config"`
	KeytabFile     string `yaml:"keytab_file"`
	CredCacheFile  string `yaml:"credential_cache_file"`
	// SPN overrides the default MSSQLSvc/<host>:<port>.
	SPN string `yaml:"spn"`
}

type Backend struct {
	Host           string        `yaml:"host"`
	Port           int           `yaml:"port"`
	Credentials    string        `yaml:"credentials"`
	ConnectTimeout time.Duration `yaml:"connect_timeout"`
	// TLSServerName overrides the name verified against the certificate.
	TLSServerName string `yaml:"tls_server_name"`
	CAFile        string `yaml:"ca_file"`
	// VerifyCertificate overrides tls.backend_verify_certificate.
	VerifyCertificate *bool `yaml:"verify_certificate"`
}

type TLS struct {
	ClientCertificate string `yaml:"client_certificate"`
	ClientPrivateKey  string `yaml:"client_private_key"`
	// MinVersion/MaxVersion apply to both sides: "1.2" or "1.3".
	// TDS 7.x deployments generally require TLS 1.2.
	MinVersion               string `yaml:"min_version"`
	MaxVersion               string `yaml:"max_version"`
	BackendVerifyCertificate *bool  `yaml:"backend_verify_certificate"`
	BackendCAFile            string `yaml:"backend_ca_file"`
}

// Load reads, defaults and validates a configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse decodes YAML strictly (unknown keys are errors) and validates it.
func Parse(data []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	s := &c.Server
	if s.MaxConnections == 0 {
		s.MaxConnections = 200
	}
	if s.HandshakeTimeout == 0 {
		s.HandshakeTimeout = 15 * time.Second
	}
	if s.ShutdownTimeout == 0 {
		s.ShutdownTimeout = 20 * time.Second
	}
	if s.AuthFailureDelay == 0 {
		s.AuthFailureDelay = time.Second
	}
	if s.MaxConcurrentHashes == 0 {
		s.MaxConcurrentHashes = 4
	}
	if s.LockoutProtection.MaxParallelLogins == 0 {
		s.LockoutProtection.MaxParallelLogins = 2
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.TLS.MinVersion == "" {
		c.TLS.MinVersion = "1.2"
	}
	if c.TLS.MaxVersion == "" {
		c.TLS.MaxVersion = "1.2"
	}
	for i := range c.Listeners {
		c.Listeners[i].Listen = LoopbackDefault(c.Listeners[i].Listen)
	}
	for name, b := range c.Backends {
		if b.Port == 0 {
			b.Port = 1433
		}
		if b.ConnectTimeout == 0 {
			b.ConnectTimeout = 10 * time.Second
		}
		c.Backends[name] = b
	}
}

// LoopbackDefault binds addresses without an explicit host (":14331" or
// "14331") to 127.0.0.1, so exposure beyond the host is always deliberate.
func LoopbackDefault(addr string) string {
	if !strings.Contains(addr, ":") {
		return "127.0.0.1:" + addr
	}
	if strings.HasPrefix(addr, ":") {
		return "127.0.0.1" + addr
	}
	return addr
}

func (c *Config) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if c.Server.MaxConnections < 0 || c.Server.MaxConcurrentHashes < 0 {
		add("server: limits must be positive")
	}
	if lp := c.Server.LockoutProtection; lp.RetryInterval < 0 || lp.MaxParallelLogins < 0 {
		add("server.lockout_protection: retry_interval and max_parallel_logins must not be negative")
	}
	if _, err := ParseCIDRs(c.Server.AllowedCIDRs); err != nil {
		add("server.allowed_cidrs: %v", err)
	}
	switch strings.ToLower(c.Logging.Level) {
	case "debug", "info", "warn", "error":
	default:
		add("logging.level: unknown level %q", c.Logging.Level)
	}
	if c.TLS.ClientCertificate == "" || c.TLS.ClientPrivateKey == "" {
		add("tls: client_certificate and client_private_key are required (client connections must be encrypted)")
	}
	minV, err1 := TLSVersion(c.TLS.MinVersion)
	maxV, err2 := TLSVersion(c.TLS.MaxVersion)
	if err1 != nil || err2 != nil || minV > maxV {
		add("tls: invalid min_version/max_version")
	}

	if len(c.Listeners) == 0 {
		add("listeners: at least one listener is required")
	}
	names, addrs := map[string]bool{}, map[string]bool{}
	for i, l := range c.Listeners {
		if l.Name == "" {
			add("listeners[%d]: name is required", i)
		} else if names[l.Name] {
			add("listeners[%d]: duplicate name %q", i, l.Name)
		}
		names[l.Name] = true
		if _, port, err := net.SplitHostPort(l.Listen); err != nil {
			add("listener %q: invalid listen address %q", l.Name, l.Listen)
		} else if addrs[l.Listen] && port != "0" {
			add("listener %q: duplicate listen address %q", l.Name, l.Listen)
		}
		addrs[l.Listen] = true
		if _, ok := c.Backends[l.Backend]; !ok {
			add("listener %q: unknown backend %q", l.Name, l.Backend)
		}
		if _, err := ParseCIDRs(l.AllowedCIDRs); err != nil {
			add("listener %q: allowed_cidrs: %v", l.Name, err)
		}
	}

	for name, b := range c.Backends {
		if b.Host == "" {
			add("backend %q: host is required", name)
		}
		if b.Port <= 0 || b.Port > 65535 {
			add("backend %q: invalid port %d", name, b.Port)
		}
		if _, ok := c.CredentialProfiles[b.Credentials]; !ok {
			add("backend %q: unknown credential profile %q", name, b.Credentials)
		}
	}

	for name, p := range c.CredentialProfiles {
		if err := p.validate(); err != nil {
			add("credential profile %q: %v", name, err)
		}
	}

	users := map[string]bool{}
	for i, u := range c.ClientAuth.Users {
		key := strings.ToLower(u.Username)
		if u.Username == "" {
			add("client_auth.users[%d]: username is required", i)
		} else if users[key] {
			add("client_auth.users[%d]: duplicate username %q", i, u.Username)
		}
		users[key] = true
		n := 0
		for _, s := range []string{u.PasswordHash, u.PasswordHashEnv, u.PasswordHashFile} {
			if s != "" {
				n++
			}
		}
		if n != 1 {
			add("user %q: exactly one of password_hash, password_hash_env, password_hash_file is required", u.Username)
		}
		for _, b := range u.AllowedBackends {
			if _, ok := c.Backends[b]; !ok && b != "*" {
				add("user %q: allowed_backends references unknown backend %q", u.Username, b)
			}
		}
	}
	return errors.Join(errs...)
}

func (p CredentialProfile) validate() error {
	hasPassword := p.PasswordFile != "" || p.PasswordEnv != ""
	if p.PasswordFile != "" && p.PasswordEnv != "" {
		return errors.New("password_file and password_env are mutually exclusive")
	}
	switch p.Type {
	case CredSQL:
		if p.Username == "" || !hasPassword {
			return errors.New("sql profiles require username and password_file or password_env")
		}
	case CredNTLM:
		if p.Domain == "" || p.Username == "" || !hasPassword {
			return errors.New("ntlm profiles require domain, username and password_file or password_env")
		}
		if strings.ContainsAny(p.Username, `\@`) {
			return errors.New(`ntlm username must not contain a domain; use the domain field`)
		}
	case CredKerberos:
		if p.Username == "" && p.CredCacheFile == "" {
			return errors.New("kerberos profiles require username (with password or keytab) or credential_cache_file")
		}
		if p.Username != "" && !hasPassword && p.KeytabFile == "" {
			return errors.New("kerberos profiles with a username require password_file, password_env or keytab_file")
		}
		if p.Username != "" && p.Realm == "" && !strings.Contains(p.Username, "@") {
			return errors.New("kerberos profiles require realm (or username@REALM)")
		}
	default:
		return fmt.Errorf("unknown type %q (want sql, ntlm or kerberos)", p.Type)
	}
	return nil
}

// ParseCIDRs parses a list of CIDR prefixes or bare IP addresses.
func ParseCIDRs(list []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR or address %q", s)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}
