// Package credentials resolves backend credential profiles to concrete
// credentials at connection time, so secret rotation takes effect for every
// new backend connection without a restart.
package credentials

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/mdrakib/tds-auth-proxy/internal/config"
)

// Credentials are the resolved secrets for one backend login. Password is
// never logged; String redacts it.
type Credentials struct {
	Type     string // config.CredSQL, CredNTLM or CredKerberos
	Domain   string
	Username string
	Password string

	Workstation    string
	ChannelBinding bool

	Realm          string
	Krb5ConfigFile string
	KeytabFile     string
	CredCacheFile  string
	SPN            string
}

func (c Credentials) String() string {
	return fmt.Sprintf("Credentials{Type:%s Domain:%s Username:%s Password:<redacted>}", c.Type, c.Domain, c.Username)
}

// LogValue keeps passwords out of structured logs.
func (c Credentials) LogValue() slog.Value { return slog.StringValue(c.String()) }

// Identity is the upstream identity, for audit logs.
func (c Credentials) Identity() string {
	if c.Domain != "" {
		return c.Domain + `\` + c.Username
	}
	return c.Username
}

// CredentialProvider resolves a profile name to credentials.
type CredentialProvider interface {
	GetCredentials(ctx context.Context, profile string) (Credentials, error)
}

var ErrUnknownProfile = errors.New("unknown credential profile")

// Store is the CredentialProvider used by the proxy. Profile definitions are
// swapped atomically on configuration reload; password files are re-read
// whenever they change on disk (see FileSecrets). It is safe for concurrent use.
type Store struct {
	profiles atomic.Pointer[map[string]config.CredentialProfile]
	files    *FileSecrets
	env      *EnvSecrets
}

func NewStore(profiles map[string]config.CredentialProfile) *Store {
	s := &Store{files: NewFileSecrets(), env: NewEnvSecrets()}
	s.SetProfiles(profiles)
	return s
}

// WithProfiles returns a Store with the given profile definitions that shares
// this Store's secret caches. Configuration reloads use it so each State
// carries one consistent set of profiles.
func (s *Store) WithProfiles(p map[string]config.CredentialProfile) *Store {
	n := &Store{files: s.files, env: s.env}
	n.SetProfiles(p)
	return n
}

// SetProfiles replaces the profile definitions. Sessions already established
// keep running with the credentials they logged in with.
func (s *Store) SetProfiles(p map[string]config.CredentialProfile) {
	cp := make(map[string]config.CredentialProfile, len(p))
	for k, v := range p {
		cp[k] = v
	}
	s.profiles.Store(&cp)
}

func (s *Store) GetCredentials(ctx context.Context, profile string) (Credentials, error) {
	p, ok := (*s.profiles.Load())[profile]
	if !ok {
		return Credentials{}, fmt.Errorf("%w %q", ErrUnknownProfile, profile)
	}
	c := Credentials{
		Type:           p.Type,
		Domain:         p.Domain,
		Username:       p.Username,
		Workstation:    p.Workstation,
		ChannelBinding: p.ChannelBinding == nil || *p.ChannelBinding,
		Realm:          p.Realm,
		Krb5ConfigFile: p.Krb5ConfigFile,
		KeytabFile:     p.KeytabFile,
		CredCacheFile:  p.CredCacheFile,
		SPN:            p.SPN,
	}
	var err error
	switch {
	case p.PasswordFile != "":
		c.Password, err = s.files.Get(p.PasswordFile)
	case p.PasswordEnv != "":
		c.Password, err = s.env.Get(p.PasswordEnv)
	}
	if err != nil {
		return Credentials{}, fmt.Errorf("profile %q: %w", profile, err)
	}
	return c, nil
}
