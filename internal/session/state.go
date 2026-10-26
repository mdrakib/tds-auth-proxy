package session

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/netip"
	"os"

	"github.com/mdrakib/tds-auth-proxy/internal/auth"
	"github.com/mdrakib/tds-auth-proxy/internal/backend"
	"github.com/mdrakib/tds-auth-proxy/internal/config"
	"github.com/mdrakib/tds-auth-proxy/internal/credentials"
)

// State is an immutable, fully validated snapshot of everything a new
// session needs. Reloads build a new State and swap it in atomically;
// sessions keep the snapshot they started with.
type State struct {
	Config        *config.Config
	Auth          *auth.Authenticator
	Creds         credentials.CredentialProvider
	ClientTLS     *tls.Config
	Backends      map[string]Backend
	Listeners     map[string]Listener
	GlobalAllowed []netip.Prefix
}

type Backend struct {
	backend.Target
	Profile string
}

type Listener struct {
	Name    string
	Backend string
	Allowed []netip.Prefix
}

// BuildState validates secrets and certificates referenced by cfg and
// prepares TLS configurations.
func BuildState(cfg *config.Config, creds credentials.CredentialProvider) (*State, error) {
	s := &State{
		Config:    cfg,
		Creds:     creds,
		Backends:  map[string]Backend{},
		Listeners: map[string]Listener{},
	}
	var err error
	if s.Auth, err = auth.NewAuthenticator(cfg.ClientAuth.Users, cfg.Server.MaxConcurrentHashes); err != nil {
		return nil, err
	}
	minV, _ := config.TLSVersion(cfg.TLS.MinVersion)
	maxV, _ := config.TLSVersion(cfg.TLS.MaxVersion)

	cert, err := tls.LoadX509KeyPair(cfg.TLS.ClientCertificate, cfg.TLS.ClientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("loading client-facing TLS certificate: %w", err)
	}
	s.ClientTLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   minV,
		MaxVersion:   maxV,
		// Session tickets would be sent after the TDS-wrapped handshake
		// and are of no use to TDS clients.
		SessionTicketsDisabled: true,
	}

	if s.GlobalAllowed, err = config.ParseCIDRs(cfg.Server.AllowedCIDRs); err != nil {
		return nil, err
	}
	for _, l := range cfg.Listeners {
		allowed, err := config.ParseCIDRs(l.AllowedCIDRs)
		if err != nil {
			return nil, err
		}
		s.Listeners[l.Name] = Listener{Name: l.Name, Backend: l.Backend, Allowed: allowed}
	}

	globalVerify := cfg.TLS.BackendVerifyCertificate == nil || *cfg.TLS.BackendVerifyCertificate
	for name, b := range cfg.Backends {
		verify := globalVerify
		if b.VerifyCertificate != nil {
			verify = *b.VerifyCertificate
		}
		tc := &tls.Config{
			ServerName:         b.Host,
			MinVersion:         minV,
			MaxVersion:         maxV,
			InsecureSkipVerify: !verify,
			// One TLS record per TDS packet; see go-mssqldb issue #166.
			DynamicRecordSizingDisabled: true,
		}
		if b.TLSServerName != "" {
			tc.ServerName = b.TLSServerName
		}
		caFile := b.CAFile
		if caFile == "" {
			caFile = cfg.TLS.BackendCAFile
		}
		if caFile != "" {
			pem, err := os.ReadFile(caFile)
			if err != nil {
				return nil, fmt.Errorf("backend %q: reading CA file: %w", name, err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("backend %q: no certificates in CA file %s", name, caFile)
			}
			tc.RootCAs = pool
		}
		s.Backends[name] = Backend{
			Target: backend.Target{
				Name:           name,
				Host:           b.Host,
				Port:           b.Port,
				TLS:            tc,
				ConnectTimeout: b.ConnectTimeout,
			},
			Profile: b.Credentials,
		}
	}
	return s, nil
}

// Allowed reports whether addr may connect to listener.
func (s *State) Allowed(listener string, addr netip.Addr) bool {
	addr = addr.Unmap()
	match := func(list []netip.Prefix) bool {
		if len(list) == 0 {
			return true
		}
		for _, p := range list {
			if p.Contains(addr) {
				return true
			}
		}
		return false
	}
	return match(s.GlobalAllowed) && match(s.Listeners[listener].Allowed)
}
