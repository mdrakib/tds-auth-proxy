// Package tdsproxy embeds the authenticating TDS proxy in another program.
//
// The host program decides who may log in and where to: for each client
// login (SQL authentication, always over TLS) the Server calls the host's
// Authorizer, which returns the backend and the credentials to log in with
// (SQL, NTLM or Kerberos). After the backend login the session is relayed
// unchanged, exactly as in the standalone tds-proxy. Listeners are added and
// removed at runtime with Serve and Close.
//
// The proxy never parses or logs SQL text and never retries a backend
// login; lockout protection is the Authorizer's job (see Grant.Done).
package tdsproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/mdrakib/tds-auth-proxy/internal/backend"
	"github.com/mdrakib/tds-auth-proxy/internal/certgen"
	"github.com/mdrakib/tds-auth-proxy/internal/config"
	"github.com/mdrakib/tds-auth-proxy/internal/credentials"
	"github.com/mdrakib/tds-auth-proxy/internal/listener"
	"github.com/mdrakib/tds-auth-proxy/internal/monitoring"
	"github.com/mdrakib/tds-auth-proxy/internal/session"
)

type (
	// Credentials are the backend login secrets. Type is CredSQL, CredNTLM
	// or CredKerberos. String and LogValue redact the password.
	Credentials = credentials.Credentials
	// Target is the backend to log in to. TLS is required: backend sessions
	// are always encrypted, and TLS.ServerName is the name verified.
	Target = backend.Target
	// ClientLogin is a client's login request, handed to the Authorizer.
	ClientLogin = session.ClientLogin
	// Grant is a successful authorization.
	Grant = session.Grant
	// Authorizer authenticates client logins and chooses their backend.
	Authorizer = session.Authorizer
	// LoginFailure controls the error a rejected client is shown.
	LoginFailure = session.LoginFailure
	// SessionInfo describes an established session.
	SessionInfo = session.SessionInfo
	// CloseInfo describes how a session ended.
	CloseInfo = session.CloseInfo
)

// Backend credential types.
const (
	CredSQL      = config.CredSQL
	CredNTLM     = config.CredNTLM
	CredKerberos = config.CredKerberos
)

// ErrAbandoned is passed to Grant.Done when the session ended before the
// backend login completed (client gone, timeout, shutdown).
var ErrAbandoned = session.ErrAbandoned

// LoginFailed returns an error that tells the client the generic
// "Login failed for user '<user>'." (18456). err is logged, not shown.
func LoginFailed(user string, err error) error {
	return session.Fail("client_auth", 18456, session.LoginFailedMessage(user), err)
}

// Refuse returns an error that shows message to the client with error
// number 18456. category names the reason in the log.
func Refuse(category, message string, err error) error {
	return session.Fail(category, 18456, message, err)
}

// CredentialsRejected reports whether a backend login error (as passed to
// Grant.Done) means the server or KDC refused the credentials, as opposed to
// a network, TLS or request problem. Only such errors should count towards
// lockout protection.
func CredentialsRejected(err error) bool { return backend.CredentialsRejected(err) }

// ServerError is the first error the backend returned for a rejected login.
type ServerError struct {
	Number  int32
	State   uint8
	Class   uint8
	Message string
}

// BackendLoginError extracts the backend's own error from a login error
// passed to Grant.Done. ok is false for network, TLS and protocol failures.
func BackendLoginError(err error) (se ServerError, ok bool) {
	var le *backend.LoginError
	if !errors.As(err, &le) || len(le.Messages) == 0 {
		return ServerError{}, false
	}
	m := le.Messages[0]
	return ServerError{Number: m.Number, State: m.State, Class: m.Class, Message: m.Message}, true
}

// Config configures a Server. Zero durations take the standalone proxy's
// defaults.
type Config struct {
	Authorizer Authorizer
	// ClientTLS is the client-facing TLS configuration (certificate, versions).
	// It is read for every new connection, so it may be swapped at runtime.
	ClientTLS func() *tls.Config
	Logger    *slog.Logger

	HandshakeTimeout time.Duration // default 15s; covers everything until the login response
	IdleTimeout      time.Duration // 0 disables
	AuthFailureDelay time.Duration // default 1s; negative disables
	MaxConnections   int           // default 200, across all listeners
	// LoginOnlyEncryption serves clients that offer no encryption the way
	// SQL Server without forced encryption does: TLS protects only their
	// LOGIN7 (and so the password); the rest of their session is not
	// encrypted, and their client does not validate the certificate. Clients
	// that ask for encryption always get full TLS. Off (the default), every
	// client must use full TLS. The backend session is always encrypted.
	LoginOnlyEncryption bool
	// AllowUnencrypted accepts clients that do not support encryption at
	// all (go-mssqldb encrypt=disable, tedious encrypt=false) without TLS,
	// as SQL Server does without forced encryption. Their login, password
	// included, and their whole session travel in clear. Off (the default),
	// such clients are refused.
	AllowUnencrypted bool

	// Allowed, if set, filters client addresses per listener.
	Allowed func(listener string, addr netip.Addr) bool
	// OnOpen and OnClose, if set, are called for each session whose backend
	// login succeeded. They must not block.
	OnOpen  func(SessionInfo)
	OnClose func(SessionInfo, CloseInfo)
}

// Server accepts TDS clients on any number of named listeners.
type Server struct {
	cfg     Config
	srv     *listener.Server
	metrics *monitoring.Metrics

	mu       sync.Mutex
	sessions map[string]SessionInfo
}

// New returns a Server. It binds nothing until Serve is called.
func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = 15 * time.Second
	}
	if cfg.AuthFailureDelay == 0 {
		cfg.AuthFailureDelay = time.Second
	}
	cfg.AuthFailureDelay = max(cfg.AuthFailureDelay, 0)
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = 200
	}
	s := &Server{cfg: cfg, metrics: monitoring.NewMetrics(), sessions: map[string]SessionInfo{}}
	h := &session.Handler{
		Settings: func() session.Settings {
			return session.Settings{
				ClientTLS:           cfg.ClientTLS(),
				HandshakeTimeout:    cfg.HandshakeTimeout,
				IdleTimeout:         cfg.IdleTimeout,
				AuthFailureDelay:    cfg.AuthFailureDelay,
				LoginOnlyEncryption: cfg.LoginOnlyEncryption,
				AllowUnencrypted:    cfg.AllowUnencrypted,
			}
		},
		Authorizer: cfg.Authorizer,
		Metrics:    s.metrics,
		Logger:     cfg.Logger,
		OnOpen: func(i SessionInfo) {
			s.mu.Lock()
			s.sessions[i.ID] = i
			s.mu.Unlock()
			if cfg.OnOpen != nil {
				cfg.OnOpen(i)
			}
		},
		OnClose: func(i SessionInfo, c CloseInfo) {
			s.mu.Lock()
			delete(s.sessions, i.ID)
			s.mu.Unlock()
			if cfg.OnClose != nil {
				cfg.OnClose(i, c)
			}
		},
	}
	s.srv = &listener.Server{Handler: h, Metrics: s.metrics, Logger: cfg.Logger,
		Allowed: cfg.Allowed, MaxConnections: cfg.MaxConnections}
	return s
}

// Serve accepts connections on ln under the given listener name and returns
// at once. A listener already registered under name is closed first.
func (s *Server) Serve(ln net.Listener, name string) error { return s.srv.Serve(ln, name) }

// Close stops accepting on the named listener. With closeSessions its
// established sessions are closed too; otherwise they run until they end.
func (s *Server) Close(name string, closeSessions bool) { s.srv.Close(name, closeSessions) }

// Addrs returns the bound address of each listener.
func (s *Server) Addrs() map[string]net.Addr { return s.srv.Addrs() }

// Sessions returns the established sessions.
func (s *Server) Sessions() []SessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SessionInfo, 0, len(s.sessions))
	for _, i := range s.sessions {
		out = append(out, i)
	}
	return out
}

// Shutdown closes every listener and waits for sessions to end until ctx
// is done, then closes the rest.
func (s *Server) Shutdown(ctx context.Context) error { return s.srv.Shutdown(ctx) }

// ErrServerClosed is returned by Serve after Shutdown.
var ErrServerClosed = listener.ErrClosed

// Certificate describes a generated self-signed certificate.
type Certificate struct {
	CertFile, KeyFile string
	NotAfter          time.Time
	SHA256            string // fingerprint, for manual verification
}

// GenerateCertificate writes a self-signed RSA certificate (proxy.crt) and
// key (proxy.key, mode 0600) for hosts into dir, the same as
// `tds-proxy gen-cert`. Existing files are only replaced when force is set.
func GenerateCertificate(dir string, hosts []string, validFor time.Duration, force bool) (*Certificate, error) {
	r, err := certgen.Generate(dir, hosts, validFor, force)
	if err != nil {
		return nil, err
	}
	return &Certificate{CertFile: r.CertFile, KeyFile: r.KeyFile, NotAfter: r.NotAfter, SHA256: r.SHA256}, nil
}
