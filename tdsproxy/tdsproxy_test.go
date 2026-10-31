package tdsproxy_test

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"net"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/microsoft/go-mssqldb"

	"github.com/mdrakib/tds-auth-proxy/internal/testutil"
	"github.com/mdrakib/tds-auth-proxy/internal/testutil/fakesql"
	"github.com/mdrakib/tds-auth-proxy/tdsproxy"
)

// authz accepts one client user and records every backend login outcome.
type authz struct {
	target   tdsproxy.Target
	password string

	mu       sync.Mutex
	outcomes []error
	logins   []tdsproxy.ClientLogin
}

func (a *authz) Authorize(_ context.Context, l *tdsproxy.ClientLogin) (*tdsproxy.Grant, error) {
	a.mu.Lock()
	a.logins = append(a.logins, tdsproxy.ClientLogin{Listener: l.Listener, User: l.User, AppName: l.AppName})
	pw := a.password
	a.mu.Unlock()
	if l.User != "app" || l.Password != "client-pw" {
		return nil, tdsproxy.LoginFailed(l.User, errors.New("wrong client password"))
	}
	return &tdsproxy.Grant{
		User:   l.User,
		Target: a.target,
		Creds:  tdsproxy.Credentials{Type: tdsproxy.CredSQL, Username: "svc_user", Password: pw},
		Done: func(err error) {
			a.mu.Lock()
			a.outcomes = append(a.outcomes, err)
			a.mu.Unlock()
		},
	}, nil
}

func (a *authz) lastOutcome(t *testing.T) error {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.outcomes) == 0 {
		t.Fatal("Done was never called")
	}
	return a.outcomes[len(a.outcomes)-1]
}

type env struct {
	pki   *testutil.PKI
	fake  *fakesql.Server
	authz *authz
	srv   *tdsproxy.Server
	addr  string

	mu     sync.Mutex
	opened []tdsproxy.SessionInfo
	closed []tdsproxy.CloseInfo
}

func newEnv(t *testing.T) *env { return newEnvWith(t, false, false) }

func newEnvWith(t *testing.T, loginOnly, unencrypted bool) *env {
	t.Helper()
	e := &env{pki: testutil.NewPKI(t)}
	e.fake = &fakesql.Server{TLS: e.pki.ServerTLS, Username: "svc_user"}
	e.fake.SetPassword("backend-pw")
	if err := e.fake.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.fake.Close)
	e.authz = &authz{password: "backend-pw", target: tdsproxy.Target{
		Name: "fake", Host: "127.0.0.1", Port: e.fake.Addr().Port, ConnectTimeout: 5 * time.Second,
		TLS: &tls.Config{RootCAs: e.pki.Pool, ServerName: "localhost", DynamicRecordSizingDisabled: true},
	}}
	e.srv = tdsproxy.New(tdsproxy.Config{
		Authorizer:          e.authz,
		ClientTLS:           func() *tls.Config { return e.pki.ServerTLS },
		HandshakeTimeout:    5 * time.Second,
		AuthFailureDelay:    -1,
		LoginOnlyEncryption: loginOnly,
		AllowUnencrypted:    unencrypted,
		OnOpen: func(i tdsproxy.SessionInfo) {
			e.mu.Lock()
			e.opened = append(e.opened, i)
			e.mu.Unlock()
		},
		OnClose: func(_ tdsproxy.SessionInfo, c tdsproxy.CloseInfo) {
			e.mu.Lock()
			e.closed = append(e.closed, c)
			e.mu.Unlock()
		},
	})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		e.srv.Shutdown(ctx)
	})
	e.addr = e.listen(t, "ep1")
	return e
}

func (e *env) listen(t *testing.T, name string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.srv.Serve(ln, name); err != nil {
		t.Fatal(err)
	}
	return ln.Addr().String()
}

func (e *env) open(t *testing.T, addr, user, password string, extra ...string) *sql.DB {
	t.Helper()
	q := url.Values{}
	q.Set("encrypt", "true")
	for i := 0; i+1 < len(extra); i += 2 {
		q.Set(extra[i], extra[i+1])
	}
	q.Set("certificate", e.pki.CAFile)
	q.Set("hostnameincertificate", "localhost")
	q.Set("connection timeout", "10")
	q.Set("app name", "tdsproxy-test")
	u := url.URL{Scheme: "sqlserver", User: url.UserPassword(user, password), Host: addr, RawQuery: q.Encode()}
	db, err := sql.Open("sqlserver", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func whoami(db *sql.DB) (string, error) {
	var who string
	err := db.QueryRow("SELECT WHOAMI").Scan(&who)
	return who, err
}

func TestEmbeddedLoginAndRelay(t *testing.T) {
	e := newEnv(t)
	db := e.open(t, e.addr, "app", "client-pw")
	who, err := whoami(db)
	if err != nil {
		t.Fatal(err)
	}
	if who != "svc_user" {
		t.Fatalf("backend identity = %q, want svc_user", who)
	}
	if err := e.authz.lastOutcome(t); err != nil {
		t.Fatalf("Done(%v), want nil", err)
	}
	s := e.srv.Sessions()
	if len(s) != 1 || s[0].Listener != "ep1" || s[0].ClientUser != "app" || s[0].BackendUser != "svc_user" || s[0].ClientApp != "tdsproxy-test" {
		t.Fatalf("Sessions() = %+v", s)
	}
	if e.authz.logins[0].Listener != "ep1" {
		t.Fatalf("Authorize saw listener %q", e.authz.logins[0].Listener)
	}
}

func TestEmbeddedWrongClientPasswordNeverReachesBackend(t *testing.T) {
	e := newEnv(t)
	_, err := whoami(e.open(t, e.addr, "app", "nope"))
	if err == nil || !strings.Contains(err.Error(), "Login failed for user 'app'") {
		t.Fatalf("err = %v, want generic login failure", err)
	}
	e.fake.LoginsMu.Lock()
	n := len(e.fake.Logins)
	e.fake.LoginsMu.Unlock()
	if n != 0 {
		t.Fatalf("backend saw %d logins", n)
	}
}

func TestEmbeddedBackendRejectionIsReported(t *testing.T) {
	e := newEnv(t)
	e.authz.mu.Lock()
	e.authz.password = "stale"
	e.authz.mu.Unlock()
	if _, err := whoami(e.open(t, e.addr, "app", "client-pw")); err == nil {
		t.Fatal("login with a stale backend password succeeded")
	}
	got := e.authz.lastOutcome(t)
	if !tdsproxy.CredentialsRejected(got) {
		t.Fatalf("CredentialsRejected(%v) = false", got)
	}
	se, ok := tdsproxy.BackendLoginError(got)
	if !ok || se.Number != 18456 {
		t.Fatalf("BackendLoginError = %+v, %v", se, ok)
	}
}

func TestEmbeddedCloseListener(t *testing.T) {
	e := newEnv(t)
	db := e.open(t, e.addr, "app", "client-pw")
	db.SetMaxOpenConns(1)
	if _, err := whoami(db); err != nil {
		t.Fatal(err)
	}

	// Without closeSessions the established session keeps working.
	e.srv.Close("ep1", false)
	if _, err := whoami(db); err != nil {
		t.Fatalf("session closed with the listener: %v", err)
	}
	if _, err := net.DialTimeout("tcp", e.addr, time.Second); err == nil {
		t.Fatal("listener still accepts")
	}

	// A new listener under the same name; closing the name with sessions
	// ends every session accepted under it, old listener included.
	addr := e.listen(t, "ep1")
	db2 := e.open(t, addr, "app", "client-pw")
	db2.SetMaxOpenConns(1)
	if _, err := whoami(db2); err != nil {
		t.Fatal(err)
	}
	e.srv.Close("ep1", true)
	deadline := time.Now().Add(3 * time.Second)
	for len(e.srv.Sessions()) > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := len(e.srv.Sessions()); n != 0 {
		t.Fatalf("%d sessions after Close(ep1, true)", n)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.closed) != 2 || len(e.opened) != 2 {
		t.Fatalf("opened %d, closed %d", len(e.opened), len(e.closed))
	}
}

// A client that offers no encryption (go-mssqldb encrypt=false, ODBC
// Encrypt=Optional) gets login-only encryption when it is enabled: the
// LOGIN7 travels over TLS and the session continues in clear. Clients asking
// for encryption are unaffected.
func TestEmbeddedLoginOnlyEncryption(t *testing.T) {
	e := newEnvWith(t, true, false)
	for _, enc := range []string{"false", "true"} {
		db := e.open(t, e.addr, "app", "client-pw", "encrypt", enc)
		if who, err := whoami(db); err != nil || who != "svc_user" {
			t.Fatalf("encrypt=%s: %q %v", enc, who, err)
		}
		// Many rows cross the relay after the switch to clear text.
		var n int
		rows, err := db.Query("BIG 5000")
		if err != nil {
			t.Fatalf("encrypt=%s: %v", enc, err)
		}
		for rows.Next() {
			n++
		}
		rows.Close()
		if n != 5000 {
			t.Fatalf("encrypt=%s: %d rows", enc, n)
		}
	}
	// A rejected login is reported in clear as well.
	_, err := whoami(e.open(t, e.addr, "app", "nope", "encrypt", "false"))
	if err == nil || !strings.Contains(err.Error(), "Login failed for user 'app'") {
		t.Fatalf("wrong password over login-only encryption: %v", err)
	}
}

// A client without encryption support (go-mssqldb encrypt=disable) is
// refused unless AllowUnencrypted is set; then it is served without TLS.
func TestEmbeddedUnencryptedClients(t *testing.T) {
	if _, err := whoami(newEnv(t).openDisabled(t)); err == nil {
		t.Fatal("unencrypted client accepted by default")
	}
	e := newEnvWith(t, false, true)
	db := e.openDisabled(t)
	if who, err := whoami(db); err != nil || who != "svc_user" {
		t.Fatalf("unencrypted client: %q %v", who, err)
	}
	_, err := whoami(e.open(t, e.addr, "app", "nope", "encrypt", "disable"))
	if err == nil || !strings.Contains(err.Error(), "Login failed for user 'app'") {
		t.Fatalf("wrong password without encryption: %v", err)
	}
	// Clients that ask for encryption still get it.
	if who, err := whoami(e.open(t, e.addr, "app", "client-pw")); err != nil || who != "svc_user" {
		t.Fatalf("encrypted client: %q %v", who, err)
	}
}

func (e *env) openDisabled(t *testing.T) *sql.DB {
	return e.open(t, e.addr, "app", "client-pw", "encrypt", "disable")
}
