package app

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/microsoft/go-mssqldb"

	"github.com/mdrakib/tds-auth-proxy/internal/auth"
	"github.com/mdrakib/tds-auth-proxy/internal/testutil"
	"github.com/mdrakib/tds-auth-proxy/internal/testutil/fakesql"
)

const (
	clientPW  = "client-password-1"
	backendPW = "backend-password-v1"
)

var (
	hashOnce   sync.Once
	clientHash string
)

func clientHashFor(t *testing.T) string {
	hashOnce.Do(func() {
		// Cheap parameters keep tests fast under the race detector.
		h, err := auth.HashPasswordParams(clientPW, 1024, 1, 1)
		if err != nil {
			t.Fatal(err)
		}
		clientHash = h
	})
	return clientHash
}

type env struct {
	t       *testing.T
	dir     string
	pki     *testutil.PKI
	fake    *fakesql.Server
	app     *App
	cfgPath string
	secret  string
	opts    envOpts
}

type envOpts struct {
	ntlm          bool
	idleTimeout   string
	allowedCIDRs  string
	backendHost   string // default 127.0.0.1
	backendPort   int    // default fake port
	tlsServerName string
	extraUsers    string
	maxConns      int
}

func newEnv(t *testing.T, o envOpts) *env {
	t.Helper()
	e := &env{t: t, dir: t.TempDir(), pki: testutil.NewPKI(t), opts: o}
	e.fake = &fakesql.Server{TLS: e.pki.ServerTLS, Username: "svc_user"}
	if o.ntlm {
		e.fake.Mode, e.fake.Domain, e.fake.RequireChannelBinding = "ntlm", "CORP", true
	}
	e.fake.SetPassword(backendPW)
	if err := e.fake.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.fake.Close)
	e.secret = filepath.Join(e.dir, "backend-password")
	e.rotateSecret(backendPW + "\n")
	e.writeConfig("")

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	if testing.Verbose() {
		logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	a, err := New(e.cfgPath, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	e.app = a
	t.Cleanup(func() { a.Shutdown(context.Background()) })
	return e
}

func (e *env) writeConfig(extraUsers string) {
	o := e.opts
	host, port := o.backendHost, o.backendPort
	if host == "" {
		host = "127.0.0.1"
	}
	if port == 0 {
		port = e.fake.Addr().Port
	}
	profile := fmt.Sprintf("type: sql\n    username: svc_user\n    password_file: %s", e.secret)
	if o.ntlm {
		profile = fmt.Sprintf("type: ntlm\n    domain: CORP\n    username: svc_user\n    password_file: %s", e.secret)
	}
	idle := o.idleTimeout
	if idle == "" {
		idle = "0s"
	}
	cidrs := o.allowedCIDRs
	if cidrs == "" {
		cidrs = "[]"
	}
	maxConns := o.maxConns
	if maxConns == 0 {
		maxConns = 200
	}
	h := clientHashFor(e.t)
	cfg := fmt.Sprintf(`
server:
  max_connections: %d
  handshake_timeout: 5s
  idle_timeout: %s
  shutdown_timeout: 2s
  auth_failure_delay: 1ms
  allowed_cidrs: %s
listeners:
  - name: main
    listen: "127.0.0.1:0"
    backend: main
  - name: other
    listen: "127.0.0.1:0"
    backend: other
client_auth:
  users:
    - username: dev1
      password_hash: "%s"
    - username: disabled
      password_hash: "%s"
      enabled: false
    - username: otheronly
      password_hash: "%s"
      allowed_backends: [other]
%s
credential_profiles:
  shared:
    %s
backends:
  main:
    host: %s
    port: %d
    credentials: shared
    tls_server_name: %q
  other:
    host: %s
    port: %d
    credentials: shared
tls:
  client_certificate: %s
  client_private_key: %s
  backend_ca_file: %s
`, maxConns, idle, cidrs, h, h, h, extraUsers, profile, host, port, o.tlsServerName, host, port, e.pki.CertFile, e.pki.KeyFile, e.pki.CAFile)
	e.cfgPath = filepath.Join(e.dir, "config.yaml")
	writeAtomic(e.t, e.cfgPath, cfg)
}

func writeAtomic(t *testing.T, path, content string) {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func (e *env) rotateSecret(v string) { writeAtomic(e.t, e.secret, v) }

func (e *env) addr(listener string) string { return e.app.Addrs()[listener].String() }

func (e *env) dsn(listener, user, password string, extra ...string) string {
	q := url.Values{}
	q.Set("encrypt", "true")
	q.Set("certificate", e.pki.CAFile)
	q.Set("hostnameincertificate", "localhost")
	q.Set("connection timeout", "10")
	q.Set("dial timeout", "5")
	for i := 0; i+1 < len(extra); i += 2 {
		q.Set(extra[i], extra[i+1])
	}
	u := url.URL{Scheme: "sqlserver", User: url.UserPassword(user, password), Host: e.addr(listener), RawQuery: q.Encode()}
	return u.String()
}

func (e *env) open(listener, user, password string, extra ...string) *sql.DB {
	db, err := sql.Open("sqlserver", e.dsn(listener, user, password, extra...))
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { db.Close() })
	return db
}

func scalar[T any](t *testing.T, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, query string) T {
	t.Helper()
	var v T
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := q.QueryRowContext(ctx, query).Scan(&v); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return v
}

func pingErr(db *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return db.PingContext(ctx)
}

func TestSQLAuthEndToEnd(t *testing.T) {
	e := newEnv(t, envOpts{})
	db := e.open("main", "dev1", clientPW)
	if got := scalar[int](t, db, "SELECT 1"); got != 1 {
		t.Fatalf("SELECT 1 = %d", got)
	}
	if got := scalar[string](t, db, "SELECT WHOAMI()"); got != "svc_user" {
		t.Fatalf("backend identity = %q", got)
	}
	l := e.fake.LastLogin()
	if !l.OK || l.ServerName != "127.0.0.1" {
		t.Fatalf("backend login = %+v", l)
	}
	for _, f := range l.Features {
		if f == 0x01 {
			t.Fatal("SESSIONRECOVERY feature was forwarded")
		}
	}
	// Usernames are case-insensitive.
	if err := pingErr(e.open("main", "DEV1", clientPW)); err != nil {
		t.Fatal(err)
	}
}

func TestClientAuthFailures(t *testing.T) {
	e := newEnv(t, envOpts{})
	cases := []struct{ name, listener, user, pw string }{
		{"wrong password", "main", "dev1", "nope-nope"},
		{"unknown user", "main", "ghost", clientPW},
		{"disabled user", "main", "disabled", clientPW},
		{"unauthorized backend", "main", "otheronly", clientPW},
		{"empty password", "main", "dev1", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := len(e.fake.Logins)
			err := pingErr(e.open(c.listener, c.user, c.pw))
			if err == nil || !strings.Contains(err.Error(), "Login failed for user") {
				t.Fatalf("expected login failure, got %v", err)
			}
			if len(e.fake.Logins) != before {
				t.Fatal("proxy contacted the backend for an unauthenticated client")
			}
		})
	}
	// The same user is accepted on the backend it is authorized for.
	if err := pingErr(e.open("other", "otheronly", clientPW)); err != nil {
		t.Fatal(err)
	}
}

func TestBackendPasswordRotation(t *testing.T) {
	e := newEnv(t, envOpts{})
	ctx := context.Background()
	db := e.open("main", "dev1", clientPW)
	db.SetMaxIdleConns(1)
	held, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if scalar[int](t, held, "SELECT 1") != 1 {
		t.Fatal("held connection")
	}

	// The password changes on the server before the proxy knows: new logins
	// fail clearly, the existing session is unaffected.
	e.fake.SetPassword("backend-password-v2")
	err = pingErr(e.open("main", "dev1", clientPW))
	if err == nil || !strings.Contains(err.Error(), "could not log in to backend server 'main'") {
		t.Fatalf("expected backend login failure, got %v", err)
	}
	if e.fake.LastLogin().Reason != "bad password" {
		t.Fatalf("backend saw %+v", e.fake.LastLogin())
	}

	// Update the shared secret once: new connections use it immediately.
	e.rotateSecret("backend-password-v2")
	for _, l := range []string{"main", "other"} {
		if err := pingErr(e.open(l, "dev1", clientPW)); err != nil {
			t.Fatalf("listener %s after rotation: %v", l, err)
		}
	}
	if scalar[int](t, held, "SELECT 1") != 1 {
		t.Fatal("held connection broken by rotation")
	}
}

func (e *env) failedBackendLogins() int {
	e.fake.LoginsMu.Lock()
	defer e.fake.LoginsMu.Unlock()
	n := 0
	for _, l := range e.fake.Logins {
		if !l.OK {
			n++
		}
	}
	return n
}

func TestLockoutProtection(t *testing.T) {
	e := newEnv(t, envOpts{})
	if err := pingErr(e.open("main", "dev1", clientPW)); err != nil {
		t.Fatal(err)
	}

	// The password expires on the server; a burst of clients arrives.
	e.fake.SetPassword("backend-password-v2")
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- pingErr(e.open([]string{"main", "other"}[i%2], "dev1", clientPW))
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err == nil {
			t.Fatal("login succeeded with a stale backend password")
		}
	}
	// At most max_parallel_logins (default 2) logins were in flight when
	// the first rejection arrived; everything after it was refused locally.
	burst := e.failedBackendLogins()
	if burst < 1 || burst > 2 {
		t.Fatalf("backend saw %d failed logins, want 1..2", burst)
	}
	err := pingErr(e.open("other", "dev1", clientPW))
	if err == nil || !strings.Contains(err.Error(), "waiting for a new password") {
		t.Fatalf("expected paused login, got %v", err)
	}
	if n := e.failedBackendLogins(); n != burst {
		t.Fatalf("backend saw %d more failed logins while paused", n-burst)
	}
	var metrics strings.Builder
	e.app.Metrics.WritePrometheus(&metrics)
	if !strings.Contains(metrics.String(), `tdsproxy_credentials_blocked{profile="shared"} 1`) {
		t.Fatal("blocked metric not set")
	}

	// A reload allows exactly one more attempt with the unchanged secret.
	if err := e.app.Reload(); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		pingErr(e.open("main", "dev1", clientPW))
	}
	if n := e.failedBackendLogins(); n != burst+1 {
		t.Fatalf("after reload: %d failed logins, want %d", n, burst+1)
	}

	// The new secret arrives: logins resume without a restart.
	e.rotateSecret("backend-password-v2")
	if err := pingErr(e.open("main", "dev1", clientPW)); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	metrics.Reset()
	e.app.Metrics.WritePrometheus(&metrics)
	if !strings.Contains(metrics.String(), `tdsproxy_credentials_blocked{profile="shared"} 0`) {
		t.Fatal("blocked metric not cleared")
	}
}

func TestLockoutProtectionUnverifiedSecret(t *testing.T) {
	e := newEnv(t, envOpts{})
	// A wrong secret is deployed before any login succeeded: of a burst of
	// clients, only one reaches the backend.
	e.rotateSecret("wrong")
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pingErr(e.open("main", "dev1", clientPW))
		}()
	}
	wg.Wait()
	if n := e.failedBackendLogins(); n != 1 {
		t.Fatalf("backend saw %d failed logins, want 1", n)
	}
}

func TestNTLMBackendWithChannelBinding(t *testing.T) {
	e := newEnv(t, envOpts{ntlm: true})
	db := e.open("main", "dev1", clientPW)
	if got := scalar[string](t, db, "SELECT WHOAMI()"); got != `CORP\svc_user` {
		t.Fatalf("backend identity = %q (last login %+v)", got, e.fake.LastLogin())
	}
	e.fake.SetPassword("ntlm-v2")
	if err := pingErr(e.open("main", "dev1", clientPW)); err == nil {
		t.Fatal("expected failure with stale NTLM password")
	}
	e.rotateSecret("ntlm-v2\n")
	if err := pingErr(e.open("main", "dev1", clientPW)); err != nil {
		t.Fatalf("after NTLM rotation: %v (%+v)", err, e.fake.LastLogin())
	}
}

func TestBackendFailures(t *testing.T) {
	t.Run("unreachable", func(t *testing.T) {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		port := ln.Addr().(*net.TCPAddr).Port
		ln.Close()
		e := newEnv(t, envOpts{backendPort: port})
		err := pingErr(e.open("main", "dev1", clientPW))
		if err == nil || !strings.Contains(err.Error(), "could not reach backend server 'main'") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("certificate name mismatch", func(t *testing.T) {
		e := newEnv(t, envOpts{tlsServerName: "wrong.example"})
		if err := pingErr(e.open("main", "dev1", clientPW)); err == nil {
			t.Fatal("expected TLS verification failure")
		}
		// "other" has no override and verifies fine.
		if err := pingErr(e.open("other", "dev1", clientPW)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("backend without encryption", func(t *testing.T) {
		e := newEnv(t, envOpts{})
		e.fake.NoEncryption = true
		if err := pingErr(e.open("main", "dev1", clientPW)); err == nil {
			t.Fatal("expected failure")
		}
	})
	t.Run("routing redirect", func(t *testing.T) {
		e := newEnv(t, envOpts{})
		e.fake.SendRouting = true
		if err := pingErr(e.open("main", "dev1", clientPW)); err == nil {
			t.Fatal("expected routing to be refused")
		}
	})
}

func TestQueryCancellation(t *testing.T) {
	e := newEnv(t, envOpts{})
	db := e.open("main", "dev1", clientPW)
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = conn.ExecContext(ctx, "WAITFOR DELAY '00:01:00'")
	if err == nil {
		t.Fatal("expected cancellation error")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("cancellation took too long")
	}
	// go-mssqldb discards a connection after cancellation (it does so
	// against SQL Server directly as well); the pool must stay healthy.
	if scalar[int](t, db, "SELECT 1") != 1 {
		t.Fatal("pool unusable after attention")
	}
}

func TestLargeResultSmallPackets(t *testing.T) {
	e := newEnv(t, envOpts{})
	db := e.open("main", "dev1", clientPW, "packet size", "4096")
	rows, err := db.Query("BIG 50000")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n, sum := 0, 0
	for rows.Next() {
		var v int
		rows.Scan(&v)
		n++
		sum += v
	}
	if err := rows.Err(); err != nil || n != 50000 || sum != 50000*50001/2 {
		t.Fatalf("n=%d sum=%d err=%v", n, sum, err)
	}
}

func TestConcurrentConnections(t *testing.T) {
	e := newEnv(t, envOpts{})
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			db, err := sql.Open("sqlserver", e.dsn("main", "dev1", clientPW))
			if err != nil {
				errs <- err
				return
			}
			defer db.Close()
			var v int
			if err := db.QueryRow("SELECT 1").Scan(&v); err != nil || v != 1 {
				errs <- fmt.Errorf("v=%d err=%v", v, err)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSessionCleanup(t *testing.T) {
	t.Run("client close", func(t *testing.T) {
		e := newEnv(t, envOpts{})
		db := e.open("main", "dev1", clientPW)
		if err := pingErr(db); err != nil {
			t.Fatal(err)
		}
		db.Close()
		waitFor(t, "backend connection to close", func() bool { return e.fake.ActiveConns() == 0 })
		waitFor(t, "session gauge to drop", func() bool { return e.app.Metrics.ActiveSessions.Load() == 0 })
	})
	t.Run("idle timeout", func(t *testing.T) {
		e := newEnv(t, envOpts{idleTimeout: "300ms"})
		db := e.open("main", "dev1", clientPW)
		if err := pingErr(db); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "idle session to close", func() bool { return e.fake.ActiveConns() == 0 })
	})
	t.Run("shutdown", func(t *testing.T) {
		e := newEnv(t, envOpts{})
		db := e.open("main", "dev1", clientPW)
		if err := pingErr(db); err != nil {
			t.Fatal(err)
		}
		e.app.Shutdown(context.Background()) // shutdown_timeout 2s, then forced
		if e.fake.ActiveConns() != 0 && e.app.Metrics.ActiveSessions.Load() != 0 {
			waitFor(t, "sessions to close", func() bool { return e.fake.ActiveConns() == 0 })
		}
		if _, err := net.DialTimeout("tcp", e.fake.Addr().String(), time.Second); err != nil {
			t.Fatal("fake backend gone?", err)
		}
	})
}

func TestReload(t *testing.T) {
	e := newEnv(t, envOpts{})
	if err := pingErr(e.open("main", "newuser", clientPW)); err == nil {
		t.Fatal("newuser should not exist yet")
	}
	e.writeConfig(fmt.Sprintf("    - username: newuser\n      password_hash: %q", clientHashFor(t)))
	if err := e.app.Reload(); err != nil {
		t.Fatal(err)
	}
	if err := pingErr(e.open("main", "newuser", clientPW)); err != nil {
		t.Fatalf("after reload: %v", err)
	}
	// A broken configuration is rejected and the previous one stays active.
	writeAtomic(t, e.cfgPath, "listeners: [")
	if err := e.app.Reload(); err == nil {
		t.Fatal("expected reload error")
	}
	if err := pingErr(e.open("main", "newuser", clientPW)); err != nil {
		t.Fatalf("after failed reload: %v", err)
	}
}

func TestIPAllowlist(t *testing.T) {
	e := newEnv(t, envOpts{allowedCIDRs: "[10.0.0.0/8]"})
	if err := pingErr(e.open("main", "dev1", clientPW)); err == nil {
		t.Fatal("expected connection from 127.0.0.1 to be rejected")
	}
	if e.app.Metrics.RejectedConnections.Load() == 0 {
		t.Fatal("rejection not counted")
	}
}

func TestMaxConnections(t *testing.T) {
	e := newEnv(t, envOpts{maxConns: 1})
	db := e.open("main", "dev1", clientPW)
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := pingErr(e.open("main", "dev1", clientPW)); err == nil {
		t.Fatal("second connection should be refused")
	}
}
