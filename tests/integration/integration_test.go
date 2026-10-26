//go:build integration

// Integration tests against a real SQL Server, driven through an in-process
// proxy with go-mssqldb as the client.
//
//	TDSPROXY_IT_SQL_ADDR      host:port of SQL Server (default 127.0.0.1:24433)
//	TDSPROXY_IT_SA_PASSWORD   sa password (tests are skipped when unset)
//	TDSPROXY_IT_CA_FILE       CA that signed SQL Server's certificate
//	TDSPROXY_IT_SQL_TLS_NAME  name in SQL Server's certificate (default localhost)
//
// See scripts/integration-test.sh, which provisions all of this in Docker.
package integration

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	mssql "github.com/microsoft/go-mssqldb"

	"github.com/mdrakib/tds-auth-proxy/internal/app"
	"github.com/mdrakib/tds-auth-proxy/internal/auth"
	"github.com/mdrakib/tds-auth-proxy/internal/testutil"
)

const clientPW = "it-client-password"

type suite struct {
	t       *testing.T
	sqlHost string
	sqlPort int
	caFile  string
	tlsName string
	sa      *sql.DB
	login   string
	dir     string
	secret  string
	pki     *testutil.PKI
	proxy   *app.App
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func setup(t *testing.T) *suite {
	saPW := os.Getenv("TDSPROXY_IT_SA_PASSWORD")
	if saPW == "" {
		t.Skip("TDSPROXY_IT_SA_PASSWORD not set; skipping SQL Server integration tests")
	}
	host, portS, err := net.SplitHostPort(env("TDSPROXY_IT_SQL_ADDR", "127.0.0.1:24433"))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portS)
	ca, _ := filepath.Abs(env("TDSPROXY_IT_CA_FILE", "../../dev/certs/ca.crt"))
	s := &suite{t: t, sqlHost: host, sqlPort: port, caFile: ca, tlsName: env("TDSPROXY_IT_SQL_TLS_NAME", "localhost"), dir: t.TempDir()}

	// go-mssqldb only accepts .pem/.der CA files.
	pemCA := filepath.Join(s.dir, "sql-ca.pem")
	b, err := os.ReadFile(ca)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(pemCA, b, 0o600)
	s.caFile = pemCA

	s.sa = s.direct("sa", saPW)
	var rnd [4]byte
	rand.Read(rnd[:])
	s.login = "it_svc_" + hex.EncodeToString(rnd[:])
	s.exec(fmt.Sprintf("CREATE LOGIN [%s] WITH PASSWORD = 'Backend-v1-Pa55!', CHECK_POLICY = OFF", s.login))
	t.Cleanup(func() {
		s.sa.Exec(fmt.Sprintf(`DECLARE @k NVARCHAR(MAX) = N'';
			SELECT @k += N'KILL ' + CAST(session_id AS NVARCHAR(10)) + N';' FROM sys.dm_exec_sessions WHERE login_name = N'%s';
			EXEC (@k); DROP LOGIN [%s];`, s.login, s.login))
	})

	s.secret = filepath.Join(s.dir, "backend-password")
	s.rotateSecret("Backend-v1-Pa55!\n")
	s.pki = testutil.NewPKI(t)
	s.writeConfig()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	if testing.Verbose() {
		logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	s.proxy, err = app.New(filepath.Join(s.dir, "config.yaml"), logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.proxy.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.proxy.Shutdown(context.Background()) })
	return s
}

func (s *suite) writeConfig() {
	h, err := auth.HashPasswordParams(clientPW, 4096, 1, 1)
	if err != nil {
		s.t.Fatal(err)
	}
	cfg := fmt.Sprintf(`
server:
  handshake_timeout: 20s
  shutdown_timeout: 3s
  auth_failure_delay: 10ms
listeners:
  - {name: main, listen: "127.0.0.1:0", backend: main}
  - {name: badcert, listen: "127.0.0.1:0", backend: badcert}
  - {name: down, listen: "127.0.0.1:0", backend: down}
client_auth:
  users:
    - {username: dev1, password_hash: "%[1]s"}
    - {username: disabled, password_hash: "%[1]s", enabled: false}
    - {username: limited, password_hash: "%[1]s", allowed_backends: [badcert]}
credential_profiles:
  shared:
    type: sql
    username: %[2]s
    password_file: %[3]s
backends:
  main: {host: %[4]s, port: %[5]d, credentials: shared, tls_server_name: %[6]s}
  badcert: {host: %[4]s, port: %[5]d, credentials: shared, tls_server_name: not-the-server.example}
  down: {host: 127.0.0.1, port: 1, credentials: shared, connect_timeout: 2s}
tls:
  client_certificate: %[7]s
  client_private_key: %[8]s
  backend_ca_file: %[9]s
`, h, s.login, s.secret, s.sqlHost, s.sqlPort, s.tlsName, s.pki.CertFile, s.pki.KeyFile, s.caFile)
	writeAtomic(s.t, filepath.Join(s.dir, "config.yaml"), cfg)
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

func (s *suite) rotateSecret(v string) { writeAtomic(s.t, s.secret, v) }

func (s *suite) exec(q string) {
	s.t.Helper()
	if _, err := s.sa.Exec(q); err != nil {
		s.t.Fatalf("%s: %v", q, err)
	}
}

func dsn(host string, port int, user, pw, ca, tlsName string, extra ...string) string {
	q := url.Values{}
	q.Set("encrypt", "true")
	q.Set("certificate", ca)
	q.Set("hostnameincertificate", tlsName)
	q.Set("connection timeout", "30")
	for i := 0; i+1 < len(extra); i += 2 {
		q.Set(extra[i], extra[i+1])
	}
	u := url.URL{Scheme: "sqlserver", User: url.UserPassword(user, pw), Host: net.JoinHostPort(host, strconv.Itoa(port)), RawQuery: q.Encode()}
	return u.String()
}

func (s *suite) direct(user, pw string, extra ...string) *sql.DB {
	db, err := sql.Open("sqlserver", dsn(s.sqlHost, s.sqlPort, user, pw, s.caFile, s.tlsName, extra...))
	if err != nil {
		s.t.Fatal(err)
	}
	s.t.Cleanup(func() { db.Close() })
	return db
}

func (s *suite) viaProxy(listener, user, pw string, extra ...string) *sql.DB {
	a := s.proxy.Addrs()[listener].(*net.TCPAddr)
	db, err := sql.Open("sqlserver", dsn("127.0.0.1", a.Port, user, pw, s.pki.CAFile, "localhost", extra...))
	if err != nil {
		s.t.Fatal(err)
	}
	s.t.Cleanup(func() { db.Close() })
	return db
}

func ping(db *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return db.PingContext(ctx)
}

type querier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func scalar[T any](t *testing.T, q querier, query string, args ...any) T {
	t.Helper()
	var v T
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := q.QueryRowContext(ctx, query, args...).Scan(&v); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return v
}

func sqlErrNumber(err error) int32 {
	var e mssql.Error
	if errors.As(err, &e) {
		return e.Number
	}
	return 0
}

func TestRealSQLServer(t *testing.T) {
	s := setup(t)
	db := s.viaProxy("main", "dev1", clientPW)

	t.Run("basic queries", func(t *testing.T) {
		if v := scalar[int](t, db, "SELECT 1"); v != 1 {
			t.Fatalf("SELECT 1 = %d", v)
		}
		if v := scalar[string](t, db, "SELECT @@VERSION"); !strings.Contains(v, "Microsoft SQL Server") {
			t.Fatalf("@@VERSION = %q", v)
		}
		if v := scalar[string](t, db, "SELECT DB_NAME()"); v != "master" {
			t.Fatalf("DB_NAME() = %q", v)
		}
		if v := scalar[string](t, db, "SELECT SUSER_SNAME()"); v != s.login {
			t.Fatalf("SUSER_SNAME() = %q, want %q", v, s.login)
		}
		spid := scalar[int](t, db, "SELECT @@SPID")
		if v := scalar[string](t, s.sa, "SELECT encrypt_option FROM sys.dm_exec_connections WHERE session_id = @p1", spid); v != "TRUE" {
			t.Fatalf("backend connection encrypt_option = %q", v)
		}
	})

	t.Run("initial database is honoured", func(t *testing.T) {
		d := s.viaProxy("main", "dev1", clientPW, "database", "tempdb")
		if v := scalar[string](t, d, "SELECT DB_NAME()"); v != "tempdb" {
			t.Fatalf("DB_NAME() = %q", v)
		}
	})

	t.Run("temporary table", func(t *testing.T) {
		c, err := db.Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		for _, q := range []string{"CREATE TABLE #ProxyTest (Id INT)", "INSERT INTO #ProxyTest VALUES (1)"} {
			if _, err := c.ExecContext(context.Background(), q); err != nil {
				t.Fatal(err)
			}
		}
		if v := scalar[int](t, c, "SELECT * FROM #ProxyTest"); v != 1 {
			t.Fatalf("got %d", v)
		}
		if _, err := c.ExecContext(context.Background(), "DROP TABLE #ProxyTest"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("transactions", func(t *testing.T) {
		c, _ := db.Conn(context.Background())
		defer c.Close()
		c.ExecContext(context.Background(), "CREATE TABLE #Tx (Id INT)")
		tx, err := c.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		tx.Exec("INSERT INTO #Tx VALUES (1)")
		if v := scalar[int](t, tx, "SELECT 1"); v != 1 {
			t.Fatal(v)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		tx, _ = c.BeginTx(context.Background(), nil)
		tx.Exec("INSERT INTO #Tx VALUES (2)")
		if err := tx.Rollback(); err != nil {
			t.Fatal(err)
		}
		if v := scalar[int](t, c, "SELECT COUNT(*) FROM #Tx"); v != 1 {
			t.Fatalf("rows after commit+rollback = %d", v)
		}
		if v := scalar[int](t, c, "SELECT @@TRANCOUNT"); v != 0 {
			t.Fatalf("@@TRANCOUNT = %d", v)
		}
	})

	t.Run("parameterized query", func(t *testing.T) {
		if v := scalar[string](t, db, "SELECT CONCAT(@p1 + @p2, N'-', @p3)", 40, 2, "ünïcode ✓"); v != "42-ünïcode ✓" {
			t.Fatalf("got %q", v)
		}
	})

	t.Run("stored procedure", func(t *testing.T) {
		c, _ := db.Conn(context.Background())
		defer c.Close()
		if _, err := c.ExecContext(context.Background(), "CREATE PROCEDURE #AddOne @x INT, @y INT OUTPUT AS SET @y = @x + 1"); err != nil {
			t.Fatal(err)
		}
		var y int
		if _, err := c.ExecContext(context.Background(), "#AddOne", sql.Named("x", 41), sql.Named("y", sql.Out{Dest: &y})); err != nil {
			t.Fatal(err)
		}
		if y != 42 {
			t.Fatalf("y = %d", y)
		}
	})

	t.Run("multiple result sets", func(t *testing.T) {
		rows, err := db.Query("SELECT 1; SELECT 2; SELECT 3")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		sum := 0
		for {
			for rows.Next() {
				var v int
				rows.Scan(&v)
				sum += v
			}
			if !rows.NextResultSet() {
				break
			}
		}
		if sum != 6 {
			t.Fatalf("sum = %d", sum)
		}
	})

	t.Run("large result set", func(t *testing.T) {
		// go-mssqldb cannot use packet sizes below 4096 even directly against
		// SQL Server (its TLS handshake buffer is too small).
		for _, ps := range []string{"4096", "8000", "32767"} {
			d := s.viaProxy("main", "dev1", clientPW, "packet size", ps)
			rows, err := d.Query(`SELECT TOP (100000) CAST(ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS BIGINT), REPLICATE('x', 200)
				FROM sys.all_objects a CROSS JOIN sys.all_objects b`)
			if err != nil {
				t.Fatalf("packet size %s: %v", ps, err)
			}
			var n, sum int64
			for rows.Next() {
				var v int64
				var pad string
				rows.Scan(&v, &pad)
				n++
				sum += v
			}
			rows.Close()
			if rows.Err() != nil || n != 100000 || sum != 100000*100001/2 {
				t.Fatalf("packet size %s: n=%d err=%v", ps, n, rows.Err())
			}
		}
	})

	t.Run("server error is relayed", func(t *testing.T) {
		_, err := db.Exec("SELECT 1/0")
		if sqlErrNumber(err) != 8134 {
			t.Fatalf("expected error 8134, got %v", err)
		}
		_, err = db.Exec("RAISERROR('custom failure %d', 16, 3, 7)")
		if err == nil || !strings.Contains(err.Error(), "custom failure 7") {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("query cancellation", func(t *testing.T) {
		for _, target := range []struct {
			name string
			db   *sql.DB
		}{{"direct", s.direct(s.login, "Backend-v1-Pa55!")}, {"proxy", db}} {
			c, err := target.db.Conn(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			start := time.Now()
			_, err = c.ExecContext(ctx, "WAITFOR DELAY '00:00:30'")
			cancel()
			if err == nil || time.Since(start) > 10*time.Second {
				t.Fatalf("%s: err=%v after %v", target.name, err, time.Since(start))
			}
			var v int
			err = c.QueryRowContext(context.Background(), "SELECT 1").Scan(&v)
			t.Logf("%s: query after cancel: v=%d err=%v", target.name, v, err)
			c.Close()
		}
		// Whatever the driver does with the cancelled conn, the pool stays healthy.
		if v := scalar[int](t, db, "SELECT 1"); v != 1 {
			t.Fatal(v)
		}
	})

	t.Run("concurrent connections", func(t *testing.T) {
		var wg sync.WaitGroup
		errs := make(chan error, 30)
		for i := 0; i < 30; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				d, _ := sql.Open("sqlserver", dsn("127.0.0.1", s.proxy.Addrs()["main"].(*net.TCPAddr).Port, "dev1", clientPW, s.pki.CAFile, "localhost"))
				defer d.Close()
				var spid, v int
				if err := d.QueryRow("SELECT @@SPID, @p1", i).Scan(&spid, &v); err != nil || v != i {
					errs <- fmt.Errorf("conn %d: v=%d err=%v", i, v, err)
				}
			}(i)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
	})

	t.Run("client authentication failures", func(t *testing.T) {
		for _, c := range []struct{ name, listener, user, pw string }{
			{"wrong client password", "main", "dev1", "wrong"},
			{"disabled client", "main", "disabled", clientPW},
			{"unauthorized backend", "main", "limited", clientPW},
			{"backend password used as client password", "main", s.login, "Backend-v1-Pa55!"},
		} {
			err := ping(s.viaProxy(c.listener, c.user, c.pw))
			if sqlErrNumber(err) != 18456 {
				t.Errorf("%s: expected 18456, got %v", c.name, err)
			}
		}
	})

	t.Run("backend TLS certificate error", func(t *testing.T) {
		err := ping(s.viaProxy("badcert", "limited", clientPW))
		if err == nil || !strings.Contains(err.Error(), "could not reach backend server 'badcert'") {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("backend unreachable", func(t *testing.T) {
		err := ping(s.viaProxy("down", "dev1", clientPW))
		if err == nil || !strings.Contains(err.Error(), "could not reach backend server 'down'") {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("password rotation", func(t *testing.T) {
		held, err := db.Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer held.Close()
		spid := scalar[int](t, held, "SELECT @@SPID")

		s.exec(fmt.Sprintf("ALTER LOGIN [%s] WITH PASSWORD = 'Backend-v2-Pa55!'", s.login))
		err = ping(s.viaProxy("main", "dev1", clientPW))
		if sqlErrNumber(err) != 18456 || !strings.Contains(err.Error(), "could not log in to backend server 'main'") {
			t.Fatalf("stale backend password: got %v", err)
		}

		s.rotateSecret("Backend-v2-Pa55!")
		fresh := s.viaProxy("main", "dev1", clientPW)
		if v := scalar[string](t, fresh, "SELECT SUSER_SNAME()"); v != s.login {
			t.Fatalf("after rotation: %q", v)
		}
		if v := scalar[int](t, held, "SELECT @@SPID"); v != spid {
			t.Fatalf("held session changed SPID %d -> %d", spid, v)
		}
	})

	t.Run("clean shutdown", func(t *testing.T) {
		// A fresh pool: SQL Server itself refuses sp_reset_connection on
		// pooled sessions whose SQL login password has since changed
		// (verified directly against SQL Server, without the proxy).
		c, err := s.viaProxy("main", "dev1", clientPW).Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		spid := scalar[int](t, c, "SELECT @@SPID")
		after := s.viaProxy("main", "dev1", clientPW)
		s.proxy.Shutdown(context.Background())
		if err := ping(after); err == nil {
			t.Fatal("proxy still accepting after shutdown")
		}
		deadline := time.Now().Add(10 * time.Second)
		for {
			var n int
			s.sa.QueryRow("SELECT COUNT(*) FROM sys.dm_exec_sessions WHERE session_id = @p1 AND login_name = @p2", spid, s.login).Scan(&n)
			if n == 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("backend session still open after shutdown")
			}
			time.Sleep(100 * time.Millisecond)
		}
		c.Close()
	})
}
