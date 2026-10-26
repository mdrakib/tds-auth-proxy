package monitoring

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAdminEndpoints(t *testing.T) {
	m := NewMetrics()
	m.TotalConnections.Add(3)
	m.AuthResult("success")
	m.AuthResult("invalid_credentials")
	m.BackendFailure("sql-a", "login")
	m.HandshakeDuration.Observe(30 * time.Millisecond)
	m.AddBytes(10, 20)
	var ready atomic.Bool
	reloadErr := error(nil)
	a := &AdminServer{Metrics: m, Ready: &ready, Reload: func() error { return reloadErr }}
	h := a.Handler()

	get := func(method, path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		return w
	}
	if w := get("GET", "/healthz"); w.Code != http.StatusOK {
		t.Fatal("healthz", w.Code)
	}
	if w := get("GET", "/readyz"); w.Code != http.StatusServiceUnavailable {
		t.Fatal("readyz before ready", w.Code)
	}
	ready.Store(true)
	if w := get("GET", "/readyz"); w.Code != http.StatusOK {
		t.Fatal("readyz", w.Code)
	}
	body := get("GET", "/metrics").Body.String()
	for _, want := range []string{
		"tdsproxy_connections_total 3",
		`tdsproxy_client_auth_total{outcome="success"} 1`,
		`tdsproxy_backend_failures_total{backend="sql-a",category="login"} 1`,
		`tdsproxy_bytes_total{direction="backend_to_client"} 20`,
		`tdsproxy_handshake_duration_seconds_bucket{le="0.05"} 1`,
		"tdsproxy_handshake_duration_seconds_count 1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
	if w := get("GET", "/-/reload"); w.Code != http.StatusMethodNotAllowed {
		t.Fatal("reload must be POST-only", w.Code)
	}
	if w := get("POST", "/-/reload"); w.Code != http.StatusOK {
		t.Fatal("reload", w.Code)
	}
	reloadErr = errors.New("bad config")
	if w := get("POST", "/-/reload"); w.Code != http.StatusUnprocessableEntity {
		t.Fatal("failed reload", w.Code)
	}
}
