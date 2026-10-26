// Package monitoring exposes health, readiness and Prometheus-format metrics.
// Nothing here ever includes usernames, hosts or secrets.
package monitoring

import (
	"fmt"
	"io"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics holds process-wide counters. Labels are limited to listener /
// backend names and fixed outcome strings, keeping cardinality bounded.
type Metrics struct {
	ActiveSessions       atomic.Int64
	TotalConnections     atomic.Int64
	RejectedConnections  atomic.Int64
	BytesClientToBackend atomic.Int64
	BytesBackendToClient atomic.Int64

	mu              sync.Mutex
	authResults     map[string]int64 // outcome -> count
	backendFailures map[string]int64 // backend/category -> count
	blockedCreds    map[string]bool  // credential profile -> blocked

	HandshakeDuration *Histogram
	SessionDuration   *Histogram
}

func NewMetrics() *Metrics {
	return &Metrics{
		authResults:       map[string]int64{},
		backendFailures:   map[string]int64{},
		blockedCreds:      map[string]bool{},
		HandshakeDuration: NewHistogram([]float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}),
		SessionDuration:   NewHistogram([]float64{1, 10, 60, 300, 900, 1800, 3600, 4 * 3600, 12 * 3600}),
	}
}

// AuthResult records a client authentication outcome such as "success",
// "invalid_credentials", "disabled", "unauthorized".
func (m *Metrics) AuthResult(outcome string) {
	m.mu.Lock()
	m.authResults[outcome]++
	m.mu.Unlock()
}

// BackendFailure records a failed backend connection attempt.
func (m *Metrics) BackendFailure(backend, category string) {
	m.mu.Lock()
	m.backendFailures[backend+"\x00"+category]++
	m.mu.Unlock()
}

// SetCredentialsBlocked records whether lockout protection is pausing logins
// for a credential profile.
func (m *Metrics) SetCredentialsBlocked(profile string, blocked bool) {
	m.mu.Lock()
	m.blockedCreds[profile] = blocked
	m.mu.Unlock()
}

func (m *Metrics) AddBytes(c2b, b2c int64) {
	if c2b != 0 {
		m.BytesClientToBackend.Add(c2b)
	}
	if b2c != 0 {
		m.BytesBackendToClient.Add(b2c)
	}
}

// WritePrometheus writes the metrics in the Prometheus text exposition format.
func (m *Metrics) WritePrometheus(w io.Writer) {
	gauge := func(name, help string, v int64) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %d\n", name, help, name, name, v)
	}
	counter := func(name, help string, v int64) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
	}
	gauge("tdsproxy_active_sessions", "Client sessions currently open.", m.ActiveSessions.Load())
	counter("tdsproxy_connections_total", "Client connections accepted.", m.TotalConnections.Load())
	counter("tdsproxy_connections_rejected_total", "Client connections rejected by allowlist or connection limit.", m.RejectedConnections.Load())
	fmt.Fprintf(w, "# HELP tdsproxy_bytes_total Bytes relayed after login.\n# TYPE tdsproxy_bytes_total counter\n")
	fmt.Fprintf(w, "tdsproxy_bytes_total{direction=\"client_to_backend\"} %d\n", m.BytesClientToBackend.Load())
	fmt.Fprintf(w, "tdsproxy_bytes_total{direction=\"backend_to_client\"} %d\n", m.BytesBackendToClient.Load())

	m.mu.Lock()
	fmt.Fprintf(w, "# HELP tdsproxy_client_auth_total Client authentication attempts by outcome.\n# TYPE tdsproxy_client_auth_total counter\n")
	for _, k := range sortedKeys(m.authResults) {
		fmt.Fprintf(w, "tdsproxy_client_auth_total{outcome=%q} %d\n", k, m.authResults[k])
	}
	fmt.Fprintf(w, "# HELP tdsproxy_backend_failures_total Failed backend connections by backend and category.\n# TYPE tdsproxy_backend_failures_total counter\n")
	for _, k := range sortedKeys(m.backendFailures) {
		var b, c string
		for i := range k {
			if k[i] == 0 {
				b, c = k[:i], k[i+1:]
				break
			}
		}
		fmt.Fprintf(w, "tdsproxy_backend_failures_total{backend=%q,category=%q} %d\n", b, c, m.backendFailures[k])
	}
	fmt.Fprintf(w, "# HELP tdsproxy_credentials_blocked 1 while backend logins with a credential profile are paused after the server rejected it.\n# TYPE tdsproxy_credentials_blocked gauge\n")
	profiles := make([]string, 0, len(m.blockedCreds))
	for p := range m.blockedCreds {
		profiles = append(profiles, p)
	}
	sort.Strings(profiles)
	for _, p := range profiles {
		v := 0
		if m.blockedCreds[p] {
			v = 1
		}
		fmt.Fprintf(w, "tdsproxy_credentials_blocked{profile=%q} %d\n", p, v)
	}
	m.mu.Unlock()

	m.HandshakeDuration.write(w, "tdsproxy_handshake_duration_seconds", "Time from accept to relayed login response.")
	m.SessionDuration.write(w, "tdsproxy_session_duration_seconds", "Duration of authenticated sessions.")
}

func sortedKeys(m map[string]int64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Histogram is a minimal cumulative histogram.
type Histogram struct {
	mu     sync.Mutex
	bounds []float64
	counts []int64
	sum    float64
	count  int64
}

func NewHistogram(bounds []float64) *Histogram {
	return &Histogram{bounds: bounds, counts: make([]int64, len(bounds))}
}

func (h *Histogram) Observe(d time.Duration) {
	v := d.Seconds()
	h.mu.Lock()
	defer h.mu.Unlock()
	for i, b := range h.bounds {
		if v <= b {
			h.counts[i]++
		}
	}
	h.sum += v
	h.count++
}

func (h *Histogram) write(w io.Writer, name, help string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", name, help, name)
	for i, b := range h.bounds {
		fmt.Fprintf(w, "%s_bucket{le=\"%g\"} %d\n", name, b, h.counts[i])
	}
	fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n", name, h.count)
	sum := h.sum
	if math.IsNaN(sum) {
		sum = 0
	}
	fmt.Fprintf(w, "%s_sum %g\n%s_count %d\n", name, sum, name, h.count)
}
