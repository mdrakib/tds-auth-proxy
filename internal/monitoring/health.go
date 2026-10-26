package monitoring

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// AdminServer serves /healthz, /readyz, /metrics and POST /-/reload.
// It should listen on loopback; it has no authentication of its own.
type AdminServer struct {
	Metrics *Metrics
	Ready   *atomic.Bool
	// Reload re-reads configuration; nil disables the endpoint.
	Reload func() error
	Logger *slog.Logger

	srv *http.Server
}

func (a *AdminServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if a.Ready != nil && a.Ready.Load() {
			writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
			return
		}
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready"})
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		a.Metrics.WritePrometheus(w)
	})
	mux.HandleFunc("POST /-/reload", func(w http.ResponseWriter, _ *http.Request) {
		if a.Reload == nil {
			http.NotFound(w, nil)
			return
		}
		if err := a.Reload(); err != nil {
			// The error text names config fields, never secret values.
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"status": "error", "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "reloaded"})
	})
	return mux
}

// Start listens on addr and serves in the background.
func (a *AdminServer) Start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	a.srv = &http.Server{Handler: a.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := a.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.Logger.Error("admin server stopped", "error", err)
		}
	}()
	return nil
}

func (a *AdminServer) Shutdown(ctx context.Context) error {
	if a.srv == nil {
		return nil
	}
	return a.srv.Shutdown(ctx)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
