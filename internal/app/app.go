// Package app wires configuration, listeners, the admin server and
// configuration reloads together. cmd/tds-proxy and the integration tests
// both drive the proxy through it.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"github.com/mdrakib/tds-auth-proxy/internal/config"
	"github.com/mdrakib/tds-auth-proxy/internal/credentials"
	"github.com/mdrakib/tds-auth-proxy/internal/listener"
	"github.com/mdrakib/tds-auth-proxy/internal/monitoring"
	"github.com/mdrakib/tds-auth-proxy/internal/session"
)

type App struct {
	path    string
	logger  *slog.Logger
	level   *slog.LevelVar
	store   *credentials.Store
	guard   *credentials.Guard
	state   atomic.Pointer[session.State]
	ready   atomic.Bool
	reload  sync.Mutex
	stop    sync.Once
	Metrics *monitoring.Metrics
	srv     *listener.Server
	admin   *monitoring.AdminServer
}

// New loads the configuration at path and prepares the proxy without
// binding any sockets. level, if non-nil, is updated from logging.level.
func New(path string, logger *slog.Logger, level *slog.LevelVar) (*App, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	a := &App{path: path, logger: logger, level: level, Metrics: monitoring.NewMetrics()}
	a.store = credentials.NewStore(cfg.CredentialProfiles)
	st, err := session.BuildState(cfg, a.store)
	if err != nil {
		return nil, err
	}
	a.state.Store(st)
	a.setLevel(cfg)
	a.guard = credentials.NewGuard()
	a.guard.OnChange = func(profile string, blocked bool) {
		a.Metrics.SetCredentialsBlocked(profile, blocked)
		if !blocked {
			logger.Info("backend logins resumed for credential profile", "event", "backend_credentials_unblocked", "profile", profile)
		}
	}
	handler := &session.Handler{State: a.state.Load, Metrics: a.Metrics, Logger: logger, Guard: a.guard}
	a.srv = &listener.Server{Handler: handler, Metrics: a.Metrics, Logger: logger}
	a.admin = &monitoring.AdminServer{Metrics: a.Metrics, Ready: &a.ready, Reload: a.Reload, Logger: logger}
	return a, nil
}

func (a *App) setLevel(cfg *config.Config) {
	if a.level == nil {
		return
	}
	var l slog.Level
	l.UnmarshalText([]byte(cfg.Logging.Level))
	a.level.Set(l)
}

// Start binds the admin server and all listeners.
func (a *App) Start() error {
	cfg := a.state.Load().Config
	if cfg.Admin.Listen != "" {
		addr := config.LoopbackDefault(cfg.Admin.Listen)
		if err := a.admin.Start(addr); err != nil {
			return fmt.Errorf("admin server: %w", err)
		}
		a.logger.Info("admin server listening", "address", addr)
	}
	if err := a.srv.Listen(a.state.Load()); err != nil {
		a.admin.Shutdown(context.Background())
		return err
	}
	a.ready.Store(true)
	a.logger.Info("proxy started", "event", "started", "listeners", len(cfg.Listeners), "users", a.state.Load().Auth.UserCount())
	return nil
}

// Addrs returns the bound listener addresses by listener name.
func (a *App) Addrs() map[string]net.Addr { return a.srv.Addrs() }

// Reload re-reads the configuration file. On any error the running
// configuration is kept. Established sessions are never touched.
func (a *App) Reload() error {
	a.reload.Lock()
	defer a.reload.Unlock()
	cfg, err := config.Load(a.path)
	if err == nil {
		var st *session.State
		if st, err = session.BuildState(cfg, a.store.WithProfiles(cfg.CredentialProfiles)); err == nil {
			warnRestartRequired(a.logger, a.state.Load().Config, cfg)
			a.state.Store(st)
			a.setLevel(cfg)
			// A reload is the operator's way to retry blocked credentials
			// (e.g. after unlocking the account without changing the secret).
			a.guard.Reset()
			a.logger.Info("configuration reloaded", "event", "config_reloaded", "users", st.Auth.UserCount(), "backends", len(st.Backends))
			return nil
		}
	}
	a.logger.Error("configuration reload failed; keeping current configuration", "event", "config_reload_failed", "error", err)
	return err
}

// Shutdown stops accepting connections and waits for sessions to end, up to
// server.shutdown_timeout (or ctx), before closing the rest.
func (a *App) Shutdown(ctx context.Context) {
	a.stop.Do(func() { a.shutdown(ctx) })
}

func (a *App) shutdown(ctx context.Context) {
	a.ready.Store(false)
	timeout := a.state.Load().Config.Server.ShutdownTimeout
	a.logger.Info("shutting down", "event", "shutdown", "timeout", timeout.String(), "active_sessions", a.Metrics.ActiveSessions.Load())
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	a.srv.Shutdown(ctx)
	a.admin.Shutdown(context.Background())
	a.logger.Info("stopped", "event", "stopped")
}

// warnRestartRequired logs settings that a reload cannot apply.
func warnRestartRequired(logger *slog.Logger, old, cur *config.Config) {
	oldAddrs := map[string]string{}
	for _, l := range old.Listeners {
		oldAddrs[l.Name] = l.Listen
	}
	for _, l := range cur.Listeners {
		if a, ok := oldAddrs[l.Name]; !ok || a != l.Listen {
			logger.Warn("listener added or address changed; restart required for it to take effect", "listener", l.Name)
		}
	}
	if old.Server.MaxConnections != cur.Server.MaxConnections || old.Admin.Listen != cur.Admin.Listen {
		logger.Warn("server.max_connections and admin.listen changes require a restart")
	}
}
