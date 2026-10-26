// Package listener owns the TCP listeners: it applies the connection limit
// and IP allowlists, hands accepted connections to the session handler, and
// coordinates graceful shutdown.
package listener

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/mdrakib/tds-auth-proxy/internal/monitoring"
	"github.com/mdrakib/tds-auth-proxy/internal/session"
)

type Server struct {
	Handler *session.Handler
	Metrics *monitoring.Metrics
	Logger  *slog.Logger

	slots  chan struct{}
	wg     sync.WaitGroup
	mu     sync.Mutex
	lns    []net.Listener
	names  []string
	ctx    context.Context // cancelled to force-close sessions
	cancel context.CancelFunc
}

// Listen binds every configured listener. It fails if any address cannot
// be bound, closing those already opened.
func (s *Server) Listen(st *session.State) error {
	s.slots = make(chan struct{}, st.Config.Server.MaxConnections)
	s.ctx, s.cancel = context.WithCancel(context.Background())
	for _, l := range st.Config.Listeners {
		ln, err := net.Listen("tcp", l.Listen)
		if err != nil {
			s.closeListeners()
			return err
		}
		s.Logger.Info("listening", "event", "listener_started", "listener", l.Name, "address", ln.Addr().String(), "backend", l.Backend)
		s.mu.Lock()
		s.lns = append(s.lns, ln)
		s.names = append(s.names, l.Name)
		s.mu.Unlock()
		s.wg.Add(1)
		go s.acceptLoop(ln, l.Name)
	}
	return nil
}

func (s *Server) acceptLoop(ln net.Listener, name string) {
	defer s.wg.Done()
	var backoff time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Transient errors such as EMFILE: back off and retry.
			backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
			s.Logger.Error("accept failed", "listener", name, "error", err)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		s.accept(c, name)
	}
}

func (s *Server) accept(c net.Conn, listener string) {
	st := s.Handler.State()
	ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil || !st.Allowed(listener, ap.Addr()) {
		s.Metrics.RejectedConnections.Add(1)
		s.Logger.Warn("connection rejected", "event", "connection_rejected", "reason", "ip_not_allowed", "listener", listener, "client_ip", c.RemoteAddr().String())
		c.Close()
		return
	}
	select {
	case s.slots <- struct{}{}:
	default:
		s.Metrics.RejectedConnections.Add(1)
		s.Logger.Warn("connection rejected", "event", "connection_rejected", "reason", "max_connections", "listener", listener, "client_ip", ap.Addr().String())
		c.Close()
		return
	}
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() { <-s.slots }()
		s.Handler.Handle(s.ctx, c, listener)
	}()
}

// Addrs returns the bound address of each listener.
func (s *Server) Addrs() map[string]net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]net.Addr, len(s.lns))
	for i, ln := range s.lns {
		out[s.names[i]] = ln.Addr()
	}
	return out
}

func (s *Server) closeListeners() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ln := range s.lns {
		ln.Close()
	}
	s.lns, s.names = nil, nil
}

// Shutdown stops accepting, waits for sessions to finish until ctx expires,
// then force-closes the rest.
func (s *Server) Shutdown(ctx context.Context) error {
	s.closeListeners()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		s.Logger.Warn("shutdown timeout reached; closing remaining sessions", "active_sessions", s.Metrics.ActiveSessions.Load())
		s.cancel()
		<-done
		return ctx.Err()
	}
}
