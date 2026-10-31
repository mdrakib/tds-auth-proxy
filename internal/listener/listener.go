// Package listener owns the TCP listeners: it applies the connection limit
// and IP allowlists, hands accepted connections to the session handler, and
// coordinates graceful shutdown. Listeners can be added and removed while
// the server runs.
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

// Address is a listener to bind.
type Address struct {
	Name    string
	Address string
	Backend string // for the startup log only
}

type Server struct {
	Handler *session.Handler
	Metrics *monitoring.Metrics
	Logger  *slog.Logger
	// Allowed reports whether addr may connect to listener; nil allows all.
	Allowed func(listener string, addr netip.Addr) bool
	// MaxConnections bounds concurrent sessions across all listeners.
	MaxConnections int

	initOnce sync.Once
	slots    chan struct{}
	wg       sync.WaitGroup
	mu       sync.Mutex
	lns      map[string]net.Listener
	sessions map[*active]struct{}
	closed   bool
	ctx      context.Context // cancelled to force-close sessions
	cancel   context.CancelFunc
}

type active struct {
	listener string
	cancel   context.CancelFunc
}

// ErrClosed is returned by Serve after Shutdown.
var ErrClosed = errors.New("listener server is shut down")

func (s *Server) init() {
	s.initOnce.Do(func() {
		s.slots = make(chan struct{}, max(s.MaxConnections, 1))
		s.lns = map[string]net.Listener{}
		s.sessions = map[*active]struct{}{}
		s.ctx, s.cancel = context.WithCancel(context.Background())
	})
}

// Listen binds every address. It fails if any address cannot be bound,
// closing those already opened.
func (s *Server) Listen(addrs []Address) error {
	var opened []string
	for _, a := range addrs {
		ln, err := net.Listen("tcp", a.Address)
		if err == nil {
			err = s.Serve(ln, a.Name)
		}
		if err != nil {
			for _, n := range opened {
				s.Close(n, false)
			}
			return err
		}
		opened = append(opened, a.Name)
		s.Logger.Info("listening", "event", "listener_started", "listener", a.Name, "address", ln.Addr().String(), "backend", a.Backend)
	}
	return nil
}

// Serve accepts connections on ln as listener name until Close or Shutdown.
// It returns at once; the accept loop runs in the background. A listener
// with the same name is closed first.
func (s *Server) Serve(ln net.Listener, name string) error {
	s.init()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		ln.Close()
		return ErrClosed
	}
	if old, ok := s.lns[name]; ok {
		old.Close()
	}
	s.lns[name] = ln
	s.wg.Add(1)
	s.mu.Unlock()
	go s.acceptLoop(ln, name)
	return nil
}

// Close stops accepting on the named listener. With closeSessions, its
// established sessions are closed as well; otherwise they run to completion.
func (s *Server) Close(name string, closeSessions bool) {
	s.init()
	s.mu.Lock()
	defer s.mu.Unlock()
	if ln, ok := s.lns[name]; ok {
		ln.Close()
		delete(s.lns, name)
	}
	if closeSessions {
		for a := range s.sessions {
			if a.listener == name {
				a.cancel()
			}
		}
	}
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
	ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil || (s.Allowed != nil && !s.Allowed(listener, ap.Addr())) {
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
	ctx, cancel := context.WithCancel(s.ctx)
	a := &active{listener: listener, cancel: cancel}
	s.mu.Lock()
	s.sessions[a] = struct{}{}
	s.mu.Unlock()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() { <-s.slots }()
		defer func() {
			s.mu.Lock()
			delete(s.sessions, a)
			s.mu.Unlock()
			cancel()
		}()
		s.Handler.Handle(ctx, c, listener)
	}()
}

// Addrs returns the bound address of each listener.
func (s *Server) Addrs() map[string]net.Addr {
	s.init()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]net.Addr, len(s.lns))
	for name, ln := range s.lns {
		out[name] = ln.Addr()
	}
	return out
}

// Shutdown stops accepting, waits for sessions to finish until ctx expires,
// then force-closes the rest.
func (s *Server) Shutdown(ctx context.Context) error {
	s.init()
	s.mu.Lock()
	s.closed = true
	for name, ln := range s.lns {
		ln.Close()
		delete(s.lns, name)
	}
	s.mu.Unlock()
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
