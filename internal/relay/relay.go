// Package relay forwards TDS traffic between an authenticated client and its
// backend session without interpreting SQL.
//
// Forwarding is frame-aware rather than a raw byte copy: each TDS packet (or
// SMP frame when MARS is in use) is read completely and written with a single
// Write. Both sides negotiated the same packet size (the backend's ENVCHANGE
// is relayed to the client verbatim), so no re-framing is needed; reading
// whole frames lets the proxy validate lengths, bound memory, and keep one
// TLS record per packet, which SQL Server handles best.
package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mdrakib/tds-auth-proxy/internal/protocol"
)

const (
	smpID         = 0x53
	smpHeaderSize = 16
	maxFrameSize  = protocol.MaxPacketSize + smpHeaderSize
)

// Reasons a relay ends.
const (
	ReasonClientClosed  = "client_closed"
	ReasonBackendClosed = "backend_closed"
	ReasonIdleTimeout   = "idle_timeout"
	ReasonShutdown      = "shutdown"
	ReasonClientError   = "client_error"
	ReasonBackendError  = "backend_error"
)

// Result summarizes a finished relay.
type Result struct {
	Reason       string
	Err          error
	ClientToBack int64
	BackToClient int64
}

// Counter is notified of forwarded bytes (for metrics).
type Counter interface {
	AddBytes(clientToBackend, backendToClient int64)
}

// Run relays until either side closes, the context is cancelled or the
// connection is idle for idleTimeout (0 disables). It closes both
// connections before returning.
func Run(ctx context.Context, client, backend net.Conn, idleTimeout time.Duration, counter Counter) Result {
	var (
		res      Result
		once     sync.Once
		reason   string
		cause    error
		lastSeen atomic.Int64
	)
	finish := func(r string, err error) {
		once.Do(func() {
			reason, cause = r, err
			client.Close()
			backend.Close()
		})
	}
	lastSeen.Store(time.Now().UnixNano())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer recoverTo(finish, ReasonClientError)
		n, rerr, werr := copyFrames(backend, client, &lastSeen, counter, true)
		res.ClientToBack = n
		finish(classify(rerr, werr, ReasonClientClosed, ReasonClientError, ReasonBackendError))
	}()
	go func() {
		defer wg.Done()
		defer recoverTo(finish, ReasonBackendError)
		n, rerr, werr := copyFrames(client, backend, &lastSeen, counter, false)
		res.BackToClient = n
		finish(classify(rerr, werr, ReasonBackendClosed, ReasonBackendError, ReasonClientError))
	}()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	var tick <-chan time.Time
	if idleTimeout > 0 {
		t := time.NewTicker(min(idleTimeout/4, 30*time.Second) + time.Millisecond)
		defer t.Stop()
		tick = t.C
	}
	cancelled := ctx.Done()
	for loop := true; loop; {
		select {
		case <-done:
			loop = false
		case <-cancelled:
			cancelled = nil // finish closes both sides; just wait for done
			finish(ReasonShutdown, nil)
		case <-tick:
			if time.Since(time.Unix(0, lastSeen.Load())) >= idleTimeout {
				finish(ReasonIdleTimeout, nil)
			}
		}
	}
	<-done
	res.Reason, res.Err = reason, cause
	return res
}

// recoverTo turns a panic in a relay goroutine into a session error, so one
// session can never take down the process.
func recoverTo(finish func(string, error), reason string) {
	if r := recover(); r != nil {
		finish(reason, fmt.Errorf("internal error: %v", r))
	}
}

func classify(rerr, werr error, eofReason, readErrReason, writeErrReason string) (string, error) {
	switch {
	case werr != nil:
		return writeErrReason, werr
	case rerr == nil || errors.Is(rerr, io.EOF) || errors.Is(rerr, net.ErrClosed):
		return eofReason, nil
	default:
		return readErrReason, rerr
	}
}

// copyFrames forwards whole TDS packets / SMP frames from src to dst. It
// returns the number of bytes forwarded, a read error and a write error.
func copyFrames(dst io.Writer, src io.Reader, lastSeen *atomic.Int64, counter Counter, fromClient bool) (int64, error, error) {
	buf := make([]byte, maxFrameSize)
	var total int64
	for {
		if _, err := io.ReadFull(src, buf[:protocol.HeaderSize]); err != nil {
			return total, err, nil
		}
		var size int
		if buf[0] == smpID {
			if _, err := io.ReadFull(src, buf[protocol.HeaderSize:smpHeaderSize]); err != nil {
				return total, err, nil
			}
			size = int(binary.LittleEndian.Uint32(buf[4:8]))
			if size < smpHeaderSize || size > maxFrameSize {
				return total, fmt.Errorf("invalid SMP frame length %d", size), nil
			}
			if _, err := io.ReadFull(src, buf[smpHeaderSize:size]); err != nil {
				return total, err, nil
			}
		} else {
			size = int(binary.BigEndian.Uint16(buf[2:4]))
			if size < protocol.HeaderSize || size > protocol.MaxPacketSize {
				return total, fmt.Errorf("invalid TDS packet length %d", size), nil
			}
			if _, err := io.ReadFull(src, buf[protocol.HeaderSize:size]); err != nil {
				return total, err, nil
			}
		}
		if _, err := dst.Write(buf[:size]); err != nil {
			return total, nil, err
		}
		total += int64(size)
		lastSeen.Store(time.Now().UnixNano())
		if counter != nil {
			if fromClient {
				counter.AddBytes(int64(size), 0)
			} else {
				counter.AddBytes(0, int64(size))
			}
		}
	}
}
