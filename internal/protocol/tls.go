package protocol

import (
	"errors"
	"fmt"
	"io"
	"net"
)

// HandshakeConn carries a TLS handshake inside TDS PRELOGIN packets, as
// required by TDS 7.x (MS-TDS 2.2.6.5, "TLS/SSL negotiation"). Once the
// handshake completes, EndHandshake switches it to a transparent pass-through
// so TLS records flow directly over the socket.
//
// Use it as the transport of a tls.Conn:
//
//	hc := NewHandshakeConn(raw)
//	tc := tls.Server(hc, cfg)
//	err := tc.Handshake()
//	err = hc.EndHandshake()
//
// It is not safe for concurrent use during the handshake; afterwards Read and
// Write may be used concurrently as with any net.Conn.
type HandshakeConn struct {
	net.Conn
	wrapping bool
	rem      int // unread payload bytes of the current inbound packet
	wbuf     []byte
}

func NewHandshakeConn(c net.Conn) *HandshakeConn {
	return &HandshakeConn{Conn: c, wrapping: true}
}

func (c *HandshakeConn) Read(b []byte) (int, error) {
	if !c.wrapping {
		return c.Conn.Read(b)
	}
	// The peer will not answer until it has seen our pending flight.
	if err := c.flush(); err != nil {
		return 0, err
	}
	for c.rem == 0 {
		h, err := ReadHeader(c.Conn, MaxPacketSize)
		if err != nil {
			return 0, fmt.Errorf("reading TLS handshake packet: %w", err)
		}
		// Some servers answer with packet type 4 rather than 18.
		if h.Type != PacketPrelogin && h.Type != PacketReply {
			return 0, fmt.Errorf("unexpected packet type 0x%02x during TLS handshake", h.Type)
		}
		c.rem = int(h.Length) - HeaderSize
	}
	if len(b) > c.rem {
		b = b[:c.rem]
	}
	n, err := c.Conn.Read(b)
	c.rem -= n
	return n, err
}

func (c *HandshakeConn) Write(b []byte) (int, error) {
	if !c.wrapping {
		return c.Conn.Write(b)
	}
	if len(c.wbuf)+len(b) > 1<<20 {
		return 0, errors.New("TLS handshake flight too large")
	}
	c.wbuf = append(c.wbuf, b...)
	return len(b), nil
}

func (c *HandshakeConn) flush() error {
	if len(c.wbuf) == 0 {
		return nil
	}
	err := WriteMessage(c.Conn, PacketPrelogin, 0, c.wbuf, DefaultPacketSize)
	c.wbuf = nil
	return err
}

// EndHandshake sends any buffered handshake bytes and switches to
// pass-through mode. Call it after tls.Conn.Handshake returns successfully.
func (c *HandshakeConn) EndHandshake() error {
	if err := c.flush(); err != nil {
		return err
	}
	if c.rem != 0 {
		return io.ErrUnexpectedEOF
	}
	c.wrapping = false
	return nil
}
