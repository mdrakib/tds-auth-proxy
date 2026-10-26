// Package backend opens an encrypted, authenticated TDS session to a real
// SQL Server. The session it returns is the one later used for relaying;
// no separate "test" login is ever made.
package backend

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/mdrakib/tds-auth-proxy/internal/auth"
	"github.com/mdrakib/tds-auth-proxy/internal/credentials"
	"github.com/mdrakib/tds-auth-proxy/internal/protocol"
)

// MaxLoginResponseSize bounds the reassembled login response.
const MaxLoginResponseSize = 1 << 20

// Error categories, usable with errors.Is.
var (
	ErrConnect  = errors.New("backend connect failed")
	ErrTLS      = errors.New("backend TLS failed")
	ErrProtocol = errors.New("backend protocol error")
	ErrLogin    = errors.New("backend login failed")
)

// LoginError carries the server's ERROR tokens for a rejected login.
type LoginError struct {
	Messages []protocol.ServerMessage
}

func (e *LoginError) Error() string {
	if len(e.Messages) == 0 {
		return "backend rejected login"
	}
	m := e.Messages[0]
	return fmt.Sprintf("backend rejected login: error %d state %d: %s", m.Number, m.State, m.Message)
}

func (e *LoginError) Unwrap() error { return ErrLogin }

// Target is a resolved backend.
type Target struct {
	Name           string
	Host           string
	Port           int
	TLS            *tls.Config
	ConnectTimeout time.Duration
}

// Session is an authenticated backend connection.
type Session struct {
	Conn net.Conn // the TLS connection; owned by the caller
	// Response is the login response payload to relay to the client
	// (SSPI tokens removed).
	Response   []byte
	SPID       uint16
	PacketSize int
	Ack        protocol.LoginAck
	Database   string
}

// Connect dials the backend, negotiates PRELOGIN and TLS, and logs in using
// login as a template (only credential fields are replaced). The caller
// must close Session.Conn.
func Connect(ctx context.Context, t Target, creds credentials.Credentials, login *protocol.Login7, mars bool) (*Session, error) {
	d := net.Dialer{Timeout: t.ConnectTimeout}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(t.Host, strconv.Itoa(t.Port)))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConnect, err)
	}
	ok := false
	defer func() {
		if !ok {
			raw.Close()
		}
	}()
	if dl, has := ctx.Deadline(); has {
		raw.SetDeadline(dl)
	}
	// Abort blocking I/O if the context is cancelled (e.g. shutdown).
	stop := context.AfterFunc(ctx, func() { raw.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	if err := prelogin(raw, mars); err != nil {
		return nil, err
	}

	hc := protocol.NewHandshakeConn(raw)
	tc := tls.Client(hc, t.TLS)
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTLS, err)
	}
	if err := hc.EndHandshake(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTLS, err)
	}

	cs := tc.ConnectionState()
	up, err := auth.NewUpstream(creds, auth.Target{Host: t.Host, Port: t.Port, TLS: &cs})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLogin, err)
	}
	defer up.Close()

	sess, err := login7(tc, up, login)
	if err != nil {
		return nil, err
	}
	raw.SetDeadline(time.Time{})
	ok = true
	sess.Conn = tc
	return sess, nil
}

func prelogin(c net.Conn, mars bool) error {
	marsByte := byte(0)
	if mars {
		marsByte = 1
	}
	req := protocol.Prelogin{Options: []protocol.PreloginOption{
		{Token: protocol.PreloginVersion, Data: protocol.VersionOption(1, 0, 0)},
		{Token: protocol.PreloginEncryption, Data: []byte{protocol.EncryptOn}},
		{Token: protocol.PreloginInstOpt, Data: []byte{0}},
		{Token: protocol.PreloginThreadID, Data: []byte{0, 0, 0, 0}},
		{Token: protocol.PreloginMARS, Data: []byte{marsByte}},
	}}
	if err := protocol.WriteMessage(c, protocol.PacketPrelogin, 0, req.Marshal(), protocol.DefaultPacketSize); err != nil {
		return fmt.Errorf("%w: sending prelogin: %v", ErrConnect, err)
	}
	msg, err := protocol.ReadMessage(c, protocol.MaxPacketSize, protocol.MaxPreloginSize)
	if err != nil {
		return fmt.Errorf("%w: reading prelogin response: %v", ErrProtocol, err)
	}
	if msg.Type != protocol.PacketReply {
		return fmt.Errorf("%w: unexpected prelogin response type 0x%02x", ErrProtocol, msg.Type)
	}
	resp, err := protocol.ParsePrelogin(msg.Payload)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	enc, _ := resp.Encryption()
	if enc != protocol.EncryptOn && enc != protocol.EncryptReq {
		return fmt.Errorf("%w: server does not support encryption (prelogin encryption=%d)", ErrTLS, enc)
	}
	if resp.MARS() != mars {
		return fmt.Errorf("%w: server did not agree to MARS=%v", ErrProtocol, mars)
	}
	return nil
}

func login7(c net.Conn, up auth.Upstream, tmpl *protocol.Login7) (*Session, error) {
	l := *tmpl
	if err := up.Prepare(&l); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLogin, err)
	}
	payload, err := l.Marshal()
	l.Password = ""
	if err != nil {
		return nil, fmt.Errorf("%w: building login: %v", ErrProtocol, err)
	}
	err = protocol.WriteMessage(c, protocol.PacketLogin7, 0, payload, protocol.DefaultPacketSize)
	clear(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: sending login: %v", ErrConnect, err)
	}

	var kept []protocol.Token
	var serverErrs []protocol.ServerMessage
	sess := &Session{PacketSize: int(tmpl.PacketSize)}
	// Integrated authentication may need several round trips; bound them.
	for round := 0; round < 8; round++ {
		msg, err := protocol.ReadMessage(c, protocol.MaxPacketSize, MaxLoginResponseSize)
		if err != nil {
			return nil, fmt.Errorf("%w: reading login response: %v", ErrProtocol, err)
		}
		if msg.Type != protocol.PacketReply {
			return nil, fmt.Errorf("%w: unexpected login response type 0x%02x", ErrProtocol, msg.Type)
		}
		sess.SPID = msg.SPID
		toks, err := protocol.ParseLoginTokens(msg.Payload)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrProtocol, err)
		}
		var sspi []byte
		acked, done := false, false
		for _, tk := range toks {
			switch tk.Type {
			case protocol.TokenSSPI:
				sspi = tk.Body()
				continue // never relayed: the client did not ask for SSPI
			case protocol.TokenFedAuthInfo:
				return nil, fmt.Errorf("%w: server requested federated authentication", ErrProtocol)
			case protocol.TokenLoginAck:
				if sess.Ack, err = protocol.ParseLoginAck(tk); err != nil {
					return nil, fmt.Errorf("%w: %v", ErrProtocol, err)
				}
				acked = true
			case protocol.TokenError:
				if m, err := protocol.ParseServerMessage(tk); err == nil {
					serverErrs = append(serverErrs, m)
				}
			case protocol.TokenEnvChange:
				if err := sess.envChange(tk); err != nil {
					return nil, err
				}
			case protocol.TokenDone:
				done = true
			}
			kept = append(kept, tk)
		}

		if acked {
			if len(kept) == 0 || kept[len(kept)-1].Type != protocol.TokenDone {
				return nil, fmt.Errorf("%w: login response does not end with DONE", ErrProtocol)
			}
			if protocol.DoneStatus(kept[len(kept)-1])&protocol.DoneError != 0 {
				return nil, &LoginError{Messages: serverErrs}
			}
			for _, tk := range kept {
				sess.Response = append(sess.Response, tk.Raw...)
			}
			return sess, nil
		}
		if done || len(serverErrs) > 0 {
			return nil, &LoginError{Messages: serverErrs}
		}
		if sspi == nil {
			return nil, fmt.Errorf("%w: incomplete login response", ErrProtocol)
		}
		reply, err := up.Next(sspi)
		if err != nil {
			return nil, fmt.Errorf("%w: integrated authentication: %v", ErrLogin, err)
		}
		if len(reply) == 0 {
			// Nothing to send: the server's verdict should follow.
			continue
		}
		if err := protocol.WriteMessage(c, protocol.PacketSSPI, 0, reply, protocol.DefaultPacketSize); err != nil {
			return nil, fmt.Errorf("%w: sending SSPI: %v", ErrConnect, err)
		}
	}
	return nil, fmt.Errorf("%w: too many authentication round trips", ErrProtocol)
}

func (s *Session) envChange(tk protocol.Token) error {
	ec, err := protocol.ParseEnvChange(tk)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	switch ec.Type {
	case protocol.EnvRouting:
		// Following a redirect would send the client somewhere the proxy
		// has not authorized; fail closed.
		return fmt.Errorf("%w: server sent a routing redirect, which the proxy does not support", ErrProtocol)
	case protocol.EnvPacketSize:
		n, err := strconv.Atoi(protocol.EnvString(ec.NewValue))
		if err != nil || n < protocol.MinPacketSize || n > protocol.MaxPacketSize {
			return fmt.Errorf("%w: invalid negotiated packet size", ErrProtocol)
		}
		s.PacketSize = n
	case protocol.EnvDatabase:
		s.Database = protocol.EnvString(ec.NewValue)
	}
	return nil
}
