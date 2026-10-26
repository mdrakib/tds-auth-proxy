// Package session handles one client connection end to end: PRELOGIN, TLS,
// LOGIN7 and client authentication, authorization, the backend login, and
// finally the relay.
package session

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/mdrakib/tds-auth-proxy/internal/auth"
	"github.com/mdrakib/tds-auth-proxy/internal/backend"
	"github.com/mdrakib/tds-auth-proxy/internal/monitoring"
	"github.com/mdrakib/tds-auth-proxy/internal/protocol"
	"github.com/mdrakib/tds-auth-proxy/internal/relay"
)

// SQL Server error numbers used for proxy-generated login failures.
const (
	errLoginFailed       = 18456 // "Login failed for user"
	errServerUnavailable = 18401 // server not accepting logins (backend unreachable)
)

// Handler serves client connections. It is safe for concurrent use.
type Handler struct {
	State   func() *State
	Metrics *monitoring.Metrics
	Logger  *slog.Logger
}

// sessionError is a failure during the login phase. clientMsg is what the
// client is told (generic); the wrapped error goes to the log only.
type sessionError struct {
	category  string
	clientNum int32
	clientMsg string
	err       error
}

func (e *sessionError) Error() string { return e.category + ": " + e.err.Error() }
func (e *sessionError) Unwrap() error { return e.err }

func fail(category string, num int32, msg string, err error) *sessionError {
	return &sessionError{category: category, clientNum: num, clientMsg: msg, err: err}
}

// conn is the per-connection state.
type conn struct {
	h        *Handler
	st       *State
	id       string
	listener string
	raw      net.Conn
	log      *slog.Logger
	start    time.Time
	tls      *tls.Conn // client TLS session, once established
	user     string    // client-supplied username, for error messages
}

// Handle runs a client session to completion and closes raw.
func (h *Handler) Handle(ctx context.Context, raw net.Conn, listener string) {
	st := h.State()
	c := &conn{
		h:        h,
		st:       st,
		id:       newID(),
		listener: listener,
		raw:      raw,
		start:    time.Now(),
	}
	c.log = h.Logger.With("connection_id", c.id, "listener", listener, "client_ip", remoteIP(raw))
	defer raw.Close()

	h.Metrics.TotalConnections.Add(1)
	h.Metrics.ActiveSessions.Add(1)
	defer h.Metrics.ActiveSessions.Add(-1)

	c.log.Debug("connection accepted", "event", "connection_accepted")

	hsCtx, cancel := context.WithTimeout(ctx, st.Config.Server.HandshakeTimeout)
	defer cancel()
	raw.SetDeadline(time.Now().Add(st.Config.Server.HandshakeTimeout))
	// Unblock any pending read on shutdown or handshake timeout.
	stop := context.AfterFunc(hsCtx, func() { raw.SetDeadline(time.Unix(1, 0)) })

	defer func() {
		if r := recover(); r != nil {
			c.log.Error("session panic", "event", "internal_error", "error", fmt.Sprint(r))
		}
	}()

	be, err := c.establish(hsCtx)
	if !stop() && err == nil {
		// The deadline callback already fired (timeout or shutdown racing a
		// successful login); it may still poison the socket deadline.
		be.sess.Conn.Close()
		err = fail("handshake_timeout", 0, "", context.DeadlineExceeded)
	}
	if err != nil {
		c.loginFailed(ctx, err)
		return
	}
	defer be.sess.Conn.Close()
	raw.SetDeadline(time.Time{})

	handshake := time.Since(c.start)
	h.Metrics.HandshakeDuration.Observe(handshake)
	c.log = c.log.With("client_user", be.user, "backend", be.backend, "backend_user", be.identity, "backend_spid", be.sess.SPID)
	c.log.Info("connection established",
		"event", "connection_established",
		"handshake_ms", handshake.Milliseconds(),
		"packet_size", be.sess.PacketSize,
		"mars", be.mars,
		"database", be.sess.Database,
		"server_version", fmt.Sprintf("%d.%d.%d", be.sess.Ack.Version[0], be.sess.Ack.Version[1], int(be.sess.Ack.Version[2])<<8|int(be.sess.Ack.Version[3])),
	)

	res := relay.Run(ctx, c.tls, be.sess.Conn, c.st.Config.Server.IdleTimeout, h.Metrics)
	dur := time.Since(c.start)
	h.Metrics.SessionDuration.Observe(dur)
	attrs := []any{
		"event", "connection_closed",
		"reason", res.Reason,
		"duration_ms", dur.Milliseconds(),
		"bytes_client_to_backend", res.ClientToBack,
		"bytes_backend_to_client", res.BackToClient,
	}
	if res.Err != nil {
		attrs = append(attrs, "error", res.Err.Error())
	}
	c.log.Info("connection closed", attrs...)
}

type established struct {
	sess     *backend.Session
	user     string
	backend  string
	identity string
	mars     bool
}

func (c *conn) establish(ctx context.Context) (*established, error) {
	first := make([]byte, 1)
	if _, err := io.ReadFull(c.raw, first); err != nil {
		return nil, fail("client_protocol", 0, "", fmt.Errorf("reading first byte: %w", err))
	}
	if first[0] == 0x16 {
		// A TLS ClientHello before PRELOGIN means TDS 8.0 (Encrypt=Strict).
		return nil, fail("unsupported", 0, "", errors.New("client uses TDS 8.0 strict encryption, which is not supported; use Encrypt=Mandatory/True"))
	}
	// Put the sniffed byte back in front of the stream.
	pre := &prefixConn{Conn: c.raw, prefix: first}

	mars, err := c.prelogin(pre)
	if err != nil {
		return nil, err
	}

	hc := protocol.NewHandshakeConn(pre)
	tc := tls.Server(hc, c.st.ClientTLS)
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, fail("client_tls", 0, "", fmt.Errorf("TLS handshake: %w", err))
	}
	if err := hc.EndHandshake(); err != nil {
		return nil, fail("client_tls", 0, "", fmt.Errorf("TLS handshake: %w", err))
	}
	c.tls = tc

	msg, err := protocol.ReadMessage(tc, protocol.MaxPacketSize, protocol.MaxLogin7Size)
	if err != nil {
		return nil, fail("client_protocol", 0, "", fmt.Errorf("reading LOGIN7: %w", err))
	}
	if msg.Type != protocol.PacketLogin7 {
		return nil, fail("client_protocol", 0, "", fmt.Errorf("expected LOGIN7, got packet type 0x%02x", msg.Type))
	}
	login, err := protocol.ParseLogin7(msg.Payload)
	clear(msg.Payload)
	if err != nil {
		return nil, fail("client_protocol", errLoginFailed, "Login failed: malformed login request.", err)
	}
	c.user = login.UserName
	c.log = c.log.With("client_app", login.AppName, "client_host", login.HostName)

	// Authenticate and authorize against the configuration current now, not
	// the one at accept time: a client stalling its handshake must not
	// benefit from users, grants or profiles a reload has since removed.
	c.st = c.h.State()

	if err := checkClientLogin(login); err != nil {
		return nil, err
	}

	// Authentication.
	password := login.Password
	login.Password = ""
	u, err := c.st.Auth.Authenticate(ctx, login.UserName, password)
	password = ""
	if err != nil && ctx.Err() != nil {
		return nil, fail("handshake_timeout", 0, "", err)
	}
	if err != nil {
		outcome := "invalid_credentials"
		if errors.Is(err, auth.ErrUserDisabled) {
			outcome = "disabled"
		}
		c.h.Metrics.AuthResult(outcome)
		return nil, fail("client_auth_"+outcome, errLoginFailed, loginFailedMsg(login.UserName), err)
	}

	// Authorization.
	l := c.st.Listeners[c.listener]
	b, ok := c.st.Backends[l.Backend]
	if !ok {
		return nil, fail("config", errLoginFailed, loginFailedMsg(login.UserName), fmt.Errorf("listener backend %q not configured", l.Backend))
	}
	if !u.MayAccess(l.Backend) {
		c.h.Metrics.AuthResult("unauthorized")
		return nil, fail("client_unauthorized", errLoginFailed, loginFailedMsg(login.UserName),
			fmt.Errorf("user %q is not authorized for backend %q", u.Name, l.Backend))
	}
	c.h.Metrics.AuthResult("success")
	c.log.Info("client authenticated", "event", "client_authenticated", "client_user", u.Name, "backend", l.Backend)

	// Backend login with current credentials.
	creds, err := c.st.Creds.GetCredentials(ctx, b.Profile)
	if err != nil {
		c.h.Metrics.BackendFailure(b.Name, "credentials")
		return nil, fail("backend_credentials", errLoginFailed, backendFailedMsg(b.Name), err)
	}
	up := upstreamLogin(login, b.Host)
	sess, err := backend.Connect(ctx, b.Target, creds, up, mars)
	if err != nil {
		cat, num := backendCategory(err)
		c.h.Metrics.BackendFailure(b.Name, cat)
		c.log = c.log.With("client_user", u.Name, "backend", b.Name, "backend_user", creds.Identity())
		msg := backendFailedMsg(b.Name)
		if num == errServerUnavailable {
			msg = fmt.Sprintf("The proxy could not reach backend server '%s'.", b.Name)
		}
		return nil, fail("backend_"+cat, num, msg, err)
	}

	// Relay the backend's genuine login response.
	pktSize := min(protocol.DefaultPacketSize, sess.PacketSize)
	if err := protocol.WriteMessage(tc, protocol.PacketReply, sess.SPID, sess.Response, pktSize); err != nil {
		sess.Conn.Close()
		return nil, fail("client_io", 0, "", fmt.Errorf("sending login response: %w", err))
	}
	return &established{sess: sess, user: u.Name, backend: b.Name, identity: creds.Identity(), mars: mars}, nil
}

// prelogin answers the client's PRELOGIN. Encryption is always required:
// a client offering OFF is told REQ (full encryption), and a client that
// does not support encryption is refused.
func (c *conn) prelogin(rw net.Conn) (mars bool, err error) {
	msg, err := protocol.ReadMessage(rw, protocol.MaxPacketSize, protocol.MaxPreloginSize)
	if err != nil {
		return false, fail("client_protocol", 0, "", fmt.Errorf("reading PRELOGIN: %w", err))
	}
	if msg.Type != protocol.PacketPrelogin {
		return false, fail("client_protocol", 0, "", fmt.Errorf("expected PRELOGIN, got packet type 0x%02x", msg.Type))
	}
	req, err := protocol.ParsePrelogin(msg.Payload)
	if err != nil {
		return false, fail("client_protocol", 0, "", err)
	}
	enc, ok := req.Encryption()
	if !ok {
		enc = protocol.EncryptOff
	}
	respEnc := protocol.EncryptOn
	if enc == protocol.EncryptOff || enc == protocol.EncryptNotSup {
		respEnc = protocol.EncryptReq
	}
	mars = req.MARS()
	marsByte := byte(0)
	if mars {
		marsByte = 1
	}
	resp := protocol.Prelogin{Options: []protocol.PreloginOption{
		{Token: protocol.PreloginVersion, Data: protocol.VersionOption(16, 0, 1000)},
		{Token: protocol.PreloginEncryption, Data: []byte{respEnc}},
		{Token: protocol.PreloginInstOpt, Data: []byte{0}},
		{Token: protocol.PreloginThreadID, Data: nil},
		{Token: protocol.PreloginMARS, Data: []byte{marsByte}},
	}}
	if _, ok := req.Get(protocol.PreloginFedAuthRequired); ok {
		resp.Options = append(resp.Options, protocol.PreloginOption{Token: protocol.PreloginFedAuthRequired, Data: []byte{0}})
	}
	if err := protocol.WriteMessage(rw, protocol.PacketReply, 0, resp.Marshal(), protocol.DefaultPacketSize); err != nil {
		return false, fail("client_io", 0, "", err)
	}
	if enc == protocol.EncryptNotSup {
		return false, fail("client_no_encryption", 0, "", errors.New("client does not support encryption"))
	}
	return mars, nil
}

// checkClientLogin rejects login requests the proxy cannot honour.
func checkClientLogin(l *protocol.Login7) error {
	reject := func(reason string) error {
		return fail("client_unsupported", errLoginFailed, "Login failed: "+reason, errors.New(reason))
	}
	if v := l.TDSVersion >> 24; v < 0x72 || v > 0x74 {
		return reject(fmt.Sprintf("TDS version 0x%08x is not supported (7.2-7.4 required).", l.TDSVersion))
	}
	if l.OptionFlags2&protocol.Flag2IntSecurity != 0 || len(l.SSPI) > 0 {
		return reject("integrated (Windows) authentication to the proxy is not supported; use SQL authentication with your proxy account.")
	}
	if l.OptionFlags3&protocol.Flag3ChangePassword != 0 || l.ChangePassword != "" {
		return reject("password change through the proxy is not supported.")
	}
	if l.OptionFlags3&protocol.Flag3UserInstance != 0 || l.AtchDBFile != "" {
		return reject("user instances and AttachDBFilename are not supported.")
	}
	for _, f := range l.Features {
		if f.ID == protocol.FeatureFedAuth {
			return reject("Microsoft Entra (federated) authentication to the proxy is not supported.")
		}
	}
	if l.UserName == "" {
		return reject("a user name is required.")
	}
	return nil
}

// relayedFeatures are LOGIN7 feature extensions passed to the backend. They
// only change the token stream that both ends see identically through the
// relay. Others are dropped, so the backend does not acknowledge them and
// the client treats them as unsupported:
//   - SESSIONRECOVERY: reconnect state would be replayed against a new
//     backend login; disabled rather than risk inconsistent sessions.
//   - AZURESQLDNSCACHING / ENHANCEDROUTING: would let the client bypass the proxy.
var relayedFeatures = map[uint8]bool{
	protocol.FeatureColumnEncryption:   true,
	protocol.FeatureGlobalTransactions: true,
	protocol.FeatureAzureSQLSupport:    true,
	protocol.FeatureDataClassification: true,
	protocol.FeatureUTF8Support:        true,
	protocol.FeatureJSONSupport:        true,
	protocol.FeatureVectorSupport:      true,
	protocol.FeatureUserAgent:          true,
}

// upstreamLogin derives the backend LOGIN7 from the client's. Credentials
// are filled in later by the backend auth mechanism.
func upstreamLogin(client *protocol.Login7, backendHost string) *protocol.Login7 {
	l := *client
	l.UserName, l.Password, l.SSPI = "", "", nil
	l.ServerName = backendHost
	if client.Features != nil {
		l.Features = []protocol.Feature{}
		for _, f := range client.Features {
			if relayedFeatures[f.ID] {
				l.Features = append(l.Features, f)
			}
		}
	}
	return &l
}

func backendCategory(err error) (string, int32) {
	switch {
	case errors.Is(err, backend.ErrLogin):
		return "login", errLoginFailed
	case errors.Is(err, backend.ErrTLS):
		return "tls", errServerUnavailable
	case errors.Is(err, backend.ErrProtocol):
		return "protocol", errServerUnavailable
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout", errServerUnavailable
	default:
		return "connect", errServerUnavailable
	}
}

func loginFailedMsg(user string) string {
	return fmt.Sprintf("Login failed for user '%s'.", truncate(user, 128))
}

func backendFailedMsg(name string) string {
	return fmt.Sprintf("Login failed: the proxy could not log in to backend server '%s'. Contact the proxy administrator.", name)
}

// loginFailed logs a login-phase failure and, when the client is far enough
// along to understand a token stream, sends it a generic error.
func (c *conn) loginFailed(ctx context.Context, err error) {
	var se *sessionError
	if !errors.As(err, &se) {
		se = fail("internal", errLoginFailed, loginFailedMsg(c.user), err)
	}
	if isTimeout(err) {
		se.category = "handshake_timeout"
	}
	c.log.Warn("login failed",
		"event", "login_failed",
		"category", se.category,
		"client_user_attempted", truncate(c.user, 128),
		"error", se.err.Error(),
		"elapsed_ms", time.Since(c.start).Milliseconds(),
	)
	if c.tls == nil || se.clientNum == 0 {
		return
	}
	if d := c.st.Config.Server.AuthFailureDelay; d > 0 && se.clientNum == errLoginFailed {
		t := time.NewTimer(d)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
		}
	}
	c.raw.SetDeadline(time.Now().Add(5 * time.Second))
	payload := protocol.ErrorToken(se.clientNum, 1, 14, se.clientMsg, c.listener)
	payload = append(payload, protocol.DoneToken(protocol.DoneError)...)
	protocol.WriteMessage(c.tls, protocol.PacketReply, 0, payload, protocol.DefaultPacketSize)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) ||
		(errors.As(err, &ne) && ne.Timeout())
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

func newID() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func remoteIP(c net.Conn) string {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return a.IP.String()
	}
	return c.RemoteAddr().String()
}

// prefixConn replays bytes already consumed while sniffing.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if len(p.prefix) > 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}
