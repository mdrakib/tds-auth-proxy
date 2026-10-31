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
	"net/netip"
	"time"

	"github.com/mdrakib/tds-auth-proxy/internal/backend"
	"github.com/mdrakib/tds-auth-proxy/internal/credentials"
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
	// Settings returns the settings for a new session; it is called once
	// per connection.
	Settings func() Settings
	// Authorizer authenticates each client login and chooses its backend.
	Authorizer Authorizer
	Metrics    *monitoring.Metrics
	Logger     *slog.Logger
	// OnOpen and OnClose, if set, are called for every session whose
	// backend login succeeded.
	OnOpen  func(SessionInfo)
	OnClose func(SessionInfo, CloseInfo)
}

// Settings are the per-session parameters that do not depend on the client.
type Settings struct {
	ClientTLS        *tls.Config
	HandshakeTimeout time.Duration
	IdleTimeout      time.Duration
	AuthFailureDelay time.Duration
	// LoginOnlyEncryption answers a client that offers ENCRYPT_OFF the way
	// SQL Server does: TLS protects the LOGIN7 (and so the password), then
	// the session continues unencrypted. Clients asking for encryption still
	// get full TLS. Off: such clients are told encryption is required.
	LoginOnlyEncryption bool
	// AllowUnencrypted accepts clients that do not support encryption
	// (ENCRYPT_NOT_SUP) with no TLS at all, as SQL Server does without
	// forced encryption. Their LOGIN7, password included, travels in clear.
	// Off: such clients are refused.
	AllowUnencrypted bool
}

// clientEncryption is what was negotiated with the client.
type clientEncryption int

const (
	encFull      clientEncryption = iota // TLS for the whole session
	encLoginOnly                         // TLS for LOGIN7 only
	encNone                              // no TLS
)

// ClientLogin is a client's validated LOGIN7, handed to the Authorizer.
type ClientLogin struct {
	Listener string
	User     string
	Password string // cleared after Authorize returns
	AppName  string
	HostName string
	Database string
	Addr     netip.Addr
	// Log carries the connection's context (connection id, listener, client).
	Log *slog.Logger
}

// Grant is a successful authorization: where to log in, and with what.
type Grant struct {
	// User is the client identity for logs.
	User   string
	Target backend.Target
	Creds  credentials.Credentials
	// Done, if set, is called exactly once with the outcome of the backend
	// login (nil on success), including when the session is abandoned.
	Done func(err error)
}

// Authorizer decides whether a client login may proceed. Returning a
// *LoginFailure controls what the client is told; any other error is
// reported as a generic "Login failed for user" (18456).
type Authorizer interface {
	Authorize(ctx context.Context, l *ClientLogin) (*Grant, error)
}

// SessionInfo describes an established session.
type SessionInfo struct {
	ID          string
	Listener    string
	ClientUser  string
	ClientAddr  netip.Addr
	ClientApp   string
	ClientHost  string
	Backend     string
	BackendUser string
	BackendSPID uint16
	Database    string
	Started     time.Time
}

// CloseInfo describes how a session ended.
type CloseInfo struct {
	Reason       string
	Duration     time.Duration
	ClientToBack int64
	BackToClient int64
	Err          error
}

// ErrAbandoned is passed to Grant.Done when the session ended before the
// backend login produced an outcome.
var ErrAbandoned = errors.New("session abandoned before the backend login completed")

// LoginFailure is a failure during the login phase. Message is what the
// client is told (generic); Err goes to the log only. Number 0 closes the
// connection without an error token.
type LoginFailure struct {
	Category string
	Number   int32
	Message  string
	Err      error
}

func (e *LoginFailure) Error() string { return e.Category + ": " + e.Err.Error() }
func (e *LoginFailure) Unwrap() error { return e.Err }

// Fail returns a *LoginFailure.
func Fail(category string, num int32, msg string, err error) *LoginFailure {
	return &LoginFailure{Category: category, Number: num, Message: msg, Err: err}
}

func fail(category string, num int32, msg string, err error) *LoginFailure {
	return Fail(category, num, msg, err)
}

// LoginFailedMessage is the generic message for a rejected client login.
func LoginFailedMessage(user string) string { return loginFailedMsg(user) }

// conn is the per-connection state.
type conn struct {
	h        *Handler
	set      Settings
	id       string
	listener string
	raw      net.Conn
	log      *slog.Logger
	start    time.Time
	tls      *tls.Conn // client TLS session, once established
	// client carries everything after LOGIN7: tls, or the plain connection
	// when only the login was encrypted. Nil until LOGIN7 was read.
	client net.Conn
	user   string // client-supplied username, for error messages
}

// Handle runs a client session to completion and closes raw.
func (h *Handler) Handle(ctx context.Context, raw net.Conn, listener string) {
	set := h.Settings()
	c := &conn{
		h:        h,
		set:      set,
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

	hsCtx, cancel := context.WithTimeout(ctx, set.HandshakeTimeout)
	defer cancel()
	raw.SetDeadline(time.Now().Add(set.HandshakeTimeout))
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
	info := SessionInfo{
		ID: c.id, Listener: listener, ClientUser: be.user, ClientAddr: remoteAddr(raw),
		ClientApp: be.app, ClientHost: be.host, Backend: be.backend, BackendUser: be.identity,
		BackendSPID: be.sess.SPID, Database: be.sess.Database, Started: c.start,
	}
	if h.OnOpen != nil {
		h.OnOpen(info)
	}
	c.log.Info("connection established",
		"event", "connection_established",
		"handshake_ms", handshake.Milliseconds(),
		"packet_size", be.sess.PacketSize,
		"mars", be.mars,
		"database", be.sess.Database,
		"server_version", fmt.Sprintf("%d.%d.%d", be.sess.Ack.Version[0], be.sess.Ack.Version[1], int(be.sess.Ack.Version[2])<<8|int(be.sess.Ack.Version[3])),
	)

	res := relay.Run(ctx, c.client, be.sess.Conn, c.set.IdleTimeout, h.Metrics)
	dur := time.Since(c.start)
	if h.OnClose != nil {
		h.OnClose(info, CloseInfo{Reason: res.Reason, Duration: dur, ClientToBack: res.ClientToBack, BackToClient: res.BackToClient, Err: res.Err})
	}
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
	app      string
	host     string
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

	mars, enc, err := c.prelogin(pre)
	if err != nil {
		return nil, err
	}

	var loginConn net.Conn = pre
	if enc != encNone {
		hc := protocol.NewHandshakeConn(pre)
		tc := tls.Server(hc, c.set.ClientTLS)
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, fail("client_tls", 0, "", fmt.Errorf("TLS handshake: %w", err))
		}
		if err := hc.EndHandshake(); err != nil {
			return nil, fail("client_tls", 0, "", fmt.Errorf("TLS handshake: %w", err))
		}
		c.tls, loginConn = tc, tc
	}

	msg, err := protocol.ReadMessage(loginConn, protocol.MaxPacketSize, protocol.MaxLogin7Size)
	// With login-only encryption TLS ends after LOGIN7: the client sends and
	// expects everything else in clear, starting with the login response.
	c.client = loginConn
	if enc == encLoginOnly {
		c.client = pre
	}
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

	if err := checkClientLogin(login); err != nil {
		return nil, err
	}

	// Authentication, authorization and the backend choice.
	cl := &ClientLogin{
		Listener: c.listener, User: login.UserName, Password: login.Password,
		AppName: login.AppName, HostName: login.HostName, Database: login.Database,
		Addr: remoteAddr(c.raw), Log: c.log,
	}
	login.Password = ""
	g, err := c.h.Authorizer.Authorize(ctx, cl)
	cl.Password = ""
	if err != nil {
		if ctx.Err() != nil {
			return nil, fail("handshake_timeout", 0, "", err)
		}
		var lf *LoginFailure
		if errors.As(err, &lf) {
			return nil, lf
		}
		return nil, fail("client_auth", errLoginFailed, loginFailedMsg(login.UserName), err)
	}
	c.log.Info("client authenticated", "event", "client_authenticated", "client_user", g.User, "backend", g.Target.Name)

	// Backend login. Done is reported exactly once, even if Connect panics.
	reported := false
	report := func(err error) {
		if !reported && g.Done != nil {
			reported = true
			g.Done(err)
		}
	}
	defer report(ErrAbandoned)
	up := upstreamLogin(login, g.Target.Host)
	sess, err := backend.Connect(ctx, g.Target, g.Creds, up, mars)
	report(err)
	if err != nil {
		cat, num := backendCategory(err)
		c.h.Metrics.BackendFailure(g.Target.Name, cat)
		c.log = c.log.With("client_user", g.User, "backend", g.Target.Name, "backend_user", g.Creds.Identity())
		msg := backendFailedMsg(g.Target.Name)
		if num == errServerUnavailable {
			msg = fmt.Sprintf("The proxy could not reach backend server '%s'.", g.Target.Name)
		}
		return nil, fail("backend_"+cat, num, msg, err)
	}

	// Relay the backend's genuine login response.
	pktSize := min(protocol.DefaultPacketSize, sess.PacketSize)
	if err := protocol.WriteMessage(c.client, protocol.PacketReply, sess.SPID, sess.Response, pktSize); err != nil {
		sess.Conn.Close()
		return nil, fail("client_io", 0, "", fmt.Errorf("sending login response: %w", err))
	}
	return &established{sess: sess, user: g.User, backend: g.Target.Name, identity: g.Creds.Identity(),
		app: login.AppName, host: login.HostName, mars: mars}, nil
}

// prelogin answers the client's PRELOGIN. A client offering OFF is told REQ
// (full encryption), or with LoginOnlyEncryption OFF, which encrypts only its
// LOGIN7, as SQL Server does without forced encryption. A client that does
// not support encryption is refused, or with AllowUnencrypted told NOT_SUP
// and served without TLS.
func (c *conn) prelogin(rw net.Conn) (mars bool, enc clientEncryption, err error) {
	msg, err := protocol.ReadMessage(rw, protocol.MaxPacketSize, protocol.MaxPreloginSize)
	if err != nil {
		return false, encFull, fail("client_protocol", 0, "", fmt.Errorf("reading PRELOGIN: %w", err))
	}
	if msg.Type != protocol.PacketPrelogin {
		return false, encFull, fail("client_protocol", 0, "", fmt.Errorf("expected PRELOGIN, got packet type 0x%02x", msg.Type))
	}
	req, err := protocol.ParsePrelogin(msg.Payload)
	if err != nil {
		return false, encFull, fail("client_protocol", 0, "", err)
	}
	offered, ok := req.Encryption()
	if !ok {
		offered = protocol.EncryptOff
	}
	respEnc := protocol.EncryptOn
	switch {
	case offered == protocol.EncryptOff && c.set.LoginOnlyEncryption:
		respEnc, enc = protocol.EncryptOff, encLoginOnly
	case offered == protocol.EncryptNotSup && c.set.AllowUnencrypted:
		respEnc, enc = protocol.EncryptNotSup, encNone
	case offered == protocol.EncryptOff || offered == protocol.EncryptNotSup:
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
		return false, encFull, fail("client_io", 0, "", err)
	}
	if offered == protocol.EncryptNotSup && enc != encNone {
		return false, encFull, fail("client_no_encryption", 0, "", errors.New("client does not support encryption"))
	}
	return mars, enc, nil
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
	var se *LoginFailure
	if !errors.As(err, &se) {
		se = fail("internal", errLoginFailed, loginFailedMsg(c.user), err)
	}
	if isTimeout(err) {
		se.Category = "handshake_timeout"
	}
	c.log.Warn("login failed",
		"event", "login_failed",
		"category", se.Category,
		"client_user_attempted", truncate(c.user, 128),
		"error", se.Err.Error(),
		"elapsed_ms", time.Since(c.start).Milliseconds(),
	)
	if c.client == nil || se.Number == 0 {
		return
	}
	if d := c.set.AuthFailureDelay; d > 0 && se.Number == errLoginFailed {
		t := time.NewTimer(d)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
		}
	}
	c.raw.SetDeadline(time.Now().Add(5 * time.Second))
	payload := protocol.ErrorToken(se.Number, 1, 14, se.Message, c.listener)
	payload = append(payload, protocol.DoneToken(protocol.DoneError)...)
	protocol.WriteMessage(c.client, protocol.PacketReply, 0, payload, protocol.DefaultPacketSize)
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

func remoteAddr(c net.Conn) netip.Addr {
	if ap, err := netip.ParseAddrPort(c.RemoteAddr().String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
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
