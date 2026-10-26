package auth

import (
	"crypto/tls"
	"fmt"

	"github.com/mdrakib/tds-auth-proxy/internal/config"
	"github.com/mdrakib/tds-auth-proxy/internal/credentials"
	"github.com/mdrakib/tds-auth-proxy/internal/protocol"
)

// Upstream fills in the authentication part of an upstream LOGIN7 and, for
// integrated authentication, answers the server's SSPI challenges.
type Upstream interface {
	// Prepare sets the credential fields of the outgoing LOGIN7.
	Prepare(l *protocol.Login7) error
	// Next answers an SSPI token from the server. An empty reply means
	// nothing has to be sent.
	Next(serverToken []byte) ([]byte, error)
	Close()
}

// Target describes the backend being authenticated to.
type Target struct {
	Host string
	Port int
	// TLS is the state of the backend TLS session, used for NTLM channel
	// binding (Extended Protection).
	TLS *tls.ConnectionState
}

// NewUpstream returns the mechanism matching the credential type.
func NewUpstream(c credentials.Credentials, t Target) (Upstream, error) {
	switch c.Type {
	case config.CredSQL:
		return &sqlUpstream{user: c.Username, password: c.Password}, nil
	case config.CredNTLM:
		return newNTLM(c, t)
	case config.CredKerberos:
		return newKerberos(c, t)
	}
	return nil, fmt.Errorf("unsupported credential type %q", c.Type)
}
