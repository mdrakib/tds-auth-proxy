package auth

import (
	"github.com/microsoft/go-mssqldb/integratedauth"
	"github.com/microsoft/go-mssqldb/integratedauth/ntlm"
	"github.com/microsoft/go-mssqldb/msdsn"

	"github.com/mdrakib/tds-auth-proxy/internal/credentials"
	"github.com/mdrakib/tds-auth-proxy/internal/protocol"
)

// sspiUpstream drives an integrated-authentication exchange through one of
// go-mssqldb's public IntegratedAuthenticator implementations. The LOGIN7
// carries the first token with fIntSecurity set; further tokens are sent as
// SSPI (0x11) messages.
type sspiUpstream struct {
	a integratedauth.IntegratedAuthenticator
}

// newNTLM uses go-mssqldb's NTLMv2 implementation, which runs on Linux
// without any system libraries and supports channel binding (EPA).
func newNTLM(c credentials.Credentials, t Target) (Upstream, error) {
	a, err := ntlm.AuthProvider.GetIntegratedAuthenticator(msdsn.Config{
		User:        c.Domain + `\` + c.Username,
		Password:    c.Password,
		Workstation: c.Workstation,
	})
	if err != nil {
		return nil, err
	}
	if c.ChannelBinding && t.TLS != nil {
		cbt, err := integratedauth.GenerateCBTFromTLSConnState(*t.TLS)
		if err == nil && cbt != nil {
			if epa, ok := a.(integratedauth.AuthenticatorWithEPA); ok {
				epa.SetChannelBinding(cbt)
			}
		}
	}
	return &sspiUpstream{a: a}, nil
}

func (s *sspiUpstream) Prepare(l *protocol.Login7) error {
	tok, err := s.a.InitialBytes()
	if err != nil {
		return err
	}
	l.UserName = ""
	l.Password = ""
	l.OptionFlags2 |= protocol.Flag2IntSecurity
	l.SSPI = tok
	return nil
}

func (s *sspiUpstream) Next(serverToken []byte) ([]byte, error) {
	return s.a.NextBytes(serverToken)
}

func (s *sspiUpstream) Close() { s.a.Free() }
