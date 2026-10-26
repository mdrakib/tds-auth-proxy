package auth

import (
	"errors"

	"github.com/mdrakib/tds-auth-proxy/internal/protocol"
)

// sqlUpstream performs SQL Server authentication: the login name and the
// (obfuscated, TLS-protected) password travel in LOGIN7 itself.
type sqlUpstream struct {
	user, password string
}

func (s *sqlUpstream) Prepare(l *protocol.Login7) error {
	l.UserName = s.user
	l.Password = s.password
	l.OptionFlags2 &^= protocol.Flag2IntSecurity
	l.SSPI = nil
	return nil
}

func (s *sqlUpstream) Next([]byte) ([]byte, error) {
	return nil, errors.New("server requested SSPI exchange during SQL authentication")
}

func (s *sqlUpstream) Close() { s.password = "" }
