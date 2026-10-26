package backend

import (
	"errors"
	"fmt"
	"testing"

	"github.com/mdrakib/tds-auth-proxy/internal/protocol"
)

func TestCredentialsRejected(t *testing.T) {
	login := func(nums ...int32) error {
		le := &LoginError{}
		for _, n := range nums {
			le.Messages = append(le.Messages, protocol.ServerMessage{Number: n})
		}
		return fmt.Errorf("wrapped: %w", le)
	}
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"wrong password", login(18456), true},
		{"password expired", login(18487), true},
		{"must change", login(18488), true},
		{"locked out", login(18486), true},
		{"ntlm untrusted domain", login(18452), true},
		{"database unavailable", login(4060, 18456), false},
		{"default database", login(4064, 18456), false},
		{"other server error", login(18401), false},
		{"kerberos preauth", fmt.Errorf("%w: KRB Error: (24) KDC_ERR_PREAUTH_FAILED Pre-authentication information was invalid", ErrLogin), true},
		{"kerberos expired", fmt.Errorf("%w: KRB Error: (23) KDC_ERR_KEY_EXPIRED Password has expired", ErrLogin), true},
		{"kerberos config", fmt.Errorf("%w: krb5.conf not found", ErrLogin), false},
		{"connect", fmt.Errorf("%w: refused", ErrConnect), false},
		{"tls", ErrTLS, false},
		{"other", errors.New("x"), false},
	} {
		if got := CredentialsRejected(tc.err); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
