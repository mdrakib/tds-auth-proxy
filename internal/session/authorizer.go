package session

import (
	"context"
	"errors"
	"fmt"

	"github.com/mdrakib/tds-auth-proxy/internal/auth"
	"github.com/mdrakib/tds-auth-proxy/internal/backend"
	"github.com/mdrakib/tds-auth-proxy/internal/credentials"
	"github.com/mdrakib/tds-auth-proxy/internal/monitoring"
)

// ConfigAuthorizer is the standalone proxy's Authorizer: users, grants,
// backends and credential profiles come from the configuration file.
type ConfigAuthorizer struct {
	State   func() *State
	Metrics *monitoring.Metrics
	// Guard pauses logins with rejected backend credentials; nil disables it.
	Guard *credentials.Guard
}

func (a *ConfigAuthorizer) Authorize(ctx context.Context, l *ClientLogin) (*Grant, error) {
	// Authenticate and authorize against the configuration current now, not
	// the one at accept time: a client stalling its handshake must not
	// benefit from users, grants or profiles a reload has since removed.
	st := a.State()

	u, err := st.Auth.Authenticate(ctx, l.User, l.Password)
	if err != nil && ctx.Err() != nil {
		return nil, fail("handshake_timeout", 0, "", err)
	}
	if err != nil {
		outcome := "invalid_credentials"
		if errors.Is(err, auth.ErrUserDisabled) {
			outcome = "disabled"
		}
		a.Metrics.AuthResult(outcome)
		return nil, fail("client_auth_"+outcome, errLoginFailed, loginFailedMsg(l.User), err)
	}

	lis := st.Listeners[l.Listener]
	b, ok := st.Backends[lis.Backend]
	if !ok {
		return nil, fail("config", errLoginFailed, loginFailedMsg(l.User), fmt.Errorf("listener backend %q not configured", lis.Backend))
	}
	if !u.MayAccess(lis.Backend) {
		a.Metrics.AuthResult("unauthorized")
		return nil, fail("client_unauthorized", errLoginFailed, loginFailedMsg(l.User),
			fmt.Errorf("user %q is not authorized for backend %q", u.Name, lis.Backend))
	}
	a.Metrics.AuthResult("success")

	creds, err := st.Creds.GetCredentials(ctx, b.Profile)
	if err != nil {
		a.Metrics.BackendFailure(b.Name, "credentials")
		return nil, fail("backend_credentials", errLoginFailed, backendFailedMsg(b.Name), err)
	}
	var ticket *credentials.Ticket
	if lp := st.Config.Server.LockoutProtection; a.Guard != nil && lp.IsEnabled() {
		ticket, err = a.Guard.Acquire(ctx, b.Profile, creds, lp.MaxParallelLogins, lp.RetryInterval)
		if err != nil {
			if ctx.Err() != nil {
				return nil, fail("handshake_timeout", 0, "", fmt.Errorf("waiting for backend credential check: %w", err))
			}
			a.Metrics.BackendFailure(b.Name, "credentials_blocked")
			return nil, fail("backend_credentials_blocked", errLoginFailed,
				fmt.Sprintf("Login failed: the proxy's credentials for backend server '%s' were rejected and it is waiting for a new password. Contact the proxy administrator.", b.Name),
				fmt.Errorf("backend %q, backend user %q: %w", b.Name, creds.Identity(), err))
		}
	}
	log := l.Log
	return &Grant{
		User:   u.Name,
		Target: b.Target,
		Creds:  creds,
		Done: func(err error) {
			outcome := credentials.Accepted
			if err != nil {
				outcome = credentials.Inconclusive
				if backend.CredentialsRejected(err) {
					outcome = credentials.Rejected
				}
			}
			if ticket.Done(outcome) && log != nil {
				log.Error("backend rejected the proxy's credentials; new logins with them are paused until the secret changes",
					"event", "backend_credentials_blocked",
					"backend", b.Name, "profile", b.Profile, "backend_user", creds.Identity(), "error", err.Error())
			}
		},
	}, nil
}

// Settings returns the session settings of s.
func (s *State) Settings() Settings {
	srv := s.Config.Server
	return Settings{
		ClientTLS:        s.ClientTLS,
		HandshakeTimeout: srv.HandshakeTimeout,
		IdleTimeout:      srv.IdleTimeout,
		AuthFailureDelay: srv.AuthFailureDelay,
	}
}
