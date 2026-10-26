package credentials

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// ErrCredentialsBlocked is returned by Guard.Acquire while a profile's
// current credentials are known to be rejected by the backend.
var ErrCredentialsBlocked = errors.New("backend login paused: these credentials were rejected by the server; waiting for a new secret")

// Guard protects upstream accounts from lockout. Once the backend rejects a
// profile's credentials, no further login is attempted with those same
// credentials until the secret changes (detected on the next connection),
// the configuration is reloaded, or an optional retry interval elapses.
//
// Credentials not yet confirmed by a successful login (after startup, a
// rotation or a rejection) are tried by one connection at a time; others
// wait for its outcome, so a wrong password costs one failed attempt rather
// than one per waiting client. Confirmed credentials allow a bounded number
// of concurrent logins, which bounds the failed attempts made when the
// password expires on the server while logins are in flight.
//
// It is safe for concurrent use.
type Guard struct {
	// OnChange, if set, is called (without locks held) when a profile
	// becomes blocked or unblocked.
	OnChange func(profile string, blocked bool)

	mu      sync.Mutex
	key     [32]byte
	entries map[string]*guardEntry
}

type guardState int

const (
	stateUnverified guardState = iota
	stateGood
	stateRejected
)

type guardEntry struct {
	gen      uint64 // bumped whenever the credentials change or state is reset
	fp       [32]byte
	state    guardState
	rejected time.Time
	inflight int
	changed  chan struct{} // closed (and replaced) on every state change
}

func NewGuard() *Guard {
	g := &Guard{entries: map[string]*guardEntry{}}
	rand.Read(g.key[:])
	return g
}

// Outcome of a backend login attempt.
type Outcome int

const (
	// Inconclusive: the attempt says nothing about the credentials
	// (network error, timeout, missing database, ...).
	Inconclusive Outcome = iota
	Accepted
	Rejected
)

// Ticket is permission for one backend login. Done must be called once.
type Ticket struct {
	g       *Guard
	profile string
	gen     uint64
	done    bool
}

// Acquire returns a Ticket for logging in with c. It waits while the
// profile's concurrent-login limit is reached: always 1 for unverified
// credentials, parallel (at least 1) once they are confirmed. retry is
// lockout_protection.retry_interval.
func (g *Guard) Acquire(ctx context.Context, profile string, c Credentials, parallel int, retry time.Duration) (*Ticket, error) {
	fp := g.fingerprint(c)
	parallel = max(parallel, 1)
	for {
		var notify func()
		g.mu.Lock()
		e := g.entries[profile]
		if e == nil {
			e = &guardEntry{fp: fp, changed: make(chan struct{})}
			g.entries[profile] = e
		}
		if e.fp != fp {
			// New secret: whatever was learned about the old one is void.
			if e.state == stateRejected {
				notify = g.notifier(profile, false)
			}
			e.reset()
			e.fp = fp
		}
		if e.state == stateRejected && retry > 0 && time.Since(e.rejected) >= retry {
			e.state = stateUnverified
		}
		if e.state == stateRejected {
			g.mu.Unlock()
			call(notify)
			return nil, fmt.Errorf("profile %q: %w", profile, ErrCredentialsBlocked)
		}
		limit := 1
		if e.state == stateGood {
			limit = parallel
		}
		if e.inflight < limit {
			e.inflight++
			t := &Ticket{g: g, profile: profile, gen: e.gen}
			g.mu.Unlock()
			call(notify)
			return t, nil
		}
		wait := e.changed
		g.mu.Unlock()
		call(notify)
		select {
		case <-wait:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Done records the login outcome. It reports whether this call blocked the
// profile. A nil Ticket is a no-op.
func (t *Ticket) Done(o Outcome) (blocked bool) {
	if t == nil || t.done {
		return false
	}
	t.done = true
	g := t.g
	g.mu.Lock()
	e := g.entries[t.profile]
	e.inflight--
	// An outcome for credentials that have since changed (or been reset)
	// says nothing about the current ones.
	if e.gen == t.gen {
		switch o {
		case Accepted:
			if e.state == stateUnverified {
				e.state = stateGood
			}
		case Rejected:
			blocked = e.state != stateRejected
			e.state = stateRejected
			e.rejected = time.Now()
		}
	}
	e.signal()
	g.mu.Unlock()
	if blocked {
		call(g.notifier(t.profile, true))
	}
	return blocked
}

// Reset forgets all rejections; the next connection per profile probes again.
func (g *Guard) Reset() {
	var unblocked []string
	g.mu.Lock()
	for name, e := range g.entries {
		if e.state == stateRejected {
			unblocked = append(unblocked, name)
		}
		e.reset()
	}
	g.mu.Unlock()
	for _, name := range unblocked {
		call(g.notifier(name, false))
	}
}

// Blocked lists the profiles currently blocked.
func (g *Guard) Blocked() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []string
	for name, e := range g.entries {
		if e.state == stateRejected {
			out = append(out, name)
		}
	}
	return out
}

func (e *guardEntry) reset() {
	e.gen++
	e.state = stateUnverified
	e.signal()
}

// signal wakes all waiters so they re-evaluate the entry.
func (e *guardEntry) signal() {
	close(e.changed)
	e.changed = make(chan struct{})
}

func (g *Guard) notifier(profile string, blocked bool) func() {
	if g.OnChange == nil {
		return nil
	}
	return func() { g.OnChange(profile, blocked) }
}

func call(f func()) {
	if f != nil {
		f()
	}
}

// fingerprint identifies the secret material of c. It is a keyed MAC with a
// per-process random key, held in memory only and never logged.
func (g *Guard) fingerprint(c Credentials) [32]byte {
	m := hmac.New(sha256.New, g.key[:])
	for _, s := range []string{c.Type, c.Domain, c.Username, c.Password, c.Realm, c.KeytabFile, c.CredCacheFile} {
		fmt.Fprintf(m, "%d:%s", len(s), s)
	}
	// Keytabs and credential caches are rotated by replacing the file.
	for _, p := range []string{c.KeytabFile, c.CredCacheFile} {
		if p == "" {
			continue
		}
		if fi, err := os.Stat(p); err == nil {
			fmt.Fprintf(m, "|%d:%d", fi.Size(), fi.ModTime().UnixNano())
		}
	}
	var fp [32]byte
	copy(fp[:], m.Sum(nil))
	return fp
}
