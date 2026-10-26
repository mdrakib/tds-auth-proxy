// Package auth verifies proxy client accounts (authentication) and decides
// which backends they may reach (authorization).
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/mdrakib/tds-auth-proxy/internal/config"
)

var (
	// ErrInvalidCredentials covers unknown users and wrong passwords.
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserDisabled       = errors.New("user disabled")
)

// Default Argon2id parameters for new hashes: the OWASP-recommended
// m=19 MiB, t=2, p=1 (about 50 ms per verification on a 2016 Xeon core).
// Existing hashes keep the parameters encoded in their PHC string.
const (
	defaultMemoryKiB = 19 * 1024
	defaultTime      = 2
	defaultThreads   = 1
	saltLen          = 16
	keyLen           = 32
	maxMemoryKiB     = 1024 * 1024
)

// Hash is a parsed Argon2id PHC string.
type Hash struct {
	memory  uint32
	time    uint32
	threads uint8
	salt    []byte
	key     []byte
}

// HashPassword returns a PHC-formatted Argon2id hash of password using the
// default cost.
func HashPassword(password string) (string, error) {
	return HashPasswordParams(password, defaultMemoryKiB, defaultTime, defaultThreads)
}

// HashPasswordParams hashes with explicit Argon2id parameters.
func HashPasswordParams(password string, memoryKiB, time uint32, threads uint8) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, time, memoryKiB, threads, keyLen)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memoryKiB, time, threads, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

// ParseHash parses "$argon2id$v=19$m=..,t=..,p=..$salt$key".
func ParseHash(s string) (*Hash, error) {
	parts := strings.Split(strings.TrimSpace(s), "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return nil, errors.New("password hash is not an argon2id PHC string")
	}
	if parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return nil, errors.New("unsupported argon2 version")
	}
	h := &Hash{}
	var m, t, p uint64
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return nil, errors.New("malformed argon2 parameters")
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return nil, errors.New("malformed argon2 parameters")
		}
		switch k {
		case "m":
			m = n
		case "t":
			t = n
		case "p":
			p = n
		default:
			return nil, errors.New("unknown argon2 parameter")
		}
	}
	if m < 8 || m > maxMemoryKiB || t < 1 || t > 100 || p < 1 || p > 255 {
		return nil, errors.New("argon2 parameters out of range")
	}
	h.memory, h.time, h.threads = uint32(m), uint32(t), uint8(p)
	var err error
	if h.salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil || len(h.salt) < 8 {
		return nil, errors.New("malformed argon2 salt")
	}
	if h.key, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil || len(h.key) < 16 {
		return nil, errors.New("malformed argon2 key")
	}
	return h, nil
}

// Verify compares password against the hash in constant time.
func (h *Hash) Verify(password string) bool {
	key := argon2.IDKey([]byte(password), h.salt, h.time, h.memory, h.threads, uint32(len(h.key)))
	return subtle.ConstantTimeCompare(key, h.key) == 1
}

// User is an authenticated proxy account.
type User struct {
	Name            string
	enabled         bool
	hash            *Hash
	allowedBackends map[string]bool // nil means all
}

// MayAccess reports whether the user is authorized for backend.
func (u *User) MayAccess(backend string) bool {
	return u.allowedBackends == nil || u.allowedBackends["*"] || u.allowedBackends[backend]
}

// Authenticator verifies client credentials. It is immutable; a config
// reload builds a new one.
type Authenticator struct {
	users map[string]*User // keyed by lower-cased username
	sem   chan struct{}
	dummy *Hash
}

// NewAuthenticator resolves every user's hash from config, environment or
// file. Usernames are matched case-insensitively, like SQL Server logins
// under the default collation.
func NewAuthenticator(users []config.User, maxConcurrent int) (*Authenticator, error) {
	a := &Authenticator{users: map[string]*User{}, sem: make(chan struct{}, max(1, maxConcurrent))}
	for _, cu := range users {
		raw := cu.PasswordHash
		switch {
		case cu.PasswordHashEnv != "":
			v, ok := os.LookupEnv(cu.PasswordHashEnv)
			if !ok {
				return nil, fmt.Errorf("user %q: environment variable %s is not set", cu.Username, cu.PasswordHashEnv)
			}
			raw = v
		case cu.PasswordHashFile != "":
			b, err := os.ReadFile(cu.PasswordHashFile)
			if err != nil {
				return nil, fmt.Errorf("user %q: reading password hash file: %w", cu.Username, err)
			}
			raw = string(b)
		}
		h, err := ParseHash(raw)
		if err != nil {
			return nil, fmt.Errorf("user %q: %w", cu.Username, err)
		}
		u := &User{Name: cu.Username, enabled: cu.IsEnabled(), hash: h}
		if len(cu.AllowedBackends) > 0 {
			u.allowedBackends = map[string]bool{}
			for _, b := range cu.AllowedBackends {
				u.allowedBackends[b] = true
			}
		}
		a.users[strings.ToLower(cu.Username)] = u
	}
	// Unknown users are verified against a dummy hash with the most expensive
	// configured parameters, so rejecting them is never measurably faster
	// than rejecting a wrong password (no username enumeration by timing).
	m, t, p := uint32(defaultMemoryKiB), uint32(defaultTime), uint8(defaultThreads)
	for _, u := range a.users {
		if uint64(u.hash.memory)*uint64(u.hash.time) > uint64(m)*uint64(t) {
			m, t, p = u.hash.memory, u.hash.time, u.hash.threads
		}
	}
	dummy, err := HashPasswordParams("dummy-password-for-timing", m, t, p)
	if err != nil {
		return nil, err
	}
	a.dummy, _ = ParseHash(dummy)
	return a, nil
}

// Authenticate verifies username and password. Unknown users, wrong
// passwords and disabled accounts all cost one hash computation.
func (a *Authenticator) Authenticate(ctx context.Context, username, password string) (*User, error) {
	select {
	case a.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-a.sem }()

	u, ok := a.users[strings.ToLower(username)]
	if !ok {
		a.dummy.Verify(password)
		return nil, ErrInvalidCredentials
	}
	if !u.hash.Verify(password) {
		return nil, ErrInvalidCredentials
	}
	if !u.enabled {
		return nil, ErrUserDisabled
	}
	return u, nil
}

// UserCount returns the number of configured users.
func (a *Authenticator) UserCount() int { return len(a.users) }
