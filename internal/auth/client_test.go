package auth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mdrakib/tds-auth-proxy/internal/config"
)

func cheapHash(t *testing.T, pw string) string {
	h, err := HashPasswordParams(pw, 1024, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestHashAndVerify(t *testing.T) {
	s, err := HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("unexpected PHC string %q", s)
	}
	h, err := ParseHash(s)
	if err != nil {
		t.Fatal(err)
	}
	if !h.Verify("correct horse") || h.Verify("correct horsE") || h.Verify("") {
		t.Fatal("verification wrong")
	}
	s2, _ := HashPassword("correct horse")
	if s == s2 {
		t.Fatal("hashes must be salted")
	}
}

func TestParseHashRejects(t *testing.T) {
	good := cheapHash(t, "x")
	for _, s := range []string{
		"", "plaintext", "$argon2i$v=19$m=1024,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		strings.Replace(good, "v=19", "v=16", 1),
		strings.Replace(good, "m=1024", "m=99999999", 1), // memory bomb
		strings.Replace(good, "t=1", "t=0", 1),
		strings.Replace(good, "m=1024", "x=1024", 1),
		good + "$extra",
	} {
		if _, err := ParseHash(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestAuthenticator(t *testing.T) {
	f := false
	a, err := NewAuthenticator([]config.User{
		{Username: "Alice", PasswordHash: cheapHash(t, "alice-pw")},
		{Username: "bob", PasswordHash: cheapHash(t, "bob-pw"), Enabled: &f},
		{Username: "carol", PasswordHash: cheapHash(t, "carol-pw"), AllowedBackends: []string{"sql-a"}},
	}, 2)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	u, err := a.Authenticate(ctx, "alice", "alice-pw")
	if err != nil || u.Name != "Alice" {
		t.Fatalf("case-insensitive login failed: %v", err)
	}
	if !u.MayAccess("anything") {
		t.Fatal("users without allowed_backends may access all backends")
	}
	if _, err := a.Authenticate(ctx, "alice", "ALICE-PW"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("passwords are case-sensitive")
	}
	if _, err := a.Authenticate(ctx, "mallory", "alice-pw"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("unknown user")
	}
	if _, err := a.Authenticate(ctx, "bob", "bob-pw"); !errors.Is(err, ErrUserDisabled) {
		t.Fatal("disabled user")
	}
	if _, err := a.Authenticate(ctx, "bob", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("disabled user with wrong password must look like bad credentials")
	}
	c, _ := a.Authenticate(ctx, "carol", "carol-pw")
	if !c.MayAccess("sql-a") || c.MayAccess("sql-b") {
		t.Fatal("authorization")
	}
}

func TestAuthenticatorHashSources(t *testing.T) {
	h := cheapHash(t, "pw-from-env")
	t.Setenv("TEST_USER_HASH", h)
	dir := t.TempDir()
	path := dir + "/hash"
	if err := writeFile(path, h+"\n"); err != nil {
		t.Fatal(err)
	}
	a, err := NewAuthenticator([]config.User{
		{Username: "env", PasswordHashEnv: "TEST_USER_HASH"},
		{Username: "file", PasswordHashFile: path},
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"env", "file"} {
		if _, err := a.Authenticate(context.Background(), u, "pw-from-env"); err != nil {
			t.Fatalf("%s: %v", u, err)
		}
	}
	if _, err := NewAuthenticator([]config.User{{Username: "x", PasswordHashEnv: "TEST_UNSET_VAR_XYZ"}}, 1); err == nil {
		t.Fatal("missing env var accepted")
	}
}

func TestAuthenticatorConcurrencyLimit(t *testing.T) {
	a, _ := NewAuthenticator([]config.User{{Username: "u", PasswordHash: cheapHash(t, "pw")}}, 1)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := a.Authenticate(context.Background(), "u", "pw"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	// A saturated limiter honours context cancellation.
	a.sem <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := a.Authenticate(ctx, "u", "pw"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}

func BenchmarkVerify(b *testing.B) {
	for _, p := range []struct {
		name    string
		m, t    uint32
		threads uint8
	}{{"m64MiB-t2-p2", 64 * 1024, 2, 2}, {"m19MiB-t2-p1", 19 * 1024, 2, 1}} {
		s, _ := HashPasswordParams("benchmark-password", p.m, p.t, p.threads)
		h, _ := ParseHash(s)
		b.Run(p.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				h.Verify("benchmark-password")
			}
		})
	}
}
