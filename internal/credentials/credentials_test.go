package credentials

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mdrakib/tds-auth-proxy/internal/config"
)

func writeAtomic(t *testing.T, path, v string) {
	t.Helper()
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(v), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func TestFileRotation(t *testing.T) {
	dir := t.TempDir()
	pw := filepath.Join(dir, "pw")
	writeAtomic(t, pw, "first\n")
	s := NewStore(map[string]config.CredentialProfile{
		"shared": {Type: config.CredNTLM, Domain: "CORP", Username: "svc", PasswordFile: pw},
	})
	ctx := context.Background()
	c, err := s.GetCredentials(ctx, "shared")
	if err != nil || c.Password != "first" || c.Identity() != `CORP\svc` || !c.ChannelBinding {
		t.Fatalf("%v %v", c, err)
	}
	writeAtomic(t, pw, "second")
	if c, _ := s.GetCredentials(ctx, "shared"); c.Password != "second" {
		t.Fatalf("rotation not picked up: %q", c.Password)
	}
	// In-place rewrite (same inode, different size) is also detected.
	os.WriteFile(pw, []byte("third-longer"), 0o600)
	if c, _ := s.GetCredentials(ctx, "shared"); c.Password != "third-longer" {
		t.Fatalf("in-place change not picked up: %q", c.Password)
	}
	os.Remove(pw)
	if _, err := s.GetCredentials(ctx, "shared"); err == nil {
		t.Fatal("missing file must fail")
	}
}

func TestSecretFileValidation(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	os.WriteFile(empty, []byte("\n"), 0o600)
	big := filepath.Join(dir, "big")
	os.WriteFile(big, bytes.Repeat([]byte("x"), maxSecretSize+1), 0o600)
	f := NewFileSecrets()
	for _, p := range []string{empty, big} {
		if _, err := f.Get(p); err == nil {
			t.Errorf("%s accepted", p)
		}
	}
	crlf := filepath.Join(dir, "crlf")
	os.WriteFile(crlf, []byte("pa ss\r\n"), 0o600)
	if v, _ := f.Get(crlf); v != "pa ss" {
		t.Fatalf("got %q", v)
	}
}

func TestEnvAndProfiles(t *testing.T) {
	t.Setenv("TEST_BACKEND_PW", "from-env")
	s := NewStore(map[string]config.CredentialProfile{
		"env":     {Type: config.CredSQL, Username: "u", PasswordEnv: "TEST_BACKEND_PW"},
		"missing": {Type: config.CredSQL, Username: "u", PasswordEnv: "TEST_UNSET_XYZ"},
	})
	if c, err := s.GetCredentials(context.Background(), "env"); err != nil || c.Password != "from-env" {
		t.Fatal(c, err)
	}
	if _, err := s.GetCredentials(context.Background(), "missing"); err == nil {
		t.Fatal("unset env accepted")
	}
	if _, err := s.GetCredentials(context.Background(), "nope"); !errors.Is(err, ErrUnknownProfile) {
		t.Fatal(err)
	}
	s.SetProfiles(map[string]config.CredentialProfile{"new": {Type: config.CredSQL, Username: "n", PasswordEnv: "TEST_BACKEND_PW"}})
	if _, err := s.GetCredentials(context.Background(), "env"); err == nil {
		t.Fatal("old profile still present after SetProfiles")
	}
}

func TestPasswordsNeverFormatted(t *testing.T) {
	c := Credentials{Type: "sql", Username: "u", Password: "super-secret"}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "creds", c)
	for _, s := range []string{fmt.Sprint(c), fmt.Sprintf("%v %+v %s", c, c, c), buf.String()} {
		if strings.Contains(s, "super-secret") {
			t.Fatalf("password leaked: %s", s)
		}
	}
}

func TestConcurrentAccessDuringRotation(t *testing.T) {
	dir := t.TempDir()
	pw := filepath.Join(dir, "pw")
	writeAtomic(t, pw, "v0")
	s := NewStore(map[string]config.CredentialProfile{"p": {Type: config.CredSQL, Username: "u", PasswordFile: pw}})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				c, err := s.GetCredentials(context.Background(), "p")
				if err != nil || !strings.HasPrefix(c.Password, "v") {
					t.Errorf("got %q %v", c.Password, err)
					return
				}
			}
		}()
	}
	for i := 1; i < 50; i++ {
		writeAtomic(t, pw, fmt.Sprintf("v%d", i))
	}
	wg.Wait()
}
