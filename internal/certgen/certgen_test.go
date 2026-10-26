package certgen

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"testing"
	"time"
)

func TestGenerate(t *testing.T) {
	dir := t.TempDir()
	r, err := Generate(dir, []string{"localhost", "127.0.0.1", "proxy.lan"}, 24*time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(r.CertFile, r.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(pair.Certificate[0])
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	for _, name := range []string{"localhost", "127.0.0.1", "proxy.lan"} {
		if _, err := cert.Verify(x509.VerifyOptions{DNSName: name, Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if fi, _ := os.Stat(r.KeyFile); fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Fatalf("key file mode %v", fi.Mode())
	}
	if _, err := Generate(dir, []string{"localhost"}, time.Hour, false); err == nil {
		t.Fatal("existing files overwritten without -force")
	}
	if _, err := Generate(dir, []string{"localhost"}, time.Hour, true); err != nil {
		t.Fatal(err)
	}
}
