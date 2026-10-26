// Package certgen creates a self-signed TLS certificate for the proxy's
// client-facing listener, so a local installation needs no other tools.
package certgen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Result describes a generated certificate.
type Result struct {
	CertFile, KeyFile string
	Names             []string
	NotAfter          time.Time
	SHA256            string // certificate fingerprint, for manual verification
}

// Generate writes proxy.crt and proxy.key into dir. hosts may contain DNS
// names and IP addresses; they become subject alternative names. Existing
// files are only replaced when force is set.
func Generate(dir string, hosts []string, validFor time.Duration, force bool) (*Result, error) {
	if len(hosts) == 0 {
		return nil, errors.New("at least one host name or IP address is required")
	}
	r := &Result{CertFile: filepath.Join(dir, "proxy.crt"), KeyFile: filepath.Join(dir, "proxy.key"), Names: hosts}
	if !force {
		for _, f := range []string{r.CertFile, r.KeyFile} {
			if _, err := os.Stat(f); err == nil {
				return nil, fmt.Errorf("%s already exists (use -force to replace it)", f)
			}
		}
	}

	// RSA rather than ECDSA: accepted by every TDS client TLS stack,
	// including older Windows SChannel versions.
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hosts[0], Organization: []string{"tds-auth-proxy (self-signed)"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		// Self-signed and meant to be trusted directly by clients, which
		// some validators (e.g. Windows root store) expect to be a CA.
		IsCA: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if err := writePEM(r.KeyFile, "PRIVATE KEY", keyDER, 0o600); err != nil {
		return nil, err
	}
	if err := writePEM(r.CertFile, "CERTIFICATE", der, 0o644); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	r.SHA256 = fmt.Sprintf("%X", sum)
	r.NotAfter = tmpl.NotAfter
	return r, nil
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
