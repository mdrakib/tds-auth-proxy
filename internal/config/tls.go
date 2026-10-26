package config

import (
	"crypto/tls"
	"fmt"
)

// TLSVersion maps "1.2"/"1.3" to crypto/tls constants.
func TLSVersion(s string) (uint16, error) {
	switch s {
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	}
	return 0, fmt.Errorf("unsupported TLS version %q", s)
}
