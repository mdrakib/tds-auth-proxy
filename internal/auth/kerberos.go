package auth

import (
	"fmt"

	"github.com/microsoft/go-mssqldb/integratedauth/krb5"
	"github.com/microsoft/go-mssqldb/msdsn"

	"github.com/mdrakib/tds-auth-proxy/internal/credentials"
)

// newKerberos uses go-mssqldb's pure-Go Kerberos/SPNEGO implementation
// (gokrb5). It needs a krb5.conf that can locate the KDC; credentials come
// from username+password, a keytab or a credential cache.
func newKerberos(c credentials.Credentials, t Target) (Upstream, error) {
	spn := c.SPN
	if spn == "" {
		spn = fmt.Sprintf("MSSQLSvc/%s:%d", t.Host, t.Port)
	}
	params := map[string]string{}
	for k, v := range map[string]string{
		"krb5-configfile":    c.Krb5ConfigFile,
		"krb5-keytabfile":    c.KeytabFile,
		"krb5-credcachefile": c.CredCacheFile,
		"krb5-realm":         c.Realm,
	} {
		if v != "" {
			params[k] = v
		}
	}
	// A keytab login must not also be offered a password.
	password := c.Password
	if c.KeytabFile != "" {
		password = ""
	}
	a, err := krb5.AuthProviderFunc.GetIntegratedAuthenticator(msdsn.Config{
		User:       c.Username,
		Password:   password,
		ServerSPN:  spn,
		Parameters: params,
	})
	if err != nil {
		return nil, err
	}
	return &sspiUpstream{a: a}, nil
}
