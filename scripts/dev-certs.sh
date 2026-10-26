#!/bin/sh
# Generates a DEVELOPMENT-ONLY CA plus certificates for the proxy and the test
# SQL Server. Never use these in production.
set -eu
out=${1:-dev/certs}
mkdir -p "$out"
cd "$out"
[ -f ca.crt ] && { echo "certificates already exist in $out"; exit 0; }

openssl req -x509 -newkey rsa:3072 -nodes -days 825 -sha256 \
  -subj "/CN=tds-proxy DEV CA - not for production" \
  -keyout ca.key -out ca.crt 2>/dev/null

issue() { # name, SANs
  openssl req -newkey rsa:2048 -nodes -sha256 -subj "/CN=$1" \
    -keyout "$1.key" -out "$1.csr" 2>/dev/null
  printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n' "$2" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days 825 -sha256 -extfile "$1.ext" -out "$1.crt" 2>/dev/null
  rm -f "$1.csr" "$1.ext"
}
issue proxy "DNS:localhost,DNS:tds-proxy,IP:127.0.0.1"
issue mssql "DNS:mssql,DNS:localhost,IP:127.0.0.1"
# Keys must be readable by the non-root container users (proxy: 65532,
# SQL Server: 10001). Acceptable for throwaway dev keys only.
chmod 644 proxy.key mssql.key
echo "development certificates written to $out"
