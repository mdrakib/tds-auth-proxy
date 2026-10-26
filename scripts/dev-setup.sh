#!/bin/sh
# Prepares the DEVELOPMENT-ONLY local stack used by docker-compose.yml:
#   dev/certs/    throwaway CA + certificates for the proxy and SQL Server
#   dev/secrets/  backend SQL password and the developer1 client password hash
#   .env          SQL Server sa password for the test container
# Re-running keeps existing files. Never use any of this in production.
set -eu
cd "$(dirname "$0")/.."
./scripts/dev-certs.sh dev/certs

mkdir -p dev/secrets
rand() { od -An -N18 -tx1 /dev/urandom | tr -d ' \n'; }

if [ ! -f .env ]; then
  printf 'MSSQL_SA_PASSWORD=Sa-%s!\n' "$(rand)" > .env
  chmod 600 .env
fi
if [ ! -f dev/secrets/mssql-password ]; then
  printf 'Svc-%s!' "$(rand)" > dev/secrets/mssql-password
fi
if [ ! -f dev/secrets/developer1.hash ]; then
  pw="Dev-$(rand)"
  # Hash with the proxy itself (via Docker, so no local Go toolchain is needed).
  hash=$(printf '%s\n' "$pw" | docker run --rm -i "$(docker build -q .)" hash-password)
  printf '%s\n' "$hash" > dev/secrets/developer1.hash
  printf '%s\n' "$pw" > dev/secrets/developer1.password.txt
  echo "developer1 password: $pw   (also in dev/secrets/developer1.password.txt)"
fi
# The proxy runs as uid 65532 and SQL Server as uid 10001; dev files only.
chmod 644 dev/secrets/* dev/certs/*.key
echo "dev environment ready: docker compose up -d --build"
