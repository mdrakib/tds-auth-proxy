#!/bin/sh
# Starts a throwaway SQL Server 2022 container with a certificate from the
# development CA, runs the Go integration tests against it, and removes it.
# Requires Docker and Go. Usage: scripts/integration-test.sh [go test flags]
set -eu
cd "$(dirname "$0")/.."
./scripts/dev-certs.sh dev/certs >/dev/null

name=tdsproxy-it-mssql-$$
port=${TDSPROXY_IT_PORT:-24433}
sa="It-$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')!"
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

docker run -d --name "$name" -e ACCEPT_EULA=Y -e "MSSQL_SA_PASSWORD=$sa" -e MSSQL_MEMORY_LIMIT_MB=1536 \
  -p "127.0.0.1:$port:1433" \
  -v "$PWD/dev/mssql/mssql.conf:/var/opt/mssql/mssql.conf:ro" \
  -v "$PWD/dev/certs/mssql.crt:/var/opt/mssql/certs/mssql.crt:ro" \
  -v "$PWD/dev/certs/mssql.key:/var/opt/mssql/certs/mssql.key:ro" \
  mcr.microsoft.com/mssql/server:2022-latest >/dev/null

printf 'waiting for SQL Server'
i=0
until docker exec "$name" /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "$sa" -C -b -Q 'SELECT 1' >/dev/null 2>&1; do
  i=$((i + 1)); [ $i -gt 90 ] && { echo; docker logs "$name" | tail -20; exit 1; }
  printf '.'; sleep 2
done
echo

TDSPROXY_IT_SA_PASSWORD="$sa" TDSPROXY_IT_SQL_ADDR="127.0.0.1:$port" TDSPROXY_IT_CA_FILE="$PWD/dev/certs/ca.crt" \
  go test -tags integration -race -count=1 "$@" ./tests/integration/
