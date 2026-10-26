#!/bin/sh
# Runs ProxyJdbcTest in a Temurin container.
# usage: run.sh <proxy port> <user> <password> [expect-login-failure]
# Trusts dev/certs/ca.crt (development CA) for the proxy's certificate.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
ver=${MSSQL_JDBC_VERSION:-13.6.1.jre11}
jar="$here/mssql-jdbc-$ver.jar"
[ -f "$jar" ] || curl -fsSL -o "$jar" "https://repo1.maven.org/maven2/com/microsoft/sqlserver/mssql-jdbc/$ver/mssql-jdbc-$ver.jar"
url="jdbc:sqlserver://localhost:$1;user=$2;password=$3;encrypt=true;trustServerCertificate=false;trustStore=/tmp/trust.p12;trustStorePassword=changeit;loginTimeout=30"
docker run --rm --network host -v "$here:/w:ro" -v "$root/dev/certs/ca.crt:/ca.crt:ro" eclipse-temurin:21-jdk sh -c \
  "keytool -importcert -noprompt -alias devca -file /ca.crt -keystore /tmp/trust.p12 -storetype PKCS12 -storepass changeit >/dev/null 2>&1 &&
   java -cp /w/$(basename "$jar") /w/ProxyJdbcTest.java '$url' ${4:-}"
