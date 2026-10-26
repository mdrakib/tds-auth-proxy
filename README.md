# tds-auth-proxy

An authenticating TDS proxy for Microsoft SQL Server, written in Go.

Clients (SSMS, DBeaver, sqlcmd, JDBC, .NET, …) log in to the proxy with
**proxy accounts** defined centrally in the proxy. The proxy then logs in to
the real SQL Server with **separately managed backend credentials** (SQL
authentication, NTLM or Kerberos) and relays the session transparently. Clients
never see the backend password, and when it changes you update it in one place.

```text
 client ──TLS session A── proxy ──TLS session B── SQL Server
  LOGIN7(dev1 / proxy pw)   │  LOGIN7 or NTLM/Kerberos (svc account / backend pw)
                            └─ after both logins: TDS packets relayed unchanged
```

- One dedicated backend session per client session; no pooling, no SQL parsing.
- The backend session that authenticated is the one that carries the traffic.
- The client receives the backend's **real** login response (LOGINACK,
  ENVCHANGEs, FEATUREEXTACK); the proxy never fabricates a successful login.
- One listening port per backend; many backends can share one credential profile.
- Single static binary (~12 MB distroless image), no database or external services.

Status: milestones 1–3 implemented and tested against SQL Server 2022; NTLM and
Kerberos backend authentication implemented (milestone 4) but **not yet tested
against a real Active Directory domain** — see [Compatibility](#tested-compatibility).

## Download and run (no Docker)

Pre-built executables for Windows, macOS and Linux (amd64/arm64) are attached to
each [GitHub Release](https://github.com/mdrakib/tds-auth-proxy/releases), with
`SHA256SUMS.txt`. Each archive holds the single `tds-proxy` executable, this
README and `config.example.yaml`.

```powershell
# Windows (PowerShell), after unzipping tds-proxy_<version>_windows_amd64.zip
.\tds-proxy.exe version
.\tds-proxy.exe gen-cert -out .\certs                   # self-signed proxy.crt / proxy.key
'MyProxyPassword' | .\tds-proxy.exe hash-password      # -> paste into config or a hash file
.\tds-proxy.exe check-config -config .\config.yaml
.\tds-proxy.exe run -config .\config.yaml               # Ctrl+C stops gracefully
```

```sh
# macOS / Linux
tar -xzf tds-proxy_<version>_linux_amd64.tar.gz && cd tds-proxy_<version>_linux_amd64
./tds-proxy run -config ./config.yaml
```

`gen-cert` covers `localhost`, `127.0.0.1` and the computer name by default
(`-host a,b,c` to choose). Clients must trust the generated `proxy.crt`: on
Windows import it into *Trusted Root Certification Authorities* (current user
is enough for SSMS/.NET), for DBeaver/JDBC import it into the driver's trust
store, or for a quick local test use `TrustServerCertificate=True`.

Always pass `-config` (the default path is `/etc/tds-proxy/config.yaml`). On
Windows there is no SIGHUP: reload with
`Invoke-RestMethod -Method Post http://127.0.0.1:8080/-/reload`. Rotating a
password file works the same everywhere: write a new file and rename/move it
over the old one. On macOS, a downloaded binary may need
`xattr -d com.apple.quarantine tds-proxy` before first run.

Releases are built by `.github/workflows/release.yml` when a tag is pushed:

```sh
git tag v0.1.0 && git push origin v0.1.0      # tags with a dash (v0.2.0-rc1) become pre-releases
```

CI (`.github/workflows/ci.yml`) runs vet, race tests, short fuzzing and the real
SQL Server integration suite on every push to `main` and on pull requests.

## Quick start (local development stack)

Requires Docker. This starts SQL Server 2022 and the proxy with throwaway
certificates and credentials (development only).

```sh
./scripts/dev-setup.sh          # dev CA + certs, backend secret, developer1 password (printed)
docker compose up -d --build
```

Connect through the proxy on `127.0.0.1:14331` as `developer1` with the printed
password. The proxy's certificate is signed by `dev/certs/ca.crt`; either trust
that CA or, for this dev stack only, use `TrustServerCertificate=True`.

```sh
sqlcmd -S tcp:localhost,14331 -U developer1 -P '<printed password>' -N -C -Q "SELECT SUSER_SNAME()"
# -> proxy_svc   (the backend identity; the client never knew its password)
```

## Connecting clients

Use ordinary SQL Server authentication with the proxy account. Encryption is
always on; validate the proxy certificate in production.

| Client | Settings |
|---|---|
| .NET (Microsoft.Data.SqlClient) | `Server=proxy.example.com,14331;User Id=developer1;Password=…;Encrypt=True;TrustServerCertificate=False` |
| JDBC / DBeaver | `jdbc:sqlserver://proxy.example.com:14331;encrypt=true;trustServerCertificate=false` + user/password. DBeaver: SQL Server driver, *Authentication: SQL Server Authentication*, *Trust Server Certificate* off, import the proxy CA into the driver's trust store if it is private. |
| sqlcmd (ODBC 18) | `sqlcmd -S tcp:proxy.example.com,14331 -U developer1 -P … -N` |
| SSMS | Server `proxy.example.com,14331`, *SQL Server Authentication*, *Encryption: Mandatory*. |

Not accepted: Windows/integrated authentication **to the proxy**, Microsoft
Entra authentication, password change at login, `Encrypt=Strict` (TDS 8.0),
AttachDBFilename/user instances. Each is rejected with a clear login error.

## Production deployment

See [`deploy/docker-compose.yml`](deploy/docker-compose.yml) and
[`config.example.yaml`](config.example.yaml).

```text
deploy/
├── docker-compose.yml
├── config.yaml                 # from config.example.yaml
├── certs/proxy.crt, proxy.key  # certificate clients will validate (+ corp CA)
└── secrets/
    ├── mssql-password          # shared AD password  (profile shared-ad)
    ├── reporting-password
    └── developer1.hash         # Argon2id hash, not a password
```

1. Create client password hashes:
   `printf '%s\n' 'their-password' | docker run --rm -i tds-auth-proxy hash-password`
   (or `tds-proxy hash-password`). Store the `$argon2id$…` string in a file
   referenced by `password_hash_file`, inline as `password_hash`, or in an
   environment variable named by `password_hash_env` (escape `$` as `$$` in
   compose files).
2. Write backend passwords to files under `secrets/`.
3. `tds-proxy check-config -config config.yaml` validates config, secrets and certificates.
4. `docker compose up -d --build`.

Security defaults: listeners without a host bind `127.0.0.1`; inside a container
bind `0.0.0.0` and publish ports on a private interface. Expose the proxy only on
a private network or VPN (e.g. WireGuard) and use `allowed_cidrs`. The container
runs as non-root with a read-only root filesystem and no capabilities.

## Central credential rotation

Credential profiles are resolved **per new backend connection**. For
`password_file` the proxy `stat`s the file on every new connection and re-reads it
only when it changed, so there is no polling and no restart:

```sh
# The AD password changed. Update it once:
printf '%s' 'New-AD-Password' > secrets/.mssql-password.tmp
mv secrets/.mssql-password.tmp secrets/mssql-password     # atomic rename
```

Every listener whose backend uses that profile picks it up on the next connection.
Existing sessions keep running on the connection they already authenticated.

Important details:

- **Mount the secrets directory, not individual files**, into the container.
  A single-file bind mount pins the original inode, so a renamed-over file on the
  host never becomes visible inside the container.
- **Environment variables cannot be rotated live.** A process's environment is
  fixed at start; changing `.env` or a compose file does nothing until the
  container is recreated (`docker compose up -d`). Use `password_file` for rotation.
- A wrong new password gives clients `Login failed: the proxy could not log in to
  backend server '<name>'` and the log shows the backend's own error
  (`event=login_failed category=backend_login error="backend rejected login: error 18456 …"`).
  Lockout protection (below) then stops further attempts with that password.
- SQL Server itself rejects `sp_reset_connection` on a pooled session after that
  **SQL login's** password changed (verified directly against SQL Server 2022,
  without the proxy). Client connection pools therefore discard such sessions on
  reuse and open new ones, which use the new password. Sessions that are not
  reset are unaffected.

### Lockout protection

When a backend password expires or is changed before the proxy's secret is
updated, every new client connection would otherwise try the stale password and
could lock the account. `server.lockout_protection` (on by default) prevents this:

- When the backend (or the Kerberos KDC) **rejects the credentials**, the proxy
  stops logging in with them. New clients immediately get
  `Login failed: the proxy's credentials for backend server '<name>' were rejected
  and it is waiting for a new password` without the backend being contacted.
  Sessions already open keep running.
- Logins **resume automatically** as soon as the secret changes: the next client
  connection notices the new file content (or keytab) and tries it.
- New or not-yet-confirmed credentials (at startup, after a rotation or a reload)
  are tried by **one connection at a time**; other clients wait for that result. A
  wrong new password therefore costs exactly one failed attempt.
- Once confirmed, at most `max_parallel_logins` (default 2) backend logins per
  profile run at the same time. That is the worst-case number of failed attempts
  when the password expires while clients are connecting. Set `1` for the
  strictest guarantee; raise it if many clients connect at once and backend
  logins are slow.
- Counted as rejection: SQL Server errors 18456, 18452, 18470, 18486, 18487
  (password expired), 18488 (must change) and Kerberos `KDC_ERR_PREAUTH_FAILED`,
  `KDC_ERR_KEY_EXPIRED`, `KDC_ERR_CLIENT_REVOKED`, `KDC_ERR_C_PRINCIPAL_UNKNOWN`.
  Not counted: network/TLS errors, timeouts, and a client requesting a database
  it cannot open (4060/4064).
- To retry the **same** secret (for example after an administrator unlocked the
  account), reload the configuration (`SIGHUP` or `POST /-/reload`); this allows
  one new attempt. `retry_interval` makes the proxy do this by itself, one trial
  login per interval.
- Watch for `event=backend_credentials_blocked` / `backend_credentials_unblocked`
  in the log and the `tdsproxy_credentials_blocked{profile="…"}` metric (1 while
  paused).

With scheduled rotation (for example every 6 hours), update the secret file in the
same step that changes the password. If the file is written **before** the
password is changed on the server, the new password is rejected briefly and the
profile stays paused until the next change; reload once, or set
`retry_interval` (for example `10m`), to recover automatically.

Configuration changes (users, profiles, backends, allowlists, the proxy TLS
certificate, log level) are applied with `SIGHUP`
(`docker compose kill -s HUP tds-proxy`) or `POST http://127.0.0.1:8080/-/reload`.
An invalid new configuration is rejected and the running one stays active.
Listener addresses, `max_connections` and `admin.listen` require a restart.

## Authentication and authorization

- Client passwords are verified against Argon2id hashes in constant time;
  unknown users cost the same hash computation as known ones. Default parameters
  for new hashes: m=19 MiB, t=2, p=1 (OWASP); `max_concurrent_hashes` bounds memory.
- Usernames are case-insensitive; passwords are case-sensitive.
- Disabled, unknown, wrong-password and unauthorized logins all receive the same
  generic `Login failed for user '<name>'.` (error 18456) after
  `auth_failure_delay`; the reason is logged. The proxy does **not** contact the
  backend until the client is authenticated and authorized.
- `allowed_backends` restricts a user to named backends (omitted = all).
- The backend sees the shared upstream identity. The proxy's audit log maps each
  session: `client_user`, `backend`, `backend_user`, `backend_spid`
  (the SQL Server `session_id`), client IP/host/application, timings, bytes.

## Backend authentication

| `type` | Mechanism | Notes |
|---|---|---|
| `sql` | SQL Server login in LOGIN7 | Tested against SQL Server 2022. |
| `ntlm` | NTLMv2 over TDS SSPI (fIntSecurity + SSPI 0x11 round trip) | Pure Go (go-mssqldb's public `integratedauth/ntlm`), works in Linux containers. Sends TLS channel bindings (Extended Protection) by default. `domain` + `username`, never `DOMAIN\user` as a SQL login. |
| `kerberos` | SPNEGO/Kerberos over TDS SSPI | Pure Go (go-mssqldb's `integratedauth/krb5` / gokrb5). Needs `krb5_config` (or `/etc/krb5.conf`), `realm`, and password, `keytab_file` or `credential_cache_file`. SPN defaults to `MSSQLSvc/<host>:<port>`. |

Backend TLS is mandatory (servers that refuse encryption are rejected) and the
certificate is verified against the system roots or `backend_ca_file`/`ca_file`;
`tls_server_name` overrides the expected name. `verify_certificate: false` exists
for testing only.

## Observability

Structured JSON logs (`log/slog`) with `event` = `connection_established`,
`connection_closed` (reason, duration, bytes), `login_failed` (category, error),
`client_authenticated`, `config_reloaded`, `connection_rejected`, … SQL text and
passwords are never logged.

Admin HTTP server (`admin.listen`, loopback by default, no authentication):

- `GET /healthz` – process alive. `GET /readyz` – listeners up and not shutting down.
- `GET /metrics` – Prometheus text format: active sessions, connections,
  rejections, client auth outcomes, backend failures by backend/category,
  credential profiles paused by lockout protection, bytes, handshake and session
  duration histograms. No usernames or secrets.
- `POST /-/reload` – reload configuration.

The container health check runs `tds-proxy healthcheck`.

## Tested compatibility

All runs: proxy and SQL Server 2022 CU25 (16.0.4255.1, Linux container) with
certificates from a test CA, both TLS sessions validated, client → proxy
`Encrypt=True`. "Suite" = SELECT 1/@@VERSION/DB_NAME()/SUSER_SNAME(), temp
tables, transactions, parameterized queries (RPC), stored procedures with output
parameters, multiple result sets, large results, server errors, cancellation,
concurrency (see `tests/`).

| Client | Version | Result |
|---|---|---|
| Microsoft.Data.SqlClient | 6.1.2 on .NET 8.0.8, Linux | Suite 20/20, plus MARS, connection pool reset (`sp_reset_connection`), 2 MB parameter, command timeout. `Encrypt=False` is upgraded to full encryption. `Encrypt=Strict` rejected (unsupported). Integrated Security rejected. |
| sqlcmd (ODBC Driver 18 for SQL Server) | sqlcmd 18.6.0002.1, msodbcsql18 18.6.2.1, Linux | Queries, wrong/locked credentials, rotation. `-N` with CA trust. |
| mssql-jdbc (DBeaver's driver) | 13.6.1.jre11 on Temurin 21.0.12 | Suite 15/15 incl. CallableStatement, cancel, query timeout, DatabaseMetaData. |
| go-mssqldb | 1.11.2 | Integration suite 16/16 (`tests/integration`), incl. password rotation and shutdown. |
| DBeaver application | – | **Not tested** (its JDBC driver is, above). |
| SSMS | – | **Not tested** (no Windows environment available). |
| NTLM / Kerberos against Active Directory | – | **Not tested against a domain.** NTLMv2 (incl. channel binding and rotation) is tested only against an in-process fake server that verifies the NTLMv2 proof; Kerberos is untested. |

Driver behaviours seen identically **without** the proxy: go-mssqldb discards a
connection after context cancellation; go-mssqldb cannot use `packet size` below
4096 (TLS handshake buffer).

## Measured performance

Measured with `go run ./tests/bench` (go-mssqldb client, proxy binary, SQL
Server 2022 in Docker, all on one host: Xeon E5-2630 v4, 8 vCPU). Default
Argon2id parameters, TLS on both legs.

| Metric | Direct | Via proxy |
|---|---|---|
| Connect + first query, p50 / p95 | 8.2 / 10.0 ms | 66.8 / 80.9 ms |
| `SELECT 1` round trip, p50 / p99 | 504 / 832 µs | 641 / 909 µs |
| Large result, 400k rows × 208 B (best of 3) | 83 MB/s | 82 MB/s |
| 100 simultaneous logins (wall time) | 0.18 s | 1.75 s |
| `SELECT 1`, 100 open connections × 200 | 12,163 q/s | 10,952 q/s |

Proxy RSS: ~53 MB after the sequential tests, ~199 MB right after the
100-login bursts (Argon2id working memory, returned to the OS by the GC
afterwards), ~77 MB while holding 100 open sessions. Login cost is dominated by
Argon2id (~53 ms per verification at the default cost on this CPU); tune with
the hash parameters and `max_concurrent_hashes`.

## Known limitations

- TDS 7.2–7.4 only; no TDS 8.0 / `Encrypt=Strict`.
- TLS 1.2 by default on both legs (TDS 7.x prelogin-wrapped TLS); configurable.
- Client-side Windows/Kerberos/Entra authentication is not supported.
- Feature extensions: SESSIONRECOVERY (connection resiliency) is not offered to
  the backend, so clients run without transparent reconnection; Azure DNS
  caching / enhanced routing and unknown features are dropped; FEDAUTH rejected.
  Always Encrypted, UTF-8, data classification, JSON and vector support are relayed.
- Routing ENVCHANGE (Azure SQL redirects, read-only routing) is refused rather
  than followed.
- `idle_timeout` counts bytes in both directions; a query that runs longer than
  it without returning data is cut off. Set `0s` to disable.
- On shutdown, sessions get `shutdown_timeout` to finish, then are closed.
- No per-user rate limiting beyond `auth_failure_delay`, `max_connections`,
  `max_concurrent_hashes` and IP allowlists.
- The admin endpoint has no authentication; keep it on loopback.
- NTLM/Kerberos not validated against a real domain yet (see above).

## Troubleshooting

| Symptom | Check |
|---|---|
| Client: `certificate verify failed` / `The certificate chain was issued by an authority that is not trusted` | Client must trust the issuer of `tls.client_certificate`, and connect using a name in its SAN. |
| Client: `Login failed for user 'x'.` | Proxy log `login_failed` → `category`: `client_auth_invalid_credentials`, `client_auth_disabled`, `client_unauthorized` (user not in `allowed_backends`), `client_unsupported`. |
| Client: `the proxy could not log in to backend server` | `category=backend_login`: backend rejected the credentials (rotate the secret file); `backend_credentials`: secret file missing/empty/unreadable. |
| Client: `… were rejected and it is waiting for a new password` | Lockout protection paused the profile (`event=backend_credentials_blocked` shows the backend's error). Update the secret file; to retry the same secret, reload. |
| Client: `could not reach backend server` | `backend_connect` (DNS/firewall), `backend_tls` (backend certificate name/CA — see `tls_server_name`, `ca_file`), `backend_protocol` (encryption refused, routing, MARS mismatch). |
| Rotated secret not picked up in Docker | Directory vs. file mount (see above); file permissions for uid 65532. |
| `client uses TDS 8.0 strict encryption` | Use `Encrypt=Mandatory`/`True` instead of `Strict`. |
| Kerberos errors | `krb5_config` reachable KDC, correct `realm`, SPN registered for the SQL service (`setspn -L`), clock skew. |
| NTLM login rejected | `domain`/`username` (no `DOMAIN\` prefix in `username`), the account's domain trust, SQL Server's Extended Protection setting; try `channel_binding: false` if a TLS-terminating device sits in front of SQL Server. |

Set `logging.level: debug` for per-connection detail (still no secrets).

## Development

```sh
make test            # vet + unit/e2e tests with -race (fake SQL Server, no Docker needed)
make fuzz            # fuzz LOGIN7/PRELOGIN/token/packet parsers
make integration     # real SQL Server 2022 in Docker + go-mssqldb integration suite
tests/clients/dotnet # Microsoft.Data.SqlClient suite:  dotnet run -- suite "<conn string>"
tests/clients/jdbc   # mssql-jdbc suite:                ./run.sh <port> <user> <password>
```

Design notes, protocol decisions and the research behind them are in
[`docs/design.md`](docs/design.md).
