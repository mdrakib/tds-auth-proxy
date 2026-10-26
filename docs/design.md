# Design notes

## Research and reuse

| Source | License / status (Oct 2026) | Use |
|---|---|---|
| [MS-TDS specification](https://learn.microsoft.com/openspecs/windows_protocols/ms-tds/) | Microsoft Open Specification | Packet header, PRELOGIN, TLS-in-PRELOGIN, LOGIN7, FeatureExt, token formats. |
| [microsoft/go-mssqldb](https://github.com/microsoft/go-mssqldb) | BSD-3-Clause, active | Dependency for **public** packages only: `integratedauth/ntlm`, `integratedauth/krb5`, `integratedauth` (channel bindings), `msdsn` (their config struct). Also the Go test client. Its TLS handshake wrapper informed `protocol.HandshakeConn` (re-implemented, not copied). |
| [tech-software/TDSProxy](https://github.com/tech-software/TDSProxy) | MIT, C# | Reviewed for the overall approach of terminating LOGIN7 and relaying afterwards. No code used. |
| [RSKGroup/haystak-tds-spi](https://github.com/RSKGroup/haystak-tds-spi) | Apache-2.0, Go | Reviewed. No code used. |
| [fclairamb/dbbat](https://github.com/fclairamb/dbbat) | **AGPL-3.0** | Not used: incompatible with an unrestricted license for this project. |

No source was copied from any of these projects. Other dependencies:
`golang.org/x/crypto` (Argon2id; MD4 only in tests) and `gopkg.in/yaml.v3`.

## Connection flow

```text
accept ─ allowlist ─ connection slot
  │  (handshake_timeout covers everything until the login response is relayed)
  ├─ sniff first byte: 0x16 → TDS 8.0 strict → refuse
  ├─ PRELOGIN from client → answer: ENCRYPTION=ON (client ON/REQ) or REQ (client OFF);
  │                         NOT_SUP → answer REQ and close
  ├─ TLS server handshake inside PRELOGIN packets (HandshakeConn), then raw TLS
  ├─ LOGIN7 (≤128 KiB) → parse/validate → reject unsupported options
  ├─ Argon2id verify (bounded concurrency) → authorize listener's backend
  ├─ resolve credential profile (re-reads rotated secret files)
  ├─ lockout guard: refuse if these exact credentials were rejected; otherwise wait
  │                 for a login slot (1 while unverified, max_parallel_logins after)
  ├─ backend: dial → PRELOGIN (ENCRYPTION=ON, same MARS) → TLS client handshake (verify cert)
  │           → LOGIN7 built from the client's, credentials replaced → [SSPI rounds]
  │           → parse full login response, fail closed on anything unexpected
  ├─ relay backend login response to client (SSPI tokens removed, backend SPID kept)
  └─ frame-aware bidirectional relay until either side closes / idle / shutdown
```

## Key decisions

**Never retry a rejected backend password.** `credentials.Guard` keys each
profile's state on an in-memory HMAC (random per-process key) of the resolved
credentials, so a new secret is recognised on the next connection without
polling and the fingerprint is useless outside the process. State per profile:
unverified (one login at a time) → confirmed (`max_parallel_logins`) → rejected
(no backend contact until the fingerprint changes, a reload, or
`retry_interval`). Only definite credential rejections block; ambiguous failures
(network, TLS, 4060 missing database) leave the state unchanged.

**Authenticate before contacting the backend.** The backend is dialled only for
an authenticated, authorized client. Unauthenticated traffic cannot create load
or failed-login noise on SQL Server, and the backend session that authenticates
is the one used for relaying (no test connections).

**Independent PRELOGIN negotiations.** Because the client's PRELOGIN is answered
before the backend is contacted, the proxy fixes the values it controls:
encryption is always full-session on both legs; MARS is mirrored (the proxy
offers the backend what the client asked for, and fails the login if the backend
disagrees). VERSION in the proxy's PRELOGIN reply is a constant; clients take the
real server version from LOGINACK, which is relayed.

**TLS-in-PRELOGIN.** For TDS 7.x the TLS handshake travels inside PRELOGIN (0x12)
packets, after which TLS records flow directly on the socket.
`protocol.HandshakeConn` buffers TLS writes into one TDS message per flight,
reads exactly one packet payload at a time (never over-reading into the
post-handshake stream), and switches to pass-through in `EndHandshake`. It also
accepts type 0x04 responses that some servers send. Session tickets are disabled
on the client-facing side. TLS 1.2 is the default because TDS 7.x stacks on both
ends commonly require it; `min_version`/`max_version` are configurable.

**LOGIN7 re-serialization, not byte patching.** The client's LOGIN7 is decoded
into a struct and a new message is laid out from scratch, recomputing all
offsets, `cbSSPILong` and the FeatureExt pointer. Only the credential fields,
`fIntSecurity`, SSPI data and ServerName (set to the backend host) change; TDS
version, packet size, flags, LCID, app/host names, database and language are
preserved. Passwords are de-obfuscated only in memory and cleared after use.

**Feature extensions.** Features that only change the shape of the token stream
are relayed: both ends see exactly the same stream, so the backend's
FEATUREEXTACK (relayed verbatim) tells the client what is active. Session
recovery is not offered (a reconnect would replay state against a different
backend login), Azure DNS caching / enhanced routing are dropped (they could
steer clients around the proxy), FEDAUTH is refused, unknown IDs are dropped —
a feature the backend never acknowledges is simply off for the client.

**Login response handling.** The full response is reassembled (≤1 MiB) and
tokenized with a strict parser that knows only the tokens valid in a login
response; anything else fails the login. Success requires LOGINACK and a final
DONE without the error bit. Routing ENVCHANGEs are refused. SSPI tokens from
integrated authentication are stripped because the client used SQL
authentication. The response is re-packetized (≤4096-byte packets) carrying the
backend's SPID so `@@SPID` and the client-visible SPID agree.

**Packet size and framing.** The client's requested packet size is sent to the
backend unchanged and the backend's packet-size ENVCHANGE is relayed unchanged,
so both sides use the same negotiated size and no re-framing is needed. The
relay is still frame-aware: it reads one complete TDS packet (or MARS SMP frame,
identified by 0x53) and writes it with one `Write`, which validates lengths,
bounds memory per direction (one 32 KiB buffer), and keeps one TLS record per
packet (go-mssqldb documents SQL Server preferring this; see its issue #166).
ATTENTION, MARS and connection-reset flags pass through untouched.

**Credentials.** `credentials.Store` holds profile definitions in an
`atomic.Pointer`, swapped on reload. File secrets are cached keyed by
`os.SameFile` + size + mtime, with one `stat` per new backend connection — no
polling, immediate pickup, safe for concurrent use. `Credentials` implements
`String`/`LogValue` with the password redacted.

**Reload model.** A reload builds a complete new immutable `session.State`
(users with parsed hashes, TLS configs, backends, allowlists) and swaps it
atomically only if everything validates — including loading certificates and
hash sources. Sessions keep the state they started with.

**Error surface.** Clients get SQL Server-style error tokens with generic
messages (18456 for authentication/authorization/backend-login failures, 18401
when the backend is unreachable), after `auth_failure_delay` for auth failures.
Logs carry the precise category and the underlying error, never secrets.

## Package layout

```text
cmd/tds-proxy         CLI: run, check-config, hash-password, healthcheck
internal/app          wiring, reload, shutdown (used by main and tests)
internal/config       YAML schema, defaults, validation
internal/protocol     packets, PRELOGIN, TLS-in-PRELOGIN, LOGIN7, login tokens
internal/auth         client Argon2id auth + authorization; backend SQL/NTLM/Kerberos
internal/credentials  credential provider: profiles, file and env secrets
internal/backend      backend dial, PRELOGIN, TLS, login loop
internal/session      per-connection state machine and immutable State
internal/relay        frame-aware bidirectional relay
internal/listener     listeners, connection limit, allowlists, graceful shutdown
internal/monitoring   metrics, /healthz /readyz /metrics /-/reload
internal/testutil     test PKI and an in-process fake SQL Server (verifies NTLMv2)
tests/integration     real SQL Server suite (go-mssqldb)
tests/clients         SqlClient (.NET) and mssql-jdbc suites
tests/bench           direct-vs-proxy benchmark
```

## Testing strategy

- Unit tests per package, including malformed-input tables for every parser.
- Fuzz targets for LOGIN7, PRELOGIN, login tokens and packet reassembly,
  asserting no panics, bounded allocation and parse → serialize → parse stability.
- In-process end-to-end tests (`internal/app`) with go-mssqldb against a fake
  SQL Server that genuinely verifies SQL passwords and NTLMv2 proofs including
  channel bindings: rotation, reload, authorization, cleanup, shutdown, idle
  timeout, allowlists, limits, routing refusal, backend TLS failures.
- Real SQL Server 2022 integration suite and client suites for SqlClient, ODBC
  sqlcmd and mssql-jdbc; everything runs under `-race` where applicable.
