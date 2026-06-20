# ADR 0023 — Secret server (ADR 0004 realization)

- **Status:** Accepted
- **Date:** 2026-06-19
- **Deciders:** agentjail-core
- **Related:** [ADR 0004](0004-credential-broker-tier1.md) (credential broker design), [ADR 0001](0001-os-sandbox-enforcement-layer.md) (OS sandbox)
- **Realizes:** ADR 0004 (Proposed → implemented for Tier 1)

## Context

ADR 0004 proposed a credential broker that strips ambient credentials from
the agent's environment and issues scoped, short-lived credentials on
demand.  The agent never reads long-lived secrets directly; instead, the
broker mints credentials with the minimum permissions needed for the task.

This ADR records the implementation decisions for the Tier 1 realization:
`cmd/agentjail-secrets/` — a local secrets store and credential broker.

## Decision

### Binary and protocol

`agentjail-secrets` is a standalone binary with two modes:
- **Server mode** (`agentjail-secrets serve`): listens on a Unix socket
  (`~/.agentjail/secrets.sock`, 0600) and handles newline-delimited JSON
  RPC (same pattern as `agentjail-daemon`).
- **CLI client mode** (`agentjail-secrets set/list/delete/grant/revoke`):
  connects to the server socket and sends a single RPC.

### Storage

Secrets are stored at `~/.agentjail/secrets/` encrypted at rest with
**AES-256-GCM** (stdlib `crypto/cipher`).  Each secret is a file containing
`nonce (12 bytes) || ciphertext || GCM tag (16 bytes)`.

The master key is a 32-byte random key stored at
`~/.agentjail/secrets.key` (0600).  On first run, a new key is generated.
**Future enhancement:** integrate with OS keystore (macOS Keychain, Linux
secret-service) for key management.  The current key-file approach is the
"fallback to a passphrase-derived key" path from ADR 0004 — simpler, no
D-Bus or Keychain dependency, but the key file must be protected by file
permissions and Landlock/Seatbelt (it's under `~/.agentjail/` which is
denied to the agent).

Secret names use `/` for backend namespacing: `aws/prod`, `pg/staging`,
`redis/dev`.  Each name is stored as a file (with subdirectories for the
backend prefix).

### Backends

Three backends, each issuing scoped, short-lived credentials (Kind-A from
ADR 0004 §4.2):

| Backend | Secret name prefix | Mechanism | Scope | Revocation |
|---|---|---|---|---|
| AWS | `aws/` | STS `AssumeRole` with inline session policy | `read-only`: deny Delete*/Terminate*/Create*/Update*; `read-write`: deny Delete*/Terminate* | Short TTL (cannot revoke early) |
| Postgres | `pg/` | `CREATE ROLE` with scoped grants + `VALID UNTIL` | `read-only`: GRANT SELECT; `read-write`: GRANT SELECT/INSERT/UPDATE/DELETE | `DROP ROLE` (immediate) |
| Redis | `redis/` | `ACL SETUSER` with key globs + command subset | `read-only`: +@read -@write; `read-write`: +@read +@write -@dangerous | `ACL DELUSER` (immediate) |

### No new dependencies

All three backends are implemented without adding any new Go module
dependencies:

- **AWS:** raw HTTP POST to STS with a minimal SigV4 signer (stdlib
  `crypto/hmac`, `crypto/sha256`, `net/http`).  Avoids the heavy AWS SDK
  for Go (~50 transitive deps).  The signer handles only POST requests to
  `sts.amazonaws.com` — sufficient for `AssumeRole`.
- **Postgres:** shells out to the `psql` command-line client via
  `exec.Command("psql", dsn, "-c", sql)`.  Avoides adding `pgx` or
  `lib/pq`.  Requires `psql` to be installed on the host.  This is the
  same trade-off as the AWS raw-HTTP approach: avoids a dep at the cost of
  depending on a system binary.
- **Redis:** raw RESP protocol over TCP (stdlib `net` + `bufio`).
  Implements just enough of the RESP protocol for `AUTH` and
  `ACL SETUSER`/`ACL DELUSER`.  Avoids adding `go-redis` or similar.

### Grant lifecycle

1. The shield (or a CLI user) calls `grant <name> --scope=<policy> --ttl=<duration>`.
2. The server loads the secret config, determines the backend from the name
   prefix, and calls the backend's grant function.
3. The backend issues scoped creds (STS session, PG role, Redis ACL user)
   with the requested TTL and scope.
4. The grant is registered in the `GrantManager` with a unique ID, expiry
   time, and a backend-specific `revokeFn`.
5. The scoped creds are returned as env vars (e.g. `AWS_ACCESS_KEY_ID`,
   `PGPASSWORD`, `REDIS_PASSWORD`).
6. On session end (shield exit) or explicit `revoke <grant-id>`, the
   `GrantManager` calls `revokeFn`:
   - AWS: `nil` (STS sessions can't be revoked early — relies on short TTL)
   - PG: `DROP ROLE` (immediate)
   - Redis: `ACL DELUSER` (immediate)
7. Every grant and revocation is logged to `slog` (JSON to stderr).  When
   the SQLite store (Phase 1) is available, these events will be persisted
   there with `cred_id` for correlation.

### Env injection (P2.4 integration)

The shield calls `agentjail-secrets grant` before exec'ing the agent,
injects the scoped creds into the agent's environment, and strips ambient
credentials (see P2.4 — env stripping).  The agent's environment contains
only scoped, short-lived creds — never the long-lived secrets stored in
`~/.agentjail/secrets/`.

## Consequences

**Positive:**
- Closes the script-indirected credential attack surface from ADR 0004: a
  Python script doing `boto3.client('s3').delete_bucket(...)` fails because
  the STS session's inline policy denies `Delete*`.
- No new dependencies — all backends use stdlib or system binaries.
- AES-256-GCM at rest with a 0600 key file; the key file is under
  `~/.agentjail/` which is denied to the agent by Landlock/Seatbelt.
- Per-backend revocation: PG and Redis revoke immediately; AWS relies on
  short TTL (minimum 15 minutes, configurable).

**Negative:**
- The master key is a file, not in an OS keystore.  A user with read access
  to `~/.agentjail/secrets.key` can decrypt all secrets.  Landlock/Seatbelt
  mitigates this for the agent, but a non-sandboxed process could read it.
  OS keystore integration is a future enhancement.
- The PG backend requires `psql` to be installed.  If `psql` is not on
  `PATH`, PG grants fail with a clear error.  This is acceptable for the
  Tier 1 OSS path; a future `pgx` integration would remove this dependency.
- The SigV4 signer is minimal — it handles only POST to STS.  Other AWS
  API calls (S3, EC2, etc.) are not supported by the signer.  This is
  sufficient for `AssumeRole`; the agent uses the resulting STS creds with
  its own SDK, not through our signer.
- STS sessions cannot be revoked early.  A granted AWS session lives for
  its full TTL (minimum 15 minutes).  This is a limitation of AWS STS, not
  our implementation.

**Implementation notes:**
- `cmd/agentjail-secrets/store.go` — AES-GCM encrypted storage
- `cmd/agentjail-secrets/grant.go` — grant tracking and revocation
- `cmd/agentjail-secrets/aws.go` — STS AssumeRole backend
- `cmd/agentjail-secrets/sigv4.go` — minimal SigV4 signer
- `cmd/agentjail-secrets/postgres.go` — PG role backend (via psql)
- `cmd/agentjail-secrets/redis.go` — Redis ACL SETUSER backend (raw RESP)
- `cmd/agentjail-secrets/server.go` — Unix socket RPC server + CLI client
- `cmd/agentjail-secrets/main.go` — CLI entry point and subcommand dispatch
- Tests: store encryption/decryption, grant lifecycle, DSN parsing, RESP
  command building, scope policies.  Backend integration tests skip when
  the backend (AWS/PG/Redis) is not available.
