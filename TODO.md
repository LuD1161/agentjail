# TODO / Roadmap

## What Is Implemented

### Phase 1 — AWS policy pack + SQLite store
- `no_aws_destructive.rego` library rule (deny destructive, ask mutating)
- Per-account posture config (`aws.posture: sandbox|prod|locked|custom`)
- `samples/configs/policy-aws.yaml` template
- `internal/store` — SQLite event store (WAL, 0600, redaction, retention, daemon.log migration)
- `ReadOnlyStore` interface with `sqliteROStore` wrapper (no write methods leak)
- `CountActionsBySession` SQL aggregate query for efficient counter display
- Indexes on `session_id+ts`, `ts`, `action`, `tool_name`, `rule_id`
- Limit clamping (default 100, max 10000) and DSN path URL-encoding
- `agentjail logs --db` reads from SQLite (falls back to daemon.log with warning)
- `agentjail replay --session <id> --list --verbose --follow`
- CLI tests for `logs --db` and `replay --list/session/verbose`
- `ListAuditEvents` store method + tests
- `TestConcurrentReaderWriter` WAL-mode concurrent access test

### Phase 2 — Shield, netproxy, secrets, env audit
- Landlock network rules (`LANDLOCK_ACCESS_NET_CONNECT_TCP`, kernel 6.7+, ABI fallback)
- `agentjail-netproxy` on Linux (child process, proxy env vars, zombie cleanup)
- `runtime.LockOSThread()` to preserve Landlock across `os/exec`
- `agentjail-secrets` binary (AES-256-GCM at rest, Unix socket RPC, AWS/PG/Redis backends)
- `agentjail secret` CLI wrapper delegating to `agentjail-secrets`
- Shield calls `agentjail-secrets grant` and injects scoped env vars; revokes on exit (Linux)
- Env stripping at launch (configurable blocklist, `AGENTJAIL_SECRETS=1` signal)
- Environment audit (root, ambient creds, IMDS, `--audit-json`, `--audit-strict`)
- `SecretsConfig.Grants` in policy.yaml

### UI — Replay viewer with server-side filters
- `agentjail ui --db PATH --edit-policy` (on-demand local server, loopback-only)
- `/api/state` from SQLite with source status indicator
- `/api/state?action=deny&tool=Bash&rule=aws` — server-side filters pushed to SQL
- `/api/session?id=<id>` chronological replay with redacted tool_input
- `/api/session?id=<id>&action=deny&tool=Bash&rule=aws` — filtered session replay
- `/api/session?id=<id>&download=1` redacted session bundle export
- `/api/audit` policy-mutation audit events from SQLite
- Server-side filter params: `action` (comma-separated), `tool`, `rule` (substring), `limit`
- Frontend sends filters to server with 300ms debounce; SSE live events still client-filtered
- `FilteredCount` and `TotalDecisions` in API response for "N of M" display
- Pooled SQLite connection (one per server, not per request)
- Audit events section in the UI
- `--edit-policy` opt-in for policy enable/disable (read-only by default)

## Remaining TODOs

### Needs a specific environment to test
- Linux network smoke coverage on kernel 6.7+ (Landlock ABI v4).
- macOS shield paths (Landlock/netproxy/shield_darwin).

### Future work
- Time-based policy allowances (temporary grants with expiry).
- Netproxy zombie cleanup improvements.
- Tier 2 microVM integration with the microsandbox Go SDK.
