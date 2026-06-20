# Agent Handoff TODO

## Current State

- Repo root: `/DATA/openclaw/Repos/agentjail`
- Branch: `main` (31 commits ahead of `origin/main`)
- Remote status: local only. Do not push unless explicitly asked.
- Only worktree, only branch — all feature branches and worktrees were merged and cleaned up.
- Go `1.26.3` installed at `/usr/local/go`.

## What Is Implemented

### Phase 1 — AWS policy pack + SQLite store
- `no_aws_destructive.rego` library rule (deny destructive, ask mutating)
- Per-account posture config (`aws.posture: sandbox|prod|locked|custom`)
- `samples/configs/policy-aws.yaml` template
- `internal/store` — SQLite event store (WAL, 0600, redaction, retention, daemon.log migration)
- `agentjail logs --db` reads from SQLite (falls back to daemon.log)
- `agentjail replay --session <id> --list --verbose --follow`
- CLI tests for `logs --db` and `replay --list/session/verbose`
- `ListAuditEvents` store method + tests

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

### UI — Replay viewer
- `agentjail ui --db PATH --edit-policy` (on-demand local server, loopback-only)
- `/api/state` from SQLite with source status indicator
- `/api/session?id=<id>` chronological replay with redacted tool_input
- `/api/session?id=<id>&download=1` redacted session bundle export
- `/api/audit` policy-mutation audit events from SQLite
- Client-side filters: action, tool (auto-populated), rule substring
- Audit events section in the UI
- `--edit-policy` opt-in for policy enable/disable (read-only by default)
- Chrome CDP tested (8 screenshots, all interactions verified)

### ADRs
- 0016 — Rego at both tiers
- 0017 — AWS pack Tier 1 scope
- 0018 — SQLite local store
- 0019 — Redaction policy
- 0020 — Environment audit at launch
- 0021 — Landlock network rules
- 0022 — Netproxy on Linux
- 0023 — Secret server
- 0024 — Env stripping at launch
- Tier 2 microsandbox substrate (pre-existing)

## How A New Agent Should Pick Up

1. Start in the repo:

   ```sh
   cd /DATA/openclaw/Repos/agentjail
   ```

2. Read these files first:

   ```sh
   AGENTS.md
   docs/ARCHITECTURE.md
   docs/ENGINEERING.md
   TODO.md
   plans/007-ui-replay-viewer.md
   ```

3. Confirm state:

   ```sh
   git status --short --branch
   git log --oneline -10
   ```

4. Do not push. Keep work local unless the user explicitly asks.

5. Before committing, run:

   ```sh
   gofmt -w <changed-go-files>
   go build ./...
   go vet ./...
   go test ./...
   make smoke
   make licenses
   ```

## Remaining TODOs

### Near-term
- Read-only SQLite open mode for UI/query paths (avoid write-lock contention with daemon).
- Server-side filters for `/api/state` and `/api/session` (action/tool/rule/session query params).
- Run final verification on main (`go build && go vet && go test && make smoke && make licenses`).

### Can't test locally
- Linux network smoke coverage on kernel 6.7+ (this host is kernel 6.1 / Landlock ABI v2).
- macOS shield paths (Landlock/netproxy/shield_darwin).

### Release hygiene
- Decide whether to squash/rebase 31 local commits before opening a PR.
- Decide whether to push or keep local indefinitely.
