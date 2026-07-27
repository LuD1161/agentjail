# agentjail — Architecture

agentjail is a policy-guardrail layer for AI coding agents (Claude Code, Codex CLI, Cursor). It intercepts every tool call before it executes and evaluates it against OPA-based Rego policies, returning an `allow`, `deny`, or `ask` decision to the agent. No proxy, no wrapper binary, no dynamic-library injection — just hooks and a warm policy daemon.

---

## How It Works

Every major coding agent ships a hook system that fires a command *before* each tool call — before a file is written, before a shell command runs, before an MCP server is contacted. agentjail installs a hook (`agentjail-hook`) that forwards the tool-call payload over a Unix socket to a persistent background daemon (`agentjail-daemon`). The daemon holds the OPA engine warm and evaluates Rego rules in under 5 ms.

```
coding agent (Claude Code / Codex / Cursor)
  |
  | fires hook on every tool use (PreToolUse / beforeShellExecution)
  ↓
agentjail-hook  (tiny binary, ~1 ms overhead)
  |
  | forwards JSON payload over Unix socket
  ↓
agentjail-daemon  (persistent process, holds OPA engine warm)
  |
  | evaluates Rego rules against the input
  ↓
allow / deny / ask  →  returned to the coding agent
```

The daemon is started on login (launchd plist on macOS, systemd user service on Linux) so OPA cold-start cost (~50 ms) is incurred once at startup. Per-decision latency target is **<5 ms**.

### Hook wire format (Claude Code example)

```json
// stdin to agentjail-hook
{
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": { "command": "rm -rf /tmp/foo" },
  "session_id": "...",
  "cwd": "/Users/dev/project"
}

// stdout from agentjail-hook
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "rm -rf on paths outside project dir is blocked by policy"
  }
}
```

Exit code 2 + stderr blocks immediately without requiring JSON output.

### Fail-open guarantee

The hook never blocks a coding agent when `agentjail-daemon` is unreachable.
`agentjail-hook` connects to the daemon's Unix socket with a 30ms timeout; if
the socket is missing, the daemon isn't running, or it doesn't respond in
time, the tool call is allowed. This keeps a daemon crash or restart from
freezing every agent on the box. The OS-level shield is independent of this
path and keeps enforcing filesystem/network restrictions regardless of daemon
state, so a fail-open hook decision doesn't relax sandbox enforcement. Every
fail-open event is captured via telemetry so degraded daemon availability is
visible rather than silent. This guarantee does not extend to credential
paths: the shield's OS-level deny on sensitive paths (`~/.ssh`, `~/.aws`,
etc.) is enforced by the sandbox itself, not the hook, so it holds even when
the daemon is down.

---

## Hook Integration per Platform

| Platform | Hook event | Config file | What is intercepted |
|---|---|---|---|
| Claude Code | `PreToolUse` | `~/.claude/settings.json` | Bash, Write, Edit, Read, all MCP tools |
| Codex CLI | `SessionStart` + `PreToolUse` + `PermissionRequest` + `PostToolUse` + `Stop` | `~/.codex/hooks.json` | Lifecycle attestation; Bash, apply_patch, MCP tools |
| Cursor | `beforeShellExecution` + `beforeMCPExecution` + `beforeReadFile` | `~/.cursor/hooks.json` | Shell, MCP, and agent file reads |

The hook is configured in a file the agent reads at startup. Because the agent runs *inside* the hook framework, it cannot remove the hook from within itself. The policy binary runs in the host shell, not in the agent's process.

---

## Policy Model

Policies live under `agentpolicy/policies/` (mirrored into the binary at
`cmd/agentjail/policies/`) and are written in Rego.

### Candidate → resolver → decision

Every policy file contributes `candidate` entries to the partial set
`data.agentjail.candidate`. `resolver.rego` is the **sole** producer of
`data.agentjail.decision`: it derives an `effective_candidate` set and picks the
most restrictive (deny > ask > allow; lowest `rule_id` breaks ties). When nothing
fires, the default is **ask** (fail-safe, not silent allow). Every rule has a
namespaced `rule_id` (`file_policy/…`, `command_policy/…`, `mcp_policy/…`,
`library/…`, `custom/<name>/…`).

### Config overlay (ADR 0012)

The daemon loads `~/.agentjail/policy.yaml`, merges it over built-in defaults,
and injects it into OPA as `data.agentjail.config` (re-injected on reload —
a control message over the daemon socket, with `SIGHUP` retained as a
fallback; see [ADR 0052](adr/0052-daemon-control-plane-socket.md) —
decision cache invalidated). Rego reads config from there — e.g.
`data.agentjail.config.mcp.allowed`, `.file.temp_roots`, `.disabled_rules`.
Request paths and `cwd` are canonicalized (symlinks/`..` resolved) at ingest, so
policies always see real absolute paths; `cwd` is part of the decision-cache key.

### `file_policy.rego` — sensitive path enforcement (ADR 0013)

Two tiers:
- **`is_protected_credential` → hard deny everywhere** (regardless of cwd):
  `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config`, `~/Downloads`, `~/Desktop`,
  `~/.npmrc`/`~/.pypirc`/`~/.git-credentials`/`~/.docker/config.json`/`~/.kube/config`/`~/.cargo/credentials`,
  `~/Library/Keychains`, `/etc`, and non-temp `/var`.
- **`is_sensitive_basename`** (`.env*`, `credentials*`, `secrets*`, `*.pem/.key/…`,
  `id_rsa`-family) → **ask** when inside the granted project dir, **deny** outside.
  The `.env` predicate is op-aware: reads use the broad `.env*` match above
  unchanged, writes/edits use a narrower secret-form deny-list only
  (`.env`, `.env.local`, `.env.production`, ...) so non-secret templates
  like `.env.example` are writable - see
  [ADR 0057](./adr/0057-env-write-deny-secret-form-denylist.md).

The temp tree (`$TMPDIR`, `/tmp`, `/var/folders/…`) is **allowed**. Project
membership is boundary-safe (`p == cwd OR startswith(p, cwd + "/")`), so a sibling
like `/proj2` doesn't match `cwd=/proj`. Writes to `~/.agentjail/` get their own
locked `file_policy/agentjail_self` deny (self-protection).

### `mcp_policy.rego` — MCP server allowlist

Allowlist by server name (glob). At install, agentjail **seeds the allowlist from
the MCP servers already configured** in Claude/Codex/Cursor (trust-on-install),
so existing setups keep working; the default blocklist (`*stripe*`, `*payment*`,
…) always takes precedence. Manage with `agentjail mcp allow/block/list` —
`allow`/`block` mutate policy, so they require an interactive-terminal
confirmation (an agent can't self-approve a server).

```yaml
# ~/.agentjail/policy.yaml
mcp:
  allowed: ["claude-mem", "context7", "github*"]
  blocked: ["*stripe*", "*payment*"]
```

### `web_policy.rego` — web read tools (WebSearch / WebFetch)

Coding agents route their read-only web tools through the hook. Without a rule
these hit `resolver/default` → **ask**, so every search/fetch prompts the user
(and the agent host's per-domain "don't ask again" can't suppress an agentjail
`ask`). So agentjail governs them explicitly: **WebSearch is always allowed** (a
query to the harness's search backend, no arbitrary endpoint), and **WebFetch is
allowed by default** (read-only GET) **unless its target host matches a
configurable blocklist**:

```yaml
# ~/.agentjail/policy.yaml
web:
  blocked: ["*tracking*", "*.internal", "169.254.*"]   # host globs; default []
```

Host globs match case-insensitively and `*` spans dots. This is domain control,
not exfil-proofing — a determined prompt-injected agent could pick an unlisted
host; the bigger exfil vector (Bash `curl`/POST) stays governed by
`command_policy`. Users who want WebFetch to prompt again can add
`web_policy/fetch` to `disabled_rules` (it falls back to the default ask).

### `command_policy.rego` — dangerous shell patterns

Block or prompt before high-risk patterns: `rm -rf` outside the project,
`curl … | bash`, `chmod -R 777`, `sudo`, `dd`, `> /dev/disk*`,
`ssh-keygen`, `gpg --export-secret-keys`, `env | curl` exfil, and more; *ask* on
package publish. **git force-push is branch-aware**: force-pushing the default
branch (`main`/`master`) is denied, force-pushing a topic/feature branch is
allowed (normal rebase / PR-update flow), and a bare `git push -f` (implicit
current branch) asks. An always-on, locked `command_policy/no-policy-mutation` rule
blocks an agent from running `agentjail policy disable`/`mcp` or writing into
`~/.agentjail/`. The mutation guard uses specific subcommand patterns (e.g.
`agentjail\s+update\b`) rather than broad keyword matching, to avoid false
positives when "agentjail" or "update" appears as a path component or in prompt
text. The sensitive-path rule likewise ignores only static, non-expanding
`git commit -m` message text; command substitutions, other arguments, chained
commands, and remote shell payloads remain subject to the deny.

### Tuning, disabling, and custom rules (ADR 0014)

- **Disable any rule** by adding its `rule_id` (or a `policy/*` glob) to
  `disabled_rules` in `policy.yaml`, or via `agentjail policy disable <rule_id>`.
  `resolver.rego` drops disabled candidates from `effective_candidate`.
- **Locked self-protection set** — a hardcoded constant in `resolver.rego`
  (`file_policy/agentjail_self`, `command_policy/no-policy-mutation`,
  `resolver/*`) can **never** be suppressed
  by `disabled_rules`, so no `policy.yaml` edit unlocks it. The CLI also requires
  `--force` + an interactive TTY confirm to disable a core rule, and logs mutations
  to `~/.agentjail/audit.log`. `library/no-daemon-kill` is on by default but
  disableable with `--force` — the daemon runs under launchd/systemd with
  `KeepAlive=true`, so a kill is a speed bump, not a permanent disable.
- **Custom rules** — `agentjail policy add <file.rego>` parses the module AST and
  accepts only partial `candidate` entries in `package agentjail`; resolver
  helpers and `decision` are not extensible. It validates reserved
  `custom/<name>/<rule>` ids and compiles the full bundle before installation.
  The daemon repeats the extension-surface validation during deterministic
  quarantine, so a manually dropped unsafe module is skipped rather than
  weakening the baseline.

See ADRs [0012](adr/0012-daemon-config-overlay.md),
[0013](adr/0013-file-policy-temp-and-project-posture.md), and
[0014](adr/0014-user-tunable-policy-surface.md) for the decisions behind these.

### Self-protection model (ADR 0025)

agentjail's self-protection uses a layered enforcement model inspired by EDR
architecture — enforcement at the point of effect, not the point of intent:

- **Regex rules (Tier 1)** are the UX/signals layer: they produce clear deny
  messages ("you are trying to disable agentjail policy") and catch obvious
  attempts early. They are defense-in-depth, not the primary guarantee.
  Write/Edit to hook config files (`~/.claude/settings.json`, etc.) produce
  **ask** (user can approve legitimate edits); Bash-based writes **deny**.
- **Shield (Tier 1.5)** is the enforcement layer: Seatbelt/Landlock deny
  writes to `~/.agentjail/` at the kernel level, regardless of how the write
  is attempted (`python -c`, `node -e`, `eval`, etc.).
- **Tier 2 (microVM)** makes self-protection structural: the agent runs in a
  VM, agentjail runs on the host, and the attack surface doesn't exist.

See [ADR 0025](adr/0025-layered-self-protection.md) for the full mutation
surface analysis and design rationale.

---

## OS-native Sandbox (`agentjail-shield`)

The hook layer is cooperative — the agent must call the hook, and the hook must
pattern-match the command. Shell tricks like variable expansion, `eval`, or
non-shell interpreters (`python -c`, `osascript`) can bypass hook-level
protection. `agentjail-shield` closes this gap by wrapping the agent in the
operating system's kernel sandbox *before* exec'ing it. Every subprocess
inherits the restrictions.

```
agentjail-shield
  │
  ├─ [macOS]  generates Seatbelt sbpl profile → sandbox-exec -p <profile> <agent>
  ├─ [Linux]  landlock_create_ruleset + landlock_restrict_self → execve <agent>
  └─ [other]  warning → exec <agent> (fail-open; hook still active)
```

**macOS (Seatbelt):** deny-list based. Denies writes to sensitive paths
(`~/.ssh`, `~/.aws`, `~/.gnupg`, etc.), denies reads of credential paths, and
restricts network egress. `~/Library/Keychains` (user keychain root) is
granted read+write by default so Claude Code's login/token-refresh flow
works — see [ADR 0037](./adr/0037-macos-keychain-access-shielded-agent.md);
the hook layer still denies an agent's own direct reads of that path. When
`agentjail-netproxy` is enabled (opt-in via `--netproxy`; OFF by default in the
interim -- ADR 0046), the
agent is restricted to localhost-only outbound TCP and all HTTPS traffic flows
through the proxy, which enforces the *effective* allowlist from `policy.yaml`.
By default (no `--netproxy`) egress is port-only (80/443, no per-host filtering)
until the transparent tunnel (planned) supersedes the proxy.
The effective allowlist is three tiers -- non-removable essentials (provider
auth + `mcp-proxy.anthropic.com`), hosts auto-derived from the MCP servers you
allow (`mcp.allowed`), then your editable `network.allowed_hosts` -- computed by
`EffectiveAllowedHosts()`. A malformed `policy.yaml` or a failed `netproxy` make
the shield refuse to launch (fail loud / fail closed) rather than silently
weaken enforcement. See [ADR 0040](./adr/0040-mcp-derived-hosts-and-fail-loud-config.md)
and [ADR 0041](./adr/0041-hostpattern-cursor-hosts-netproxy-fail-closed.md);
for the end-to-end walkthrough see [`docs/FLOW.md`](./FLOW.md).

**Linux (Landlock):** allowlist-based. Grants read-write to `/tmp` and the
project CWD, read-only to system directories and `$HOME`, and denies everything
else. Sensitive subdirectories (`~/.ssh`, `~/.aws`, `~/.gnupg`) are never
allowlisted. `~/.agentjail` -- agentjail's own enforcement state -- is granted
**read-only**, so `policy.yaml`, the SQLite DB, and `trusted.yaml` stay
unwritable and the agent cannot disable its own guardrail. The sandboxed hook
still reaches `daemon.sock` with no write grant of any kind: Landlock is a
filesystem LSM and does not mediate `AF_UNIX connect()` at all (measured --
ADR 0067-control-plane-token-auth, addendum 1).
`~/.agentjail/run/daemon-ctl.sock` (the grant control socket, ADR 0047) is
deliberately excluded from the write grant -- the agent can file grant requests
through `daemon.sock` but cannot approve them.

**No special privileges required.** Both `sandbox-exec` and Landlock run as the
invoking user — no sudo, no entitlement, no kernel module.

**Environment hardening** (before exec):
- Strips ambient credentials from the agent's env (configurable blocklist)
- Audits for root, readable credential files, IMDS reachability
- `agentjail-secrets` broker issues scoped, short-lived credentials via
  `grant`/`revoke` over Unix socket (AES-256-GCM at rest)

For the full user guide, see [`docs/SANDBOX.md`](./SANDBOX.md).
For the decision record, see [ADR 0001](./adr/0001-os-sandbox-enforcement-layer.md).

---

## Decision Store (SQLite)

Every policy decision is persisted to `~/.agentjail/agentjail.db` (SQLite, WAL
mode). The daemon writes; the CLI, UI, and replay tools read via `ReadOnlyStore`
(a separate read-only connection that cannot write even if type-asserted).

```
agentjail-daemon (writer)
  │  RecordDecision / RecordAuditEvent
  ▼
agentjail.db  (WAL mode, concurrent readers OK)
  ▲
  │  ListDecisions / CountActionsBySession / ListSessions
agentjail logs / replay / ui  (readers via OpenReadOnly)
```

**Schema highlights:**
- `decisions` table: `id`, `ts`, `session_id`, `tool_name`, `action`, `rule_id`,
  `reason`, `summary`, `tool_input_redacted`, `elapsed_us`, `cwd`, `agent`
- `sessions` table: `session_id`, `agent`, `start_ts`, `end_ts`, `decision_count`
- `audit_events` table: policy enable/disable/reload mutations
- Indexes on `(session_id, ts)`, `ts`, `action`, `tool_name`, `rule_id`
- Automatic retention cleanup via `Cleanup(maxAge)`
- Tool input redaction at write time: secret-bearing **keys** are stripped, and
  recognised secret **values** (bearer tokens, provider keys, PEM blocks, URL
  passwords) are stripped wherever they appear — including inside a positional
  value such as a Bash `command` string (ADR 0019, ADR 0084-redact-secret-values)

**Filter support:** `store.Filter` supports `SessionID` (substring), `Actions`
(case-insensitive OR), `Tool` (exact), `Rule` (case-insensitive substring),
`AfterID` (keyset pagination, direction-aware for ASC/DESC), and `Limit` (clamped
to [100, 10000]).

### Unified Audit Log

The `audit_log` table captures every significant event across daemon, CLI,
shield, and secrets — policy mutations, session lifecycle, shield activation,
credential grants/revokes, config reloads, and more. It replaces the scattered
`audit_events` table and flat-file `audit.log` with a single queryable source.

Components emit audit events through the `AuditEmitter` interface
(`internal/audit/`), which decouples event production from storage. Event type
constants live in `internal/audit/audit.go`. Three durability classes govern
how events are written:

- **Fail-closed:** policy mutations (`policy.change_requested` /
  `policy.changed`) — audit must succeed before `config.Save()` proceeds.
- **Transactional:** emitted in the same SQLite transaction as the primary data
  write (e.g. session upsert, tool registration). Audit failure is logged but
  does not roll back the primary write.
- **Best-effort:** lifecycle events (daemon startup, shield activation). Fire-
  and-forget, never blocks the hot path.

Decisions are NOT duplicated into `audit_log` — they remain in the `decisions`
table, which is optimized for the per-decision hot path. A unified query layer
provides combined chronological views when needed.

The `Detail` column is redacted at the store boundary using the same key-pattern
matcher and value-pattern sweep as `RedactToolInput`, with a 4096-byte cap.
Credential values are never stored — only fingerprints (ADR 0032). The shield opens the
database before sandbox activation so pre-opened file descriptors survive
Landlock/Seatbelt restrictions.

See [ADR 0033](adr/0033-unified-audit-log.md) for the full decision record.

---

## Local UI

`agentjail ui` starts a loopback-only HTTP server backed by the SQLite store.

- `/api/state` — sessions, counters (global), recent events (filtered)
- `/api/session?id=<id>` — chronological session replay with filters
- `/api/audit` — policy-mutation audit log
- Server-side filter query params: `action`, `tool`, `rule`, `limit`
- Counters (`total_allow`/`deny`/`ask`) are always global; only `recent_events`
  and session replay rows are filtered
- `FilteredCount` and `TotalDecisions` in response for "showing N of M"
- Frontend sends filters with 300ms debounce; SSE live events remain client-filtered
- `--edit-policy` opt-in enables policy enable/disable controls (read-only by default)

---

## Isolation Tiers

agentjail is designed across three levels of isolation strength. They are not mutually exclusive — stronger tiers can layer on top of lighter ones.

### Tier 1 — Hooks (lightest isolation)

The agent runs normally on the host. agentjail intercepts at the agent's own tool-call boundary using the platform hook system described above. No changes to the host OS, no container, no kernel module required.

**Characteristics:**
- Zero friction to install; hooks are a first-class feature of all supported agents.
- Policy decisions happen in user space, in the host shell.
- An agent that cooperates with its hook framework cannot bypass this layer from within itself.
- Does not protect against agents that have been modified to skip hook dispatch entirely.

### Tier 2 — Container / MicroVM (stronger isolation)

The agent runs inside a microVM. The proposed substrate is **Microsandbox** (built on libkrun) for the developer-laptop path — macOS (HVF), Linux (KVM), and Windows (WSL2) — with **Firecracker** retained as the server-fleet backend. The VM boundary enforces egress from `network.allowed_hosts` and keeps credentials out of the guest; the Tier 1 hook + daemon run *inside* the VM unchanged. The same OPA policy engine governs both sides of the boundary.

**What it adds over Tier 1:**
- Hard containment: an agent that attempts to ignore hooks is physically prevented from reaching the host filesystem or network.
- Works for agents that do not support hooks at all.
- Stronger audit trail: every syscall crossing the boundary is logged, not just declared tool calls.

> Substrate selection, the two-backend split, and the long-term pros/cons are decided in [ADR 0016](./adr/0016-tier2-microsandbox-substrate.md) (status: Proposed). The libkrun and Firecracker spikes live under [`agentjail/research/`](../agentjail/research/).

### Tier 3 — Kernel Module (strongest isolation)

A kernel module (eBPF LSM on Linux, macOS SystemExtension) intercepts all file, network, and process events system-wide, regardless of whether the agent runs in a container or directly on the host.

**What it adds over Tier 2:**
- Covers any process on the machine, not only agents that agentjail spawned.
- No agent cooperation required: works even if the agent binary is replaced or modified.
- Suitable for fleet-wide deployment where every machine needs a consistent enforcement boundary.

---

## Setup

```sh
# One-time setup
agentjail install --for claude-code
# → writes hook entry to ~/.claude/settings.json
# → starts agentjail-daemon as a launchd service
# → writes default ~/.agentjail/policy.yaml

# Then use your agent normally
claude  # every tool call is now policy-checked
```

---

## Related Docs

- [`docs/FLOW.md`](./FLOW.md) -- plain-language walkthrough of a shielded session and the allowed-hosts model
- [`docs/PRINCIPLES.md`](./PRINCIPLES.md) — design constraints and trade-offs
- [`agentpolicy/docs/DECISION_RPC.md`](../agentpolicy/docs/DECISION_RPC.md) — daemon RPC protocol
- [`docs/adr/`](./adr/) — architectural decision records
