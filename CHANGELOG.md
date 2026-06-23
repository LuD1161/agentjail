# Changelog

Pre-1.0; `main` is the live branch. Significant ships only — see `git log` for the full picture. Format roughly follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and dates are ISO-8601.

## v0.2.7 — 2026-06-23

Replay session labels and docs polish.

## TL;DR

- **Replay session prefix** - 8-char session prefix instead of truncated UUID with ellipsis.
- **Docs cleanup** - README updated for v0.2.6, duplicate badge removed.

### Fixed

- **Replay session label** - `agentjail replay` now shows an 8-char session
  prefix instead of a truncated UUID with ellipsis
- **Duplicate badge** - removed duplicate GitHub downloads badge from README

### Changed

- **README** - updated for v0.2.6, added recent updates timeline

## v0.2.6 — 2026-06-23

Daemon auto-update - the daemon can now update itself without human
intervention.

## TL;DR

- **Daemon auto-update** - download, verify, swap binaries, and restart automatically.
- **Linux systemd support** - auto-update works on Linux via systemd in addition to macOS launchd.

### Added

- **Daemon auto-update** - the daemon can download the latest release, verify
  its SHA256 checksum, atomically swap binaries, and exit for launchd/systemd
  to restart it (ADR 0026)
- **Linux systemd support** - auto-update daemon restart works on Linux via
  systemd in addition to macOS launchd

### Fixed

- **ExtractTarball** - create destination directory if it does not exist

## v0.2.5 — 2026-06-23

Combined changelogs on update, UI polish, TUI local time fix, and telemetry
overhaul — PostHog now builds real user profiles, heartbeats actually arrive,
and the web UI gets session permalinks, scroll stability, and a wider sidebar.

### Added

- **Combined changelogs on update** — `agentjail update` now shows what shipped
  in every release you skipped, not just the latest; backed by a new Worker
  endpoint `/v1/changelog?from=vX.Y.Z`
- **Session URL permalinks** — selecting a session updates the URL with
  `?session=ID`; the session is restored on page load and browser back/forward
- **"← All Sessions" back button** — visible at the top of the sidebar when a
  session is selected; replaces the hidden bottom toggle

### Fixed

- **Person properties** — every telemetry event now sends `$set` (mutable:
  `agentjail_version`, `os`, `arch`) and `$set_once` (immutable:
  `install_method`, `first_installed_version`) so PostHog builds person profiles
  instead of showing anonymous hashes with no metadata
- **Heartbeat reliability** — CLI now waits for the heartbeat HTTP POST to
  complete before exiting; previously the goroutine was fire-and-forget and most
  heartbeats were silently lost
- **Install inflation** — install events now carry `is_fresh_install` to
  distinguish first-ever installs from binary/daemon refreshes (`curl | sh` on
  an already-installed machine)
- **Empty version on dev builds** — non-release builds now report
  `"dev-<sha7>"` instead of an empty string, via a `commit` ldflags variable
- **`session_start` reliability** — sent immediately at daemon startup instead
  of waiting for the 2-minute spool flush, so it's captured even if the daemon
  exits quickly
- **Worktree repo name** — git `--git-common-dir` resolves the real repo name
  inside worktrees instead of showing the worktree folder name
- **Timeline scroll stability** — scroll position is preserved during SSE
  updates; expanded event cards no longer jump to the top
- **Expanded event identity** — expanded cards track by `req_id|time` instead
  of array index, so new SSE events don't shift the card to a different row
- **Timeline grid layout** — Summary column is now the flexible column; Rule
  has a fixed width, eliminating the empty space on the right
- **Logs TUI local time** — `agentjail logs` now displays timestamps in local
  time instead of UTC

### Changed

- **Sidebar width** — default increased from 208px to 280px for better
  readability of session labels
- **Agent text removed from labels** — the agent icon is sufficient; agent name
  appears on hover tooltip only
- **Releases Worker cache TTL** — reduced from 5 minutes to 1 minute so new
  releases are visible immediately after publish
- **TELEMETRY.md** — documented person properties (`$set`/`$set_once`),
  `is_fresh_install`, version fallback, and updated delivery semantics

## v0.2.4 — 2026-06-23

Smarter session labels, live event ticker, and CWD column in the web UI.

### Added

- **Git-aware session labels** — sessions now display as `agent · branch ·
  repo` (e.g. "claude-code · main · agentjail") instead of opaque UUIDs; git
  branch and repo name are looked up once per session on first event
- **CWD column in timeline** — the event timeline table shows the working
  directory basename for each event
- **Live event ticker** — the header bar shows "last event: Xs ago" updated
  every second, so it is clear the SSE connection is alive

### Fixed

- **`agentjail ui` version label** — showed stale "NOT in v0.1.0-alpha
  release" text; now displays the actual binary version

## v0.2.3 — 2026-06-23

Changelog shown during install/update, so users see what shipped at a glance.

### Added

- **Install-time changelog** — `curl | sh` installer now displays a compact
  "What's new" section with unicode-formatted bullet points extracted from the
  GitHub release notes
- **Update-time changelog** — `agentjail update` shows the same "What's new"
  section after a successful self-update, using the release body from the
  `/v1/latest` API
- **Releases Worker changelog field** — `/v1/latest` API response includes
  the release body so both the installer and the update command can display it
  without an extra network call

### Changed

- **Update confirmation** — `agentjail update` now accepts Enter to proceed
  (previously required typing 'y'); the stricter confirmation remains for
  `policy disable` and `mcp allow/block`
- **CHANGELOG.md backfill** — added entries for v0.2.0, v0.2.1, and v0.2.2

## v0.2.2 — 2026-06-23

Reduced daemon memory usage and safer self-update behaviour.

### Added

- **Cross-process update lock** — a file-based lock prevents concurrent update
  attempts across multiple daemon instances or rapid restarts from racing each
  other during a self-update

### Fixed

- **SQLite memory footprint** — reduced per-connection cache and WAL settings so
  the daemon consumes significantly less resident memory under normal operation
- **daemon.log fallback** — when the SQLite store is unavailable, log queries
  fall back to `daemon.log` and emit a clear warning instead of silently
  returning empty results

## v0.2.1 — 2026-06-23

Web UI polish: live version display, session tracking, and layout fixes.

### Fixed

- **Dynamic version display** — the UI header now shows the running daemon
  version rather than a hardcoded placeholder
- **Cache-busting** — static assets include a version-derived query string so
  browsers pick up UI changes after a daemon upgrade without a manual cache clear
- **CWD display** — the current working directory is shown correctly in session
  context panels
- **Active session count** — the session list now reflects only currently active
  sessions rather than all historical sessions

## v0.2.0 — 2026-06-22

Layered self-protection, enriched Bash policy input, OS notifications for
pending updates, and a hook-config watchdog for self-healing.

### Added

- **Self-update package** — `internal/selfupdate` centralises version-check
  logic; the CLI and daemon both use it, and a background goroutine in the daemon
  fires OS-native notifications when a new release is available
- **OS notification package** — `internal/notify` delivers desktop alerts on
  macOS and Linux without a GUI dependency
- **Structured Bash input** — the daemon enriches every Bash `PreToolUse` event
  with `command_binaries` (a parsed list of the distinct executables in the
  command) via `internal/shellparse`, giving Rego policies fine-grained access to
  what will actually run
- **Layered self-protection** (ADR 0025) — policy evaluation now uses structured
  input to enforce agentjail's own protection rules in multiple independent
  layers, closing gaps that string-only matching left open
- **Shield hook-config protection** — `agentjail-shield` now blocks agent writes
  to hook-configuration directories, preventing an agent from removing its own
  guardrails through the filesystem
- **Hook-config watchdog** — the daemon monitors hook-config directories and
  automatically restores any entry that an agent removes, giving the installation
  self-healing capability
- **Shared 24-hour daemon ID** — telemetry heartbeats carry a stable 24-hour
  rotating daemon identifier and a `source` field so server-side analytics can
  distinguish CLI-initiated checks from daemon background checks

### Fixed

- **Heartbeat on every version check** — the daemon now emits a telemetry
  heartbeat on each scheduled version check, not only at startup

## v0.1.2 — 2026-06-20

SQLite decision store, AWS policy pack, shield hardening, web UI with
server-side filters, and E2E test infrastructure.

### Added

- **SQLite decision store** — WAL-mode event store at `~/.agentjail/agentjail.db`
  with redaction, retention cleanup, concurrent reader/writer support, and indexes
  on session_id, ts, action, tool_name, rule_id
- **ReadOnlyStore** — separate read-only connection type (`sqliteROStore`) for UI,
  logs, and replay; no write methods leak even via type assertion
- **AWS policy pack** — `no_aws_destructive.rego` library rule (deny destructive,
  ask mutating); per-account posture config (sandbox/prod/locked/custom);
  `policy-aws.yaml` sample template
- **Replay CLI** — `agentjail replay --session <id> --list --verbose --follow`
  with formatted output and column headers
- **Shield hardening** — env-stripping at launch (configurable blocklist),
  environment audit (root/ambient creds/IMDS detection), Landlock network rules
  with `runtime.LockOSThread()` preservation, `agentjail-netproxy` for per-host
  egress on Linux
- **Secrets broker** — `agentjail-secrets` binary (AES-256-GCM at rest, Unix
  socket RPC, AWS/PG/Redis backends); shield calls grant/revoke for scoped env
  var injection
- **Web UI** — `agentjail ui` local replay viewer with SQLite backend, server-side
  filters (action/tool/rule/limit query params), resizable panes and columns,
  agent logos (Claude/Cursor/Codex/OpenCode), collapsible audit section, branded
  header with GitHub star/issue links
- **Server-side filters** — `/api/state` and `/api/session` accept `?action=`,
  `?tool=`, `?rule=`, `?limit=` query params; counters remain global while events
  are filtered; `FilteredCount` and `TotalDecisions` in response
- **E2E test** — `make e2e` runs a 20-assertion new-user test script covering
  build, daemon, hook decisions, SQLite store, replay, UI API, filters, try, and
  SIGHUP reload; CI job on ubuntu-latest + macos-14

### Fixed

- AfterID keyset cursor for DESC pagination (`id < ?` not `id > ?`)
- Session filter uses substring match (INSTR) consistently across SQLite and
  daemon.log modes
- UI connection pooling — one shared SQLite handle instead of per-request open
- sqliteSnapshot over-fetch — SQL aggregate for counters, LIMIT for display
- DSN path URL-encoding for paths with `?`, `#`, `%`
- SSE "connecting..." stuck — flush `:ok` comment on connect
- Limit clamping (default 100, max 10000) on all queries
- SQLite fallthrough to daemon.log now logs a warning

### Security

- ADRs 0020-0024: environment audit, Landlock network, netproxy, secret server,
  env-stripping at launch

## v0.1.1 — 2026-06-15

Plugin MCP discovery, log rotation, and brew telemetry fix.

### Added

- MCP plugin discovery — `agentjail install` now auto-whitelists Claude Code
  plugin MCP servers from `~/.claude/plugins/`
- Built-in log rotation — daemon manages its own log (10 MB, 5 backups) instead
  of relying on launchd `StandardErrorPath`

### Fixed

- Brew install telemetry — formula now sets `AGENTJAIL_INSTALL_METHOD=brew`

## v0.1.0 — 2026-06-02

First public release. Hook-based policy guardrails evaluate every coding-agent
tool call locally — before it runs — across Claude Code, Codex, and Cursor. One
install discovers and wires every supported agent on the machine, backed by a
local OPA/Rego policy daemon, an OS-native sandbox, and a styled terminal UI.

### Added

- **Multi-agent support** — `internal/agents` registry with per-agent hook wiring;
  Claude Code path plus an `agentjail-hook --agent=cursor` adapter, with structured
  fail-open markers
- **Agent auto-discovery** — install detects and wires every supported agent on the
  machine, including inside the `curl | sh` one-liner; an interactive multi-select
  picker (over `/dev/tty`) chooses which agents to protect when several are present
- **`agentjail-hook`** — stdin/stdout bridge to the daemon; reads PreToolUse JSON,
  dials the per-session Unix socket (30 ms timeout), translates `allow/deny/ask` →
  exit code; fails-open when the daemon is absent
- **`agentjail-daemon`** — long-running OPA evaluator on a Unix socket; SIGHUP
  hot-reload; LRU cache with a static/dynamic split; p95 < 5 ms warm. Projects the
  loaded `policy.yaml` into OPA as `data.agentjail.config` (merged over defaults),
  canonicalizes request paths + `cwd`, and keeps the last-good policy on failure
- **`agentjail install` / `status` / `uninstall` / `version` / `help`** — install
  copies binaries, writes the launchd plist, and merges the PreToolUse hook entry
  idempotently; `~/.agentjail/bin` is added to PATH automatically
- **Policy packs** — `file_policy.rego` (sensitive-path denies: `~/.ssh`, `~/.aws`,
  `~/.gnupg`, `.env`, `*.pem`/`*.key`/`*.p12`, …; allow for the project CWD;
  default-ask for unknown), `command_policy.rego` (dangerous-shell guards:
  `curl|bash`, `sudo`, `rm -rf`, `git push --force`, `dd if=/dev/`, …), and
  `mcp_policy.rego` (server allowlist + per-tool gating)
- **`agentjail policy list/enable/disable`** plus a **user-tunable surface** —
  `agentjail policy add/remove` custom rules with an audit log of every change, and a
  locked self-protection set the agent can't disable
- **6 opt-in hardening library rules** (`agentjail policy enable <name>`):
  `no-shell-init-write`, `no-hook-self-disable`, `no-app-binary-write`,
  `no-launchctl`, `no-history-read`, `no-shell-eval`
- **`agentjail mcp allow/block/list`** + **trust-on-install** — discovers the MCP
  servers already configured in Claude (`~/.claude.json`), Codex
  (`~/.codex/config.toml`), and Cursor (`~/.cursor/mcp.json`) and seeds the allowlist
  so an existing setup keeps working instead of being denied on first run; each
  mutation hot-reloads the daemon
- **`agentjail-shield`** — OS-native sandbox wrapping the agent in `sandbox-exec`
  (macOS) or Landlock (Linux) for kernel-level file-access enforcement; fails-open
  when `sandbox-exec` is absent
- **`agentjail-netproxy`** — localhost HTTPS forward proxy enforcing
  `network.allowed_hosts` via CONNECT; wildcard matching; SIGHUP reload; stdlib only
- **`agentjail try`** — hands-on, live policy-evaluation walkthrough
- **`agentjail logs`** — color-coded real-time decision stream; follow mode; filters
  by action/tool/since; latency and impact display
- **Styled terminal UI** — `internal/ui` Lip Gloss layer across install, status,
  uninstall, version, help, and `agentjail logs`; palette matches the agentjail.io site
- **Resolver pattern** — `resolver.rego` defines the single complete `decision` rule
  and picks the most-restrictive `candidate` (deny > ask > allow); default-ask when no
  candidate fires, eliminating rule-conflict errors
- **`PolicyConfig`** — `~/.agentjail/policy.yaml` schema with `mcp`, `file`,
  `command`, and `network` sections; validated on startup; SIGHUP hot-reload
- **Samples + harness** — 5 example policies and 3 example configs (all
  dogfood-tested), and a hook → daemon → policy e2e smoke harness with latency in CI
- **Anonymous telemetry** — opt-out usage statistics (OS/arch, version, CLI command
  counts, aggregated decision/perf rollups with enum rule IDs) to guide what we
  improve. No paths, commands, repo names, or policy contents are ever sent; data is
  tied to a random ID. Off in CI; disable with `agentjail telemetry disable` or
  `AGENTJAIL_SEND_ANONYMOUS_USAGE_STATS=false`. `agentjail telemetry view` shows
  exactly what's queued. Full data contract in `docs/TELEMETRY.md`

### Security

- **Always-on `no-daemon-kill` and `no-hook-self-disable` core rules** — an agent
  cannot kill the policy daemon or disable its own hook to escape enforcement
- **Credential-store read denies** — reads of `~/.npmrc`, `~/.pypirc`,
  `~/.git-credentials`, `~/.docker/config.json`, `~/.kube/config`,
  `~/.cargo/credentials`, and keychains are denied (home-anchored, so project-local
  copies stay allowed); mirrored into `agentjail-shield`
- **`confirm-publish` guard** — `npm`/`yarn`/`pnpm publish`, `gem push`,
  `poetry publish`, `docker push`, and `gh release create` prompt before running
- **Identity bound in the parent process** before the agent forks
  (`principal.id`/`agent`/`user`/`cwd_repo`/`enforce`), preventing child-process
  identity spoofing

### Known limitations (planned for v0.2.0)

- Credential broker not yet integrated — ADR 0004 sketches the design
- MCP reverse proxy is design-only — ADR 0003
- Linux network-egress control requires eBPF / Landlock's network ABI (Linux 6.7+)
- microVM isolation — libkrun + Firecracker integration are spike-complete but not
  yet wired into the `agentjail-shield` dispatch path

### License

Apache-2.0.
