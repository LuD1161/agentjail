# Changelog

Pre-1.0; `main` is the live branch. Significant ships only — see `git log` for the full picture. Format roughly follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and dates are ISO-8601.

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
