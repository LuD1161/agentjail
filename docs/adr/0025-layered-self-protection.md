# ADR 0025 — Layered self-protection model

- **Status:** Accepted
- **Date:** 2026-06-21
- **Deciders:** agentjail-core
- **Related:** [ADR 0001](0001-os-sandbox-enforcement-layer.md) (OS sandbox), [ADR 0014](0014-user-tunable-policy-surface.md) (user-tunable policy surface), [ADR 0016](0016-tier2-microsandbox-substrate.md) (Tier 2 microsandbox)

## Context

agentjail's self-protection mechanism — preventing an agent from disabling its
own guardrails — was primarily implemented via regex pattern matching on Bash
command strings (`command_policy/no-policy-mutation`, `library/no-hook-self-disable`,
`library/no-daemon-kill`). This produced three classes of problems.

**False positives** blocked legitimate work:
- `git add cmd/agentjail/update.go` was blocked because "agentjail" appeared
  in the path and "update" in the filename.
- `codex exec -s read-only "review agentjail policy"` was blocked because the
  prompt text contained mutation-looking keywords.
- Legitimate edits to agent config files (`~/.claude/settings.json`) were
  denied outright, forcing workarounds.

**False negatives** left real attacks unprotected:
- Interpreter-based writes (`python -c "import os; os.remove(os.path.expanduser('~/.agentjail/rules/command_policy.rego'))"`) bypass all regex rules entirely.
- Variable-expansion tricks, `eval`, and non-shell interpreters are invisible
  to command-string pattern matching.

**Design mismatch** with the enforcement layer below:
- The shield (Tier 1.5 — Seatbelt on macOS, Landlock on Linux) already
  provides kernel-level file protection for `~/.agentjail/`. The regex layer
  was carrying weight that a lower layer already handles better.
- EDR systems provide the design precedent: they enforce self-protection at the
  syscall/kernel level (minifilters, process protection callbacks), not via
  command-string pattern matching. Behavioral detection is a signals layer, not
  the enforcement boundary.

## Decision

Adopt a layered self-protection model where enforcement responsibility is
assigned to the lowest available tier, and each layer has a defined role.

### Layer 1 — Regex rules (UX and signals, Tier 1)

Regex rules remain valuable for their UX: they fire early, produce clear deny
messages that explain why ("you are trying to disable agentjail policy"), and
give the user actionable context. They are defense-in-depth and a detection
signal, not the primary enforcement guarantee.

Specific changes to reduce false positives:

- **`command_policy/no-policy-mutation`**: tightened. The broad `\bupdate\b`
  clause is replaced with `agentjail\s+update\b` (requires `agentjail` to
  appear as a command token, not merely as a path component). The sed/awk/perl
  in-place editing clause is removed — those paths are covered by the shield
  and the removal eliminates false positives without weakening real protection.

- **`library/no-hook-self-disable`**: Write/Edit tool calls targeting hook
  config files (`~/.claude/settings.json`, `~/.codex/hooks.json`, etc.) are
  downgraded from **deny** to **ask** — users can approve legitimate config
  edits. Bash-based writes to those files stay **deny** (there is no legitimate
  reason an agent needs raw shell access to hook config).

- **`library/no-daemon-kill`**: removed from the locked set. The daemon runs
  under launchd/systemd with `KeepAlive=true`, so a kill is a speed bump, not
  a permanent disable. The rule remains on by default but is disableable with
  `--force` for users who need it (e.g. a restart script).

### Layer 2 — Shield (enforcement, Tier 1.5)

The shield (Seatbelt on macOS, Landlock on Linux) is the enforcement layer for
filesystem-based self-protection attacks. It operates at the kernel boundary
and is immune to interpreter tricks, variable expansion, or non-shell
interpreters.

Current coverage:
- `~/.agentjail/` — write-denied by Landlock allowlist (not granted) and
  Seatbelt deny-write rule.

Planned additions (future work, tracked separately):
- Hook config files (`~/.claude/settings.json`, `~/.codex/hooks.json`,
  `~/.cursor/hooks.json`) — add to shield deny-write list.
- agentjail binary path — add to shield deny-write list.

### Layer 3 — Daemon watchdog (verify-and-heal, Tier 1, future work)

Rather than deny-all for hook config files (which blocks legitimate user
edits), the daemon watches those files via fsnotify/kqueue. On change: verify
the agentjail hook entry is still present. If removed: re-inject, write an
audit log entry, and notify the user. This replaces a blanket deny with a
verify-and-heal approach that permits legitimate edits while detecting and
reversing adversarial removals.

### Layer 4 — Tier 2 (structural, Tier 2)

When the agent runs in a microVM (Tier 2), self-protection becomes structural:
the agentjail binary, policies, and hook config files all live on the host, not
in the VM. The attack surface does not exist in the guest.

### Mutation surface analysis

| Vector | Tier 1 (regex) | Tier 1.5 (shield) | Tier 2 (VM) |
|---|---|---|---|
| `agentjail policy disable X` | deny (regex + TTY guard) | N/A | binary not in guest |
| Bash write to `~/.agentjail/` | deny (regex) | EPERM (kernel) | path doesn't exist |
| `python -c "os.remove(...)"` | UNPROTECTED | EPERM (kernel) | path doesn't exist |
| Kill daemon | deny (regex, unlockable) | daemon outside sandbox | daemon on host |
| Edit hook config (Write/Edit tool) | ask (user confirms) | future: EPERM | file on host |
| Edit hook config (Bash) | deny (regex) | future: EPERM | file on host |
| Replace agentjail binary | unprotected | shield denies app paths | binary on host |

## Consequences

**Positive:**
- False positives eliminated. `git add cmd/agentjail/update.go`, `codex exec`
  with policy-related prompt text, and `go build` in the agentjail repo all
  work without triggering self-protection rules.
- Users can legitimately edit agent config files (ask, not deny); agents
  cannot do so via raw Bash (deny stays).
- Defense-in-depth is clearer: each layer has a defined role and the
  responsibility boundary between them is explicit.
- Aligns with EDR industry practice: enforce at the point of effect (kernel),
  use behavioral detection (regex) as signals, not as the enforcement boundary.

**Negative:**
- Tier 1-only users lose some regex coverage: the sed/awk/perl in-place
  editing clause is removed, and `no-daemon-kill` is now unlockable. Users
  without the shield installed have a narrower regex net.
- Watchdog is future work. Until it lands, hook config edits rely on "ask"
  (user confirmation at the terminal) rather than verify-and-heal.
- Shield coverage of hook config files and the agentjail binary path is also
  future work. Until those paths are added to the shield deny list, the shield
  does not protect them.
- Shield adoption is opt-in; users must run `agentjail-shield` for kernel-level
  protection. The hook layer alone does not provide the same guarantee.

**Follow-ups:**
1. Implement daemon hook-config watchdog (fsnotify/kqueue watcher + re-injection
   on missing hook entry).
2. Add hook config files (`~/.claude/settings.json`, `~/.codex/hooks.json`,
   `~/.cursor/hooks.json`) and the agentjail binary path to shield deny-write
   rules.
3. Phase 2 (structured input from hook shim) — eliminates the need for
   command-string regex entirely for self-protection by making the hook shim
   parse structured tool inputs before they reach the shell.
