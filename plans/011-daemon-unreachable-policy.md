# Plan 011 — Configurable daemon-unreachable policy (fail-open → tiered)

Implements [ADR 0050](../docs/adr/0050-daemon-unreachable-policy.md). Updates the
AGE-115 fail-open stance into a tiered `allow | degraded | deny` knob, with a
daemon-written JSON sidecar so the stdlib-only hook can act on it, a loud
per-occurrence notice, and (later) daemon auto-recovery.

Default stays `allow` → **behavior-preserving on upgrade**. Ship phases
independently; each is green on its own.

## Phase 1 — Config knob + sidecar plumbing + loud notice + `deny`
*Goal: the knob exists end-to-end and `deny` works; `degraded` falls back to `deny`-with-allow-rest until Phase 2. No behavior change at the `allow` default.*

1. **Config** (`agentpolicy/config/config.go`)
   - Add `DaemonUnreachable DaemonUnreachableLevel `yaml:"daemon_unreachable"`` to `PolicyConfig`.
   - New named type `DaemonUnreachableLevel` (string enum: `allow`/`degraded`/`deny`); empty → `allow` (default). Validate at load (reject unknown values). Type-safe, no bare string.
2. **Wire** (`internal/wire/wire.go`)
   - `HookFallbackPath()` → `~/.agentjail/hook-fallback.json` (mirror the existing path helpers).
   - Shared typed `HookFallback` struct (`Version int`, `Level string`, `OfflineRules []OfflineRule`) + `OfflineRule` (kind + operands) so daemon and hook share one definition.
3. **Daemon writes the sidecar** (`cmd/agentjail-daemon`)
   - On startup (after listening) and on every SIGHUP reload, atomically write `hook-fallback.json` (temp + rename, 0600) from the current config's `DaemonUnreachable` level. Phase 1 writes `offline_rules: []` (populated in Phase 2).
   - Best-effort: a write failure logs + audits but never blocks daemon startup.
4. **Hook reads the sidecar on daemon-unreachable** (`cmd/agentjail-hook/main.go`)
   - New `loadHookFallback() (HookFallback, bool)` — stdlib `encoding/json`; missing/unparseable/`version != 1` → `allow` fallback.
   - Branch the existing fail-open path on `level`:
     - `allow` → current behavior.
     - `deny` → render the agent's deny convention with a restart-instruction reason.
     - `degraded` → Phase 1 stub = behave as `allow` (Phase 2 adds enforcement); still print the degraded banner.
5. **Loud notice** — replace the one-shot `failOpenFriendlyMessage` with a
   per-occurrence banner that names the level + restart command. Keep the
   `fail_open` telemetry on every occurrence. (The `fail-open-warned` sentinel
   can be retired for the banner, or repurposed to rate-limit to once per N.)
6. **Tests**
   - config: load/validate the enum (valid, invalid, default-empty).
   - wire: round-trip the struct through JSON.
   - daemon: sidecar written on startup with the configured level; atomic.
   - hook: table over `{allow, degraded(stub), deny, missing-sidecar}` → asserts allow/deny decision + banner text.
7. **Docs**: `default_policy.yaml` commented example (recommend `degraded`);
   README failure-behavior note; this ADR referenced.

**Acceptance:** with `daemon_unreachable: deny` and the daemon stopped, a tool
call is denied with restart instructions; with `allow` (or no setting), it's
allowed exactly as today; the banner is loud and per-call.

## Phase 2 — `degraded` offline enforcement (the locked-rule denylist)
*Goal: `degraded` actually enforces the crown-jewel rules offline.*

1. **Daemon compiles offline rules** from the locked-rule set into the sidecar:
   - `path_prefix_write` → home `~/.agentjail` (mirrors `file_policy/agentjail_self`).
   - `path_read` → `~/.agentjail/secrets.key`, `~/.agentjail/secrets/` (mirrors `file_policy/agentjail_secrets`).
   - `command_mutation` → agentjail policy-mutation signature (mirrors `command_policy/no-policy-mutation`).
   Keep the locked-rule list as the single source; the daemon translates it (do
   not re-hardcode in the hook).
2. **Hook enforces** offline rules with stdlib matching:
   - File tools: normalize the target path, compare against `path_prefix_write` /
     `path_read` operands (same tilde/$HOME expansion the policy layer uses).
   - Bash: parse with `internal/shellparse` (stdlib, P6-hardened) and match the
     `command_mutation` signature.
   - Match → deny with the offline rule's reason; no match → allow.
3. **Tests**: the C1/C2/P6 attack payloads (write `~/.agentjail/...`, read
   `secrets.key`, `sh -c 'agentjail policy disable ...'`) are **denied** by the
   hook with the daemon stopped and `degraded` set; benign calls allowed.

**Acceptance:** daemon down + `degraded` → the three locked-rule attack classes
are blocked offline; everything else proceeds; banner shows "REDUCED protection."

## Phase 3 — Daemon auto-recovery (shrinks the window)
*Goal: the daemon rarely stays down, so the level rarely matters.*

1. OS supervision: launchd `KeepAlive` (macOS) / systemd `Restart=always`
   (Linux) in the install-generated unit files. Ties into AGE-114.
2. Optional hook-triggered restart-and-retry: on connect failure, attempt one
   non-blocking `agentjail daemon restart` (or a socket-activation nudge) and
   retry once within budget before falling back to the sidecar level.
3. Tests / smoke: kill the daemon, confirm it comes back and the next hook call
   succeeds without hitting the fallback.

**Acceptance:** killing the daemon self-heals within ~1s; the fallback path is
exercised only when recovery genuinely fails.

## Rollout
- Phases land as separate PRs; default `allow` throughout, so no user-visible
  change until someone sets the knob.
- After Phase 2, update docs to recommend `degraded` and consider proposing it
  as the default in a future major (separate decision, not this plan).
