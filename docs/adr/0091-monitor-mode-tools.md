# 0091 — Monitor mode for tool calls

Status: Accepted

## Context

AgentJail enforces or it does nothing. There is no way to answer "what would
this block if I turned it on?" — the classic WAF/IDS land-and-expand on-ramp,
and the most requested shape of adoption: *run it log-only for a day, see what
it would have caught, then choose what to enforce.*

This is axis 1 of 3 (AGE-242, split from AGE-209). The network axis (AGE-243)
needs TLS visibility and is blocked on the tunnel; the filesystem axis
(AGE-244) cannot be done this way at all — Landlock and Seatbelt are
kernel-enforced, so there is no evaluate-then-decide step to shadow. Only the
tool-call axis has a userspace seam, and it is on `main`.

## Decision

Add `enforcement: enforce | monitor` to policy.yaml. Monitor evaluates the full
policy set and records every verdict, but acts on none.

### The seam is daemon-side

AGE-209 framed this as "the hook layer". That is wrong twice over. The hook
does not evaluate policy — it RPCs the daemon (`cmd/agentjail-hook/main.go`),
and the only hook-side matching is the daemon-unreachable sidecar. More
importantly, the decision row is written **daemon-side** from the verdict, so a
hook-side downgrade would persist `action='deny'` for a tool call that actually
ran. That is the AGE-212 bug class: the record claiming an enforcement that
never happened.

The cut is in `internal/daemonapp`, between `evaluator.Eval` and the response
encode — the daemon already owns config resolution, the wire response, and
persistence, so one place controls all three. It is applied before telemetry
and persistence so every downstream consumer sees what happened, not what
policy wanted.

Not inside `policyeval.Eval`: its decision cache is keyed on input only, so
flipping the mode there would poison cached entries across a reload boundary.

### `action` is what happened; `would_action` is what policy said

`decisions.would_action` (new column) carries the declined verdict; empty means
it matched `action`. **`action` is always what was actually enforced.**

The alternative — keep `action='deny'` and add an `enforced` flag — was
rejected. A reader of the decisions table would see `deny` on a call that ran,
with no way to tell otherwise. `action` must never overstate enforcement.
Existing rows read back with an empty `would_action`, which is truthful: their
verdicts were enforced.

`CREATE TABLE IF NOT EXISTS` is a no-op on a database that predates a column,
so the `ALTER` is separate and guarded on `pragma_table_info` — the first
additive column migration in this store.

### No new action value

The action vocabulary is a bare `string` at every layer, and the hook's
enforcement switches have a `default:` that means *allow*. A `"monitor"` action
would silently fall through it, unchecked. Monitor is therefore a **mode**, not
an action: it downgrades to `allow` and records the original elsewhere. (A
typed `Action` enum is the correct fix — AGENTS.md and ADR 0035 both require it
— but it is a cross-cutting refactor and is not in scope here.)

### Monitor mode cannot be turned on by a project

`Enforcement` is resolved in `Merge` (the global config path) and deliberately
absent from `MergeProjectOverlay`. A project's `.agentjail/policy.yaml` lives in
the repo **the agent can write**; honouring it there would hand the agent an off
switch for its own guardrail. The global `~/.agentjail/policy.yaml` is granted
read-only by the shield (`shield_agentpaths.go`, invariant 0) and protected by
the locked rule `command_policy/no-policy-mutation`. Guarded by a test.

### The unenforced window is auditable

Entering or leaving monitor mode emits `enforcement.mode_changed`. Monitor mode
means nothing is enforced, and a table full of `allow` rows cannot explain
itself — the window has to be reconstructable from the audit log alone. That is
the AGE-212 lesson applied forward.

The mode is an atomic read on the hot path, rewritten only after a successful
engine swap: a failed reload keeps serving the old engine, so it keeps the old
mode with it.

### The agent is told

The declined verdict is rendered on all three agent paths via `systemMessage`
(Claude), Codex `systemMessage`, and Cursor `user_message` — never stderr, which
Claude Code discards on exit 0, and which is exactly how the fail-open banner
stayed invisible for three days (ADR 0073). An allowed call under monitor mode
is otherwise indistinguishable from a clean run.

## Consequences

- The land-and-expand on-ramp exists, on `main`, with no tunnel dependency.
- **Monitor mode means the guardrail is off.** It is opt-in, warned at startup,
  audited on entry, and announced on every affected tool call. A default that
  silently stopped enforcing would be AGE-212 shipped as a feature.
- Verified end-to-end on Linux: the same `Read ~/.ssh/id_rsa` exits 2 under
  `enforce` and exits 0 under `monitor` with the notice naming
  `file_policy/sensitive_credential`; SIGHUP flips the mode without a restart;
  the row reads `action=allow, would_action=deny`; an ordinary allow is not
  marked; `enforcement.mode_changed` records the window.
- The report's value is capped by policy coverage. A thin ruleset flags nothing
  and looks identical to a clean run, so `agentjail monitor` says which of the
  two an empty report is.
- `ReadOnlyStore` grows `CountWouldBlock`. Aggregating over `ListDecisions`
  would have been silently truncated by its clamped limit.
- The daemon-unreachable axis is untouched and remains independent: monitor mode
  governs the daemon-*reachable* path only.
