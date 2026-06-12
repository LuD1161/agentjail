# Plan 003: Close the newline-split bypass in the locked `no_daemon_kill` rule

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**:
> `git diff --stat 11129c5..HEAD -- agentpolicy/policies/no_daemon_kill.rego cmd/agentjail/policies/no_daemon_kill.rego`
> If either file changed since this plan was written, compare the "Current
> state" excerpt against the live code before proceeding; on a mismatch,
> treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: S
- **Risk**: LOW
- **Depends on**: plans/001-opa-test-in-ci.md (soft — see plans/README.md)
- **Category**: security
- **Planned at**: commit `11129c5`, 2026-06-11

## Why this matters

`no_daemon_kill` is a **locked, always-on core rule** that blocks killing the
agentjail daemon — important because `agentjail-hook` **fails open**: if it
can't reach the daemon socket, it allows the call. So `pkill agentjail-daemon &&
rm -rf ~/important` would let the second command slip through the fail-open
window. The rule's two regexes use `[^\n]*` between the kill verb and the target
name. `[^\n]` explicitly excludes newlines, so a multi-line command — which
agents pass as a single `command` string with embedded `\n` — splits the match:

```
pkill -f
agentjail-daemon
```

does not match `\b(pkill|killall)\b[^\n]*agentjail-(daemon|…)`, so the rule does
not fire and the kill is allowed. This plan replaces `[^\n]*` with `[\s\S]*`
(match any character including newlines) so the rule catches the split form.

## Current state

The policy is **mirrored**: source `agentpolicy/policies/no_daemon_kill.rego`
and byte-identical embed copy `cmd/agentjail/policies/no_daemon_kill.rego`.
`cmd/agentjail/embed_parity_test.go` (`TestCoreFileParity`) fails if they
diverge — **edit both**.

`agentpolicy/policies/no_daemon_kill.rego`, the two match predicates (lines
60–67), verbatim:

```rego
_kills_agentjail if {
	regex.match(`\b(pkill|killall)\b[^\n]*agentjail-(daemon|hook|shield|netproxy)`, _cmd)
}

# launchctl stop|kill of the daemon label (bootout/unload/remove are core-covered).
_kills_agentjail if {
	regex.match(`\blaunchctl\s+(stop|kill)\b[^\n]*com\.agentjail`, _cmd)
}
```

OPA uses RE2, where `.` does not match `\n` by default and there is no inline
`(?s)` DOTALL convenience needed — `[\s\S]` is the portable "any char including
newline" class and is the idiom already implied by the codebase's use of
explicit classes.

There is currently **no** `no_daemon_kill_test.rego` in
`agentpolicy/policies/`. You will create one.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Run Rego tests | `opa test agentpolicy/policies/` | `PASS: N/N` (N rises with your new tests) |
| Run just this rule's tests | `opa test agentpolicy/policies/ -r '.*daemon_kill.*'` | new tests pass |
| Mirror parity | `go test ./cmd/agentjail/ -run TestCoreFileParity` | PASS |
| Full Go test | `go test ./... -race` | all pass |

## Scope

**In scope**:
- `agentpolicy/policies/no_daemon_kill.rego` and mirror `cmd/agentjail/policies/no_daemon_kill.rego`
- `agentpolicy/policies/no_daemon_kill_test.rego` (create)

**Out of scope** (do NOT touch):
- Any other `.rego` rule. The `kill <pid>` (numeric-PID) gap noted in the rule's
  own comment (line 32) is a *separate, harder* problem — do NOT attempt to block
  `ps`/`pgrep`/numeric `kill` here; it risks blocking legitimate diagnostics and
  needs its own design.
- `resolver.rego` and the locked-rules set — the rule is already locked; you are
  only fixing its match pattern.

## Git workflow

- Branch: `advisor/003-no-daemon-kill-newline-bypass`
- Conventional Commits with sign-off (`git commit -s`). Example from `git log`:
  `feat(policy): make git force-push branch-aware`. Suggested message:
  `fix(policy): match newline-split daemon-kill commands in no_daemon_kill`.
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Replace `[^\n]*` with `[\s\S]*` in both predicates (source)

In `agentpolicy/policies/no_daemon_kill.rego`:
- Line 61: `\b(pkill|killall)\b[^\n]*agentjail-(daemon|hook|shield|netproxy)` →
  `\b(pkill|killall)\b[\s\S]*agentjail-(daemon|hook|shield|netproxy)`
- Line 66: `\blaunchctl\s+(stop|kill)\b[^\n]*com\.agentjail` →
  `\blaunchctl\s+(stop|kill)\b[\s\S]*com\.agentjail`

Change nothing else.

**Verify**: `opa test agentpolicy/policies/` → `PASS` (existing tests, if any
reference this rule via `resolver_test.rego`, still pass).

### Step 2: Mirror into the embed copy

`cp agentpolicy/policies/no_daemon_kill.rego cmd/agentjail/policies/no_daemon_kill.rego`

**Verify**: `go test ./cmd/agentjail/ -run TestCoreFileParity` → PASS.

### Step 3: Create `no_daemon_kill_test.rego`

Create `agentpolicy/policies/no_daemon_kill_test.rego`. The rule emits its
verdict through `agentjail.decision` (the resolver aggregates candidates), with
`rule_id == "library/no-daemon-kill"` (the prefix is cosmetic — see the file's
header comment) and `action == "deny"`. Model the test on the structure of
`agentpolicy/policies/command_policy_test.rego` (same `bash_input` builder
shape). Write at minimum:

```rego
package agentjail_no_daemon_kill_test

import future.keywords.if
import data.agentjail

bash_input(cmd) := {
	"hook_event": "PreToolUse",
	"tool_name":  "Bash",
	"tool_input": {"command": cmd, "description": ""},
	"session_id": "test-session",
	"cwd":        "/Users/dev/project",
}

# Single-line form still denies (regression guard for the existing behavior).
test_pkill_single_line_deny if {
	d := agentjail.decision with input as bash_input("pkill -f agentjail-daemon")
	d.action == "deny"
	d.rule_id == "library/no-daemon-kill"
}

# THE BUG: newline-split form must now deny.
test_pkill_newline_split_deny if {
	d := agentjail.decision with input as bash_input("pkill -f\nagentjail-daemon")
	d.action == "deny"
	d.rule_id == "library/no-daemon-kill"
}

test_killall_newline_split_deny if {
	d := agentjail.decision with input as bash_input("killall\nagentjail-hook")
	d.action == "deny"
	d.rule_id == "library/no-daemon-kill"
}

test_launchctl_newline_split_deny if {
	d := agentjail.decision with input as bash_input("launchctl stop\ncom.agentjail.daemon")
	d.action == "deny"
	d.rule_id == "library/no-daemon-kill"
}

# A benign pkill of an unrelated process must NOT be denied by this rule.
test_unrelated_pkill_not_denied_by_this_rule if {
	d := agentjail.decision with input as bash_input("pkill -f my-dev-server")
	d.rule_id != "library/no-daemon-kill"
}
```

If `agentjail.decision`'s exact shape differs from the assumption above (e.g.
the resolver returns a set, or `decision` is undefined when no candidate fires),
inspect `agentpolicy/policies/resolver.rego` and `resolver_test.rego` to see how
existing tests read the aggregated verdict, and match that access pattern — the
key assertions to preserve are `action == "deny"` and `rule_id ==
"library/no-daemon-kill"` for the deny cases.

**Verify**: `opa test agentpolicy/policies/ -r '.*daemon_kill.*'` → all your new
cases pass. Critically, confirm `test_pkill_newline_split_deny` passes (it would
have FAILED before Step 1 — that is the proof the bypass is closed).

### Step 4: Full suite

**Verify**:
- `opa test agentpolicy/policies/` → `PASS: N/N`, N > previous count.
- `go test ./... -race` → all pass.

## Test plan

- New file `agentpolicy/policies/no_daemon_kill_test.rego` with the cases above:
  single-line deny (regression guard), newline-split `pkill`/`killall`/`launchctl`
  deny (the fix), and a benign-pkill negative case.
- Pattern source: `agentpolicy/policies/command_policy_test.rego` for the input
  builder and assertion style; `resolver_test.rego` if you need the exact
  `decision` access shape.
- Verification: `opa test agentpolicy/policies/` all green including new cases.

## Done criteria

ALL must hold:

- [ ] `grep -c '\[\^\\n\]' agentpolicy/policies/no_daemon_kill.rego` returns `0` (no `[^\n]` left)
- [ ] `grep -c '\[\\s\\S\]' agentpolicy/policies/no_daemon_kill.rego` returns `2`
- [ ] `agentpolicy/policies/no_daemon_kill_test.rego` exists and `test_pkill_newline_split_deny` passes
- [ ] `opa test agentpolicy/policies/` reports `PASS: N/N`, N greater than before
- [ ] `diff agentpolicy/policies/no_daemon_kill.rego cmd/agentjail/policies/no_daemon_kill.rego` → no output
- [ ] `go test ./... -race` exits 0
- [ ] Only in-scope files modified (`git status`)
- [ ] `plans/README.md` status row for 003 updated

## STOP conditions

Stop and report back (do not improvise) if:

- `no_daemon_kill.rego` does not match the "Current state" excerpt (drift).
- `test_pkill_newline_split_deny` still FAILS after Step 1 (the fix did not take
  — possibly the regex is matched differently than assumed; report the live
  pattern).
- `agentjail.decision` cannot be read the way the test assumes and
  `resolver_test.rego` uses a materially different access pattern you can't map
  cleanly — report what `resolver_test.rego` does.

## Maintenance notes

- The `kill <numeric-pid>` daemon-kill vector remains open by design (see the
  rule comment at line 32). It is genuinely hard to block without false
  positives and is mitigated (not closed) by launchd `KeepAlive` respawn on
  macOS. If a maintainer wants to close it, that is a separate plan and likely
  needs a structural approach (e.g. correlating `pgrep agentjail` + `kill` in one
  command chain), not another regex here.
- A reviewer should confirm `[\s\S]*` did not make the pattern match unintended
  inputs — it still requires both the kill verb AND the `agentjail-` target to be
  present, just no longer on the same line, so over-matching risk is low.
