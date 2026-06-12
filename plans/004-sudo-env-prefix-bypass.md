# Plan 004: Close the env-var-prefix `sudo` bypass in `command_policy`

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**:
> `git diff --stat 11129c5..HEAD -- agentpolicy/policies/command_policy.rego cmd/agentjail/policies/command_policy.rego`
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

`command_policy/no-sudo` is a core rule that denies privilege escalation. It has
two clauses: a chained-command regex (`(^|;|&&|\|\|)\s*sudo\s+`) and a
first-token check (`startswith(trim_space(cmd), "sudo ")`). Neither matches the
common **environment-variable-prefix** form, where one or more `KEY=value`
assignments precede `sudo`:

```
SUDO_ASKPASS=/tmp/x sudo -A some-command
PATH=/evil:$PATH sudo cmd
```

The command starts with `SUDO_ASKPASS=…`, not `sudo`, and there is no leading
`;`/`&&`/`||`, so the chained regex's `^` alternative sees the env assignment,
not `sudo`. The deny does not fire and the escalation is allowed. This plan adds
one clause that matches a leading run of `KEY=value` assignments followed by
`sudo`.

## Current state

Policy is **mirrored**: source `agentpolicy/policies/command_policy.rego` and
embed copy `cmd/agentjail/policies/command_policy.rego`, kept byte-identical by
`TestCoreFileParity` in `cmd/agentjail/embed_parity_test.go` — **edit both**.

The two existing sudo clauses (`agentpolicy/policies/command_policy.rego`, lines
62–84), verbatim:

```rego
# sudo — privilege escalation via operator or chained command.
candidate contains r if {
	is_bash
	regex.match(`(^|;|&&|\|\|)\s*sudo\s+`, cmd)
	r := {
		"action":  "deny",
		"rule_id": "command_policy/no-sudo",
		"reason":  "agents must not escalate privileges via sudo",
		"impact":  "would escalate to root",
	}
}

# sudo as the first token (most common form).
candidate contains r if {
	is_bash
	startswith(trim_space(cmd), "sudo ")
	r := {
		"action":  "deny",
		"rule_id": "command_policy/no-sudo",
		"reason":  "agents must not escalate privileges via sudo",
		"impact":  "would escalate to root",
	}
}
```

`is_bash` and `cmd` are defined earlier in the file (the same predicates the
other command rules use). OPA candidates are a set, so adding a third
`candidate contains r if { … }` clause with the **same `r` object** is safe —
duplicate candidates collapse; no `eval_conflict`.

There is an existing `test_sudo_deny` in
`agentpolicy/policies/command_policy_test.rego` (around line 54) you will model
new cases on.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Run Rego tests | `opa test agentpolicy/policies/` | `PASS: N/N` (rises with new tests) |
| Mirror parity | `go test ./cmd/agentjail/ -run TestCoreFileParity` | PASS |
| Full Go test | `go test ./... -race` | all pass |

## Scope

**In scope**:
- `agentpolicy/policies/command_policy.rego` and mirror `cmd/agentjail/policies/command_policy.rego`
- `agentpolicy/policies/command_policy_test.rego` (add cases)

**Out of scope** (do NOT touch):
- The two existing sudo clauses — add a third; do not rewrite the existing two.
- Any other command pattern (rm -rf, curl|bash, etc.) or any other `.rego` file.
- The `contains_sensitive_path` block (that is plan 002's territory).

## Git workflow

- Branch: `advisor/004-sudo-env-prefix-bypass`
- Conventional Commits with sign-off (`git commit -s`). Suggested:
  `fix(policy): deny env-var-prefixed sudo (VAR=val sudo ...)`.
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Add the env-prefix sudo clause (source)

In `agentpolicy/policies/command_policy.rego`, immediately after the existing
"sudo as the first token" clause (after line 84), add a third clause:

```rego
# sudo preceded by one or more KEY=value environment-variable assignments,
# e.g. `SUDO_ASKPASS=/tmp/x sudo -A cmd` or `PATH=/evil:$PATH sudo cmd`.
# The first two clauses miss this because the command does not *start* with
# `sudo` and has no leading ; && || separator.
candidate contains r if {
	is_bash
	regex.match(`(^|;|&&|\|\|)\s*([A-Za-z_][A-Za-z0-9_]*=\S*\s+)+sudo(\s|$)`, cmd)
	r := {
		"action":  "deny",
		"rule_id": "command_policy/no-sudo",
		"reason":  "agents must not escalate privileges via sudo",
		"impact":  "would escalate to root",
	}
}
```

The pattern: an optional statement boundary, then one-or-more `KEY=value`
assignment tokens (`[A-Za-z_][A-Za-z0-9_]*=\S*` followed by whitespace),
then `sudo` at a word/end boundary. Use the **identical** `r` object as the
other two clauses so the candidate set collapses cleanly.

**Verify**: `opa test agentpolicy/policies/` → `PASS`.

### Step 2: Mirror into the embed copy

`cp agentpolicy/policies/command_policy.rego cmd/agentjail/policies/command_policy.rego`

**Verify**: `go test ./cmd/agentjail/ -run TestCoreFileParity` → PASS.

### Step 3: Add tests

In `agentpolicy/policies/command_policy_test.rego`, add cases modeled on the
existing `test_sudo_deny`. The builder is `bash_input(cmd)` (defined at the top
of that file). Add:

```rego
# env-var-prefix sudo bypass (the fix) — must deny.
test_sudo_env_askpass_prefix_deny if {
	agentjail.decision.action == "deny" with input as bash_input("SUDO_ASKPASS=/tmp/x sudo -A whoami")
	agentjail.decision.rule_id == "command_policy/no-sudo" with input as bash_input("SUDO_ASKPASS=/tmp/x sudo -A whoami")
}

test_sudo_env_path_prefix_deny if {
	agentjail.decision.action == "deny" with input as bash_input("PATH=/evil:$PATH sudo cat /etc/shadow")
	agentjail.decision.rule_id == "command_policy/no-sudo" with input as bash_input("PATH=/evil:$PATH sudo cat /etc/shadow")
}

test_sudo_multi_env_prefix_deny if {
	agentjail.decision.action == "deny" with input as bash_input("A=1 B=2 sudo id")
}

# A normal KEY=value assignment WITHOUT sudo must NOT trigger no-sudo.
test_env_assignment_without_sudo_not_sudo_denied if {
	agentjail.decision.rule_id != "command_policy/no-sudo" with input as bash_input("FOO=bar echo hello")
}
```

Match the exact assertion style of the existing `test_sudo_deny` case — if it
asserts the full verdict object rather than `.action`/`.rule_id` fields,
follow that form instead, keeping the same expected `rule_id` and `action`.

**Verify**: `opa test agentpolicy/policies/ -r '.*sudo.*'` → all sudo cases pass,
including the three new deny cases and the negative case. Confirm
`test_sudo_env_askpass_prefix_deny` passes (it would FAIL before Step 1).

### Step 4: Full suite

**Verify**: `opa test agentpolicy/policies/` → `PASS: N/N` (N up); `go test
./... -race` → all pass.

## Test plan

- New cases in `agentpolicy/policies/command_policy_test.rego`: single env-prefix
  sudo, `PATH=`-prefix sudo, multi-assignment prefix sudo (all deny), and one
  negative (env assignment without sudo must not be sudo-denied).
- Pattern source: the existing `test_sudo_deny` in the same file.
- Verification: `opa test agentpolicy/policies/` all green including new cases.

## Done criteria

ALL must hold:

- [ ] A third `command_policy/no-sudo` clause exists in `agentpolicy/policies/command_policy.rego` matching the env-prefix pattern
- [ ] `test_sudo_env_askpass_prefix_deny` exists and passes
- [ ] `test_env_assignment_without_sudo_not_sudo_denied` passes (no false positive)
- [ ] `opa test agentpolicy/policies/` reports `PASS: N/N`, N greater than before
- [ ] `diff agentpolicy/policies/command_policy.rego cmd/agentjail/policies/command_policy.rego` → no output
- [ ] `go test ./... -race` exits 0
- [ ] Only in-scope files modified (`git status`)
- [ ] `plans/README.md` status row for 004 updated

## STOP conditions

Stop and report back (do not improvise) if:

- `command_policy.rego` does not match the "Current state" excerpt (drift).
- `test_sudo_env_askpass_prefix_deny` still FAILS after Step 1 (regex not
  matching as expected — report the behavior).
- `test_env_assignment_without_sudo_not_sudo_denied` FAILS (the pattern is
  over-matching benign `KEY=val cmd` lines — the `sudo` token requirement should
  prevent this; report the failing input).
- Adding the third clause causes an OPA compile error (`eval_conflict` or
  similar) — it should not, since the `r` object is identical to the other
  clauses; report the exact error.

## Maintenance notes

- The pattern intentionally requires the env assignment(s) to be **immediately
  followed by `sudo`**. Forms like `export SUDO_ASKPASS=x; sudo cmd` are already
  covered by the existing chained-command clause (the `;` boundary). A reviewer
  should confirm the new clause doesn't fire on legitimate `VAR=val program`
  invocations that merely *mention* sudo later in an argument — the `(\s|$)`
  boundary after `sudo` plus the assignment-run anchor keeps this tight.
- If future work normalizes commands before evaluation (tokenizing env prefixes
  out), these regex clauses could be simplified — note that as a possible
  consolidation.
