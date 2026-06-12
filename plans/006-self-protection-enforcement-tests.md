# Plan 006: Add enforcement-level tests for the locked self-protection rules

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**:
> `git diff --stat 11129c5..HEAD -- cmd/agentjail/policies_behavior_test.go`
> If the file changed since this plan was written, compare the "Current state"
> excerpts against the live code before proceeding; on a mismatch, treat it as
> a STOP condition.

## Status

- **Priority**: P2
- **Effort**: S
- **Risk**: LOW
- **Depends on**: plans/001-opa-test-in-ci.md (soft — see plans/README.md)
- **Category**: tests
- **Planned at**: commit `11129c5`, 2026-06-11

## Why this matters

The two rules guarding the highest-severity attack vector — `no_daemon_kill`
(killing the daemon opens the hook's fail-open window) and `no_hook_self_disable`
(an agent removing its own hook by writing to `~/.claude`/`~/.codex`/`~/.cursor`
settings) — are exercised at the Go/OPA-SDK enforcement level by **no test
case**. `cmd/agentjail/policies_behavior_test.go` (`TestMirrorPolicyDecisions`)
is exactly the right place: it loads all core mirror rules and evaluates real
`HookInput` through the OPA Go SDK, asserting the resulting action. It covers
file_policy, command_policy, and the no_destructive_git library rule — but has
**zero** cases for daemon-kill or hook-self-disable. A regex typo or a package-
conflict regression in either locked rule would pass CI silently. This plan adds
enforcement cases for both, so the daemon's actual decision pipeline is asserted
to deny these attacks.

## Current state

`cmd/agentjail/policies_behavior_test.go` loads every core rule from the embed
(`allCoreRuleBytes()` walks the whole `policies/` embed dir, so `no_daemon_kill`
and `no_hook_self_disable` **are** loaded into the test engine) plus the
`no_destructive_git` library rule, and queries `data.agentjail.decision`.

The test-case struct and existing cases (lines 82–175):

```go
	type testCase struct {
		name      string
		toolName  string
		toolInput map[string]interface{}
		want      string // exact "action" value; empty → use notDeny
		notDeny   bool   // when true, assert action != "deny"
	}

	const cwd = "/Users/dev/project"

	cases := []testCase{
		// ----- file_policy -----
		{
			name:      "Read sensitive ~/.npmrc → deny",
			toolName:  "Read",
			toolInput: map[string]interface{}{"path": "/Users/dev/.npmrc"},
			want:      "deny",
		},
		// ... more file_policy / command_policy / no_destructive_git cases ...
		{
			name:      "Bash sudo apt install → deny (core no-sudo)",
			toolName:  "Bash",
			toolInput: map[string]interface{}{"command": "sudo apt install x"},
			want:      "deny",
		},
		// ...
	}
```

Each case is evaluated through `evalDecision(t, pq, input)` which returns the
action string ("deny"/"ask"/"allow"), defaulting to "ask" when no candidate
fires. The input passed to the engine includes `hook_event: "PreToolUse"`,
`tool_name`, `tool_input`, `session_id`, and `cwd` — confirm the exact input
assembly by reading lines 177–230 of the same file (where `cases` are run);
match that assembly for the new cases (they go in the same `cases` slice, so
they are assembled identically — you only add struct literals).

Both target rules emit `action: "deny"`:
- `no_daemon_kill` — Bash command killing `agentjail-daemon`/`-hook`/`-shield`/
  `-netproxy` (`pkill`/`killall`) or `launchctl stop|kill com.agentjail.*`.
- `no_hook_self_disable` — Write/Edit to `~/.claude/settings*.json`,
  `~/.codex/…`, `~/.cursor/…` (see `agentpolicy/policies/no_hook_self_disable.rego`
  for the exact tool names it keys on; it matches the `file_path`/`path` field).

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Run this test | `go test ./cmd/agentjail/ -run TestMirrorPolicyDecisions -v` | all subtests pass, including new ones |
| Full Go test | `go test ./... -race` | all pass |

## Scope

**In scope**:
- `cmd/agentjail/policies_behavior_test.go` (add cases to the existing `cases` slice)

**Out of scope** (do NOT touch):
- Any `.rego` file — this plan asserts existing rule behavior; it does not change
  rules. (If a new case FAILS, that is a real finding — see STOP conditions —
  not a license to edit the rule here.)
- `buildMirrorOpts` / `evalDecision` helpers — they already load the needed rules.
- Any other test file.

## Git workflow

- Branch: `advisor/006-self-protection-enforcement-tests`
- Conventional Commits with sign-off (`git commit -s`). Example from `git log`:
  `test(policy): include internal_tools in TestCoreRuleNames expected set`.
  Suggested: `test(policy): assert daemon-kill and hook-self-disable denials`.
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Add daemon-kill enforcement cases

Append to the `cases` slice in `TestMirrorPolicyDecisions`:

```go
		// ----- no_daemon_kill (locked self-protection) -----
		{
			name:      "Bash pkill agentjail-daemon → deny (no_daemon_kill)",
			toolName:  "Bash",
			toolInput: map[string]interface{}{"command": "pkill -f agentjail-daemon"},
			want:      "deny",
		},
		{
			name:      "Bash killall agentjail-hook → deny (no_daemon_kill)",
			toolName:  "Bash",
			toolInput: map[string]interface{}{"command": "killall agentjail-hook"},
			want:      "deny",
		},
		{
			name:      "Bash launchctl stop com.agentjail.daemon → deny (no_daemon_kill)",
			toolName:  "Bash",
			toolInput: map[string]interface{}{"command": "launchctl stop com.agentjail.daemon"},
			want:      "deny",
		},
```

**Verify**: `go test ./cmd/agentjail/ -run TestMirrorPolicyDecisions -v` → the
three new subtests pass. If any reports the actual action (e.g. "ask"/"allow")
instead of "deny", STOP (see STOP conditions).

### Step 2: Add hook-self-disable enforcement cases

First confirm which tool name and input field `no_hook_self_disable.rego` keys
on by reading `agentpolicy/policies/no_hook_self_disable.rego` (it matches a file
path — likely `tool_name` in {`Write`,`Edit`} with `file_path`). Then append
cases that match its actual shape, e.g.:

```go
		// ----- no_hook_self_disable (locked self-protection) -----
		{
			name:      "Write ~/.claude/settings.json → deny (no_hook_self_disable)",
			toolName:  "Write",
			toolInput: map[string]interface{}{"file_path": "/Users/dev/.claude/settings.json"},
			want:      "deny",
		},
		{
			name:      "Write ~/.codex/config → deny (no_hook_self_disable)",
			toolName:  "Write",
			toolInput: map[string]interface{}{"file_path": "/Users/dev/.codex/config.toml"},
			want:      "deny",
		},
```

Use the `toolName`/field that the rule actually checks — if the rule keys on
`path` rather than `file_path`, or a different tool set, adjust the literals to
match what the rule reads (the file_policy cases in this same test use `"path"`
for Read; check what `no_hook_self_disable` expects).

**Verify**: `go test ./cmd/agentjail/ -run TestMirrorPolicyDecisions -v` → the
hook-self-disable subtests pass.

### Step 3: Full suite

**Verify**: `go test ./... -race` → all pass.

## Test plan

- New cases appended to the existing `cases` slice in
  `cmd/agentjail/policies_behavior_test.go`: three `no_daemon_kill` deny cases
  (pkill/killall/launchctl) and two `no_hook_self_disable` deny cases.
- Structural pattern: the existing `testCase` literals in the same slice (e.g.
  the "Bash sudo apt install → deny" case for command shape, the file_policy
  cases for path shape).
- Verification: `go test ./cmd/agentjail/ -run TestMirrorPolicyDecisions -v` all
  green; `go test ./... -race` green.

## Done criteria

ALL must hold:

- [ ] `TestMirrorPolicyDecisions` contains ≥3 `no_daemon_kill` deny cases and ≥2 `no_hook_self_disable` deny cases
- [ ] `go test ./cmd/agentjail/ -run TestMirrorPolicyDecisions -v` passes, new subtests green and asserting `want: "deny"`
- [ ] `go test ./... -race` exits 0
- [ ] Only `cmd/agentjail/policies_behavior_test.go` is modified (`git status`)
- [ ] `plans/README.md` status row for 006 updated

## STOP conditions

Stop and report back (do not improvise) if:

- The `testCase` struct or `cases` slice does not match the "Current state"
  excerpt (drift).
- A new case asserting `want: "deny"` FAILS (the engine returns "ask"/"allow").
  This means the locked rule does NOT fire for that input — a real security gap.
  **Do not** edit the rule or weaken the test to make it pass. Report the exact
  input and observed action. (Note: if you are running this *before* plan 003,
  the newline-split daemon-kill bypass is still open — but the single-line cases
  in Step 1 should already deny; a single-line failure is a genuine finding.)
- `no_hook_self_disable.rego` keys on a tool/field you cannot determine — report
  what the rule reads.

## Maintenance notes

- These cases lock in the *enforcement* behavior (full OPA-SDK pipeline), distinct
  from the rule-unit `*_test.rego` files (plans 002/003 add those). Keeping both
  layers means a rule regression is caught whether it's a regex bug (unit) or a
  resolver/loading bug (enforcement).
- A reviewer should confirm the new cases use `want: "deny"` (exact action), not
  `notDeny`, so a downgrade to "ask" is also caught.
- When new sibling binaries or settings paths are added to the self-protection
  rules, add matching enforcement cases here.
