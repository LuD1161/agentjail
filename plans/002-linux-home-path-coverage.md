# Plan 002: Cover Linux home paths in sensitive-path & self-protection Rego rules

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**:
> `git diff --stat 11129c5..HEAD -- agentpolicy/policies/file_policy.rego agentpolicy/policies/command_policy.rego agentpolicy/policies/no_hook_self_disable.rego cmd/agentjail/policies/`
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding; on a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: plans/001-opa-test-in-ci.md (soft — see plans/README.md)
- **Category**: security
- **Planned at**: commit `11129c5`, 2026-06-11

## Why this matters

Every credential-protection and self-protection Rego rule anchors its path
regexes to **`/Users/<name>/…`** — the macOS home layout. On Linux, home
directories are `/home/<name>/` and `/root/`. The result: on Linux, `~/.ssh`,
`~/.aws`, `~/.gnupg`, `~/.config`, `~/.npmrc`, the Kubernetes/Docker/cargo
credential files, **and the locked self-protection rules** (`~/.agentjail/`,
`~/.claude`/`~/.codex`/`~/.cursor` settings) match **nothing** — no deny
candidate fires. The README advertises "macOS · Linux" support and the daemon
binary builds and runs on Linux (no build tags); Linux daemon wiring is on the
near-term roadmap. The moment that lands, all of this protection silently
provides zero coverage on the most common server/CI deployment target. This
plan broadens each anchor to also match `/home/<name>/` and `/root/`.

## Current state

The policies are **mirrored**: the source of truth is `agentpolicy/policies/`,
and a byte-identical copy lives in `cmd/agentjail/policies/` (embedded into the
`agentjail` binary at build time). `cmd/agentjail/embed_parity_test.go`
(`TestCoreFileParity`) fails the Go build/test if the two copies diverge. **You
must edit both copies of every file you touch.**

Three source files contain `/Users/`-anchored path regexes:

### `agentpolicy/policies/file_policy.rego`

- `is_agentjail_self(p)` (line 162) — the locked self-protection predicate:
  ```rego
  is_agentjail_self(p) if {
      regex.match(`^/Users/[^/]+/\.agentjail(/|$)`, p)
  }
  ```
- `is_protected_credential(p)` clauses (lines 173–238), each of the form
  `regex.match(\`^/Users/[^/]+/<store>…\`, p)` for: `.ssh`, `.aws`, `.gnupg`,
  `Downloads`, `Desktop`, `.config`, `.npmrc`, `.pypirc`, `.git-credentials`,
  `.docker/config.json`, `.kube/config`, `.cargo/credentials(.toml)?`,
  `Library/Keychains`. Example (line 173):
  ```rego
  is_protected_credential(p) if {
      regex.match(`^/Users/[^/]+/\.ssh(/|$)`, p)
  }
  ```
  (`Library/Keychains` is macOS-only and has no Linux equivalent — leave that
  one `/Users/`-only; see Step 2.)

### `agentpolicy/policies/command_policy.rego`

- Two `_is_policy_mutation` redirect patterns (lines 323, 328) already include
  `~` and `$HOME` alternates alongside `/Users/[^/\s'"]+`:
  ```rego
  regex.match(`(>|>>|\btee\b)\s*(~|(\$HOME)|/Users/[^/\s'"]+)/\.agentjail\b`, cmd)
  ```
- `contains_sensitive_path(c)` clauses (lines 368–415). Two anchoring styles:
  - **Absolute-only** (lines 368–374): `regex.match(\`/Users/[^/\s'"]+/\.ssh\b\`, c)` for `.ssh`, `.aws`, `.gnupg`, `.agentjail`.
  - **Combined** (lines 385–415): `regex.match(\`(~|(\$HOME)|/Users/[^/\s'"]+)/\.npmrc…\`, c)` for `.npmrc`, `.pypirc`, `.git-credentials`, `.docker/config.json`, `.kube/config`, `.cargo/credentials`, `Library/Keychains`.

### `agentpolicy/policies/no_hook_self_disable.rego`

- Path predicates (lines 73, 78, 83) and one command pattern (line 127):
  ```rego
  regex.match(`^/Users/[^/]+/\.claude/settings[^/]*\.json$`, p)   # 73
  regex.match(`^/Users/[^/]+/\.codex(/|$)`, p)                    # 78
  regex.match(`^/Users/[^/]+/\.cursor(/|$)`, p)                   # 83
  regex.match(`/Users/[^/\s'"]+/\.(claude|codex|cursor)\b`, c)    # 127
  ```
  Line 88 is `Library/LaunchAgents/com.agentjail.` — macOS-only (launchd), leave
  `/Users/`-only.

**The fix pattern.** Replace the anchor alternative `/Users/[^/]+` (and the
`contains_sensitive_path` variant `/Users/[^/\s'"]+`) with a parenthesised
alternation that also matches Linux homes. Concretely:

- For the `^/Users/[^/]+/…` predicate regexes (file_policy, no_hook_self_disable
  path rules), change the leading `^/Users/[^/]+` to:
  `^(/Users/[^/]+|/home/[^/]+|/root)`
- For the absolute `contains_sensitive_path` patterns that use `/Users/[^/\s'"]+`
  with no `~`/`$HOME` alternation (command_policy lines 368–374), change
  `/Users/[^/\s'"]+` to `(/Users/[^/\s'"]+|/home/[^/\s'"]+|/root)`.
- For the **combined** patterns that already have `(~|(\$HOME)|/Users/[^/\s'"]+)`
  (command_policy lines 323, 328, 385–415; and the `_is_policy_mutation` lines),
  extend the alternation in place to
  `(~|(\$HOME)|/Users/[^/\s'"]+|/home/[^/\s'"]+|/root)`.

`/root` has no `/<name>` segment (root's home is `/root` directly), so it needs
no `[^/]+`. The `(/|$)` / `\b` / `$` suffixes on each existing regex are
preserved unchanged — you are only widening the home-prefix alternative.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Run Rego tests | `opa test agentpolicy/policies/` | `PASS: N/N` (N ≥ 334; rises as you add cases) |
| Check mirror parity | `go test ./cmd/agentjail/ -run TestCoreFileParity` | `ok` / PASS |
| Full Go test | `go test ./... -race` | all pass |
| Confirm no `/Users`-only sensitive anchors remain | see Step 5 | as specified |

## Suggested executor toolkit

- OPA Rego docs for `regex.match` semantics if a pattern misbehaves:
  https://www.openpolicyagent.org/docs/latest/policy-reference/#regex
- The patterns use Go's RE2 syntax (OPA uses RE2). Alternation `(a|b|c)` and
  character classes behave as in RE2 — no lookbehind/backreferences.

## Scope

**In scope** (modify all of these):
- `agentpolicy/policies/file_policy.rego` and its mirror `cmd/agentjail/policies/file_policy.rego`
- `agentpolicy/policies/command_policy.rego` and its mirror `cmd/agentjail/policies/command_policy.rego`
- `agentpolicy/policies/no_hook_self_disable.rego` and its mirror `cmd/agentjail/policies/no_hook_self_disable.rego`
- `agentpolicy/policies/file_policy_test.rego` (add Linux cases)
- `agentpolicy/policies/command_policy_test.rego` (add Linux cases)
- `agentpolicy/policies/no_hook_self_disable_test.rego` (add Linux cases)

**Out of scope** (do NOT touch):
- `Library/Keychains` and `Library/LaunchAgents` regexes — macOS-only paths with
  no Linux analogue; leave them `/Users/`-anchored.
- The `is_temp_path` predicates (`/tmp`, `/var/folders/…`) — temp handling, not
  credential protection; unrelated.
- `resolver.rego`, `mcp_policy.rego`, `web_policy.rego`, `internal_tools.rego`,
  `no_daemon_kill.rego` — out of scope here (no_daemon_kill is plan 003).
- The Go daemon (`cmd/agentjail-daemon/`) — this is a pure-Rego change. Do NOT
  attempt the alternative "inject runtime home_dir into OPA data" approach; it is
  a larger, separately-scoped change.

## Git workflow

- Branch: `advisor/002-linux-home-path-coverage`
- Conventional Commits with sign-off (`git commit -s`). Example from `git log`:
  `feat(policy): make git force-push branch-aware`.
- Suggested commits: one per file pair (source + mirror + that file's tests), or
  one cohesive `fix(policy): cover Linux home paths in sensitive-path rules`.
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Widen the anchors in `file_policy.rego` (source)

In `agentpolicy/policies/file_policy.rego`:
- Line 162 (`is_agentjail_self`): change `^/Users/[^/]+` → `^(/Users/[^/]+|/home/[^/]+|/root)`.
- Lines 173, 178, 183, 188, 193, 203, 208, 213, 218, 223, 228, 233 (the
  `is_protected_credential` clauses for `.ssh`/`.aws`/`.gnupg`/`Downloads`/
  `Desktop`/`.config`/`.npmrc`/`.pypirc`/`.git-credentials`/`.docker/config.json`/
  `.kube/config`/`.cargo/credentials`): same change to each — `^/Users/[^/]+` →
  `^(/Users/[^/]+|/home/[^/]+|/root)`.
- **Leave line 238 (`Library/Keychains`) unchanged** (`/Users/`-only).

Preserve every suffix exactly (`(/|$)`, `$`, `/config\.json$`, etc.).

**Verify**: `opa test agentpolicy/policies/` → still `PASS` (no test asserts the
old macOS-only behavior negatively; if any test breaks here, STOP — it means a
test depended on Linux paths being *allowed*, which is the bug).

### Step 2: Mirror `file_policy.rego` into the embed copy

Copy the edited source over the mirror so they are byte-identical:
`cp agentpolicy/policies/file_policy.rego cmd/agentjail/policies/file_policy.rego`

**Verify**: `go test ./cmd/agentjail/ -run TestCoreFileParity` → PASS.

### Step 3: Repeat for `command_policy.rego` and `no_hook_self_disable.rego`

`command_policy.rego` (source):
- Lines 368, 370, 372, 374 (absolute `contains_sensitive_path` for `.ssh`/`.aws`/
  `.gnupg`/`.agentjail`): `/Users/[^/\s'"]+` → `(/Users/[^/\s'"]+|/home/[^/\s'"]+|/root)`.
- Lines 323, 328 (`_is_policy_mutation`) and 385, 387, 390, 392, 395, 397, 400,
  402, 405, 407, 410, 412 (combined `.npmrc`…`.cargo/credentials`): extend the
  existing alternation `(~|(\$HOME)|/Users/[^/\s'"]+)` →
  `(~|(\$HOME)|/Users/[^/\s'"]+|/home/[^/\s'"]+|/root)`.
- **Leave line 415 (`Library/Keychains`) unchanged.**

`no_hook_self_disable.rego` (source):
- Lines 73, 78, 83: `^/Users/[^/]+` → `^(/Users/[^/]+|/home/[^/]+|/root)`.
- Line 127: `/Users/[^/\s'"]+` → `(/Users/[^/\s'"]+|/home/[^/\s'"]+|/root)`.
- **Leave line 88 (`Library/LaunchAgents`) unchanged.**

Then mirror both:
`cp agentpolicy/policies/command_policy.rego cmd/agentjail/policies/command_policy.rego`
`cp agentpolicy/policies/no_hook_self_disable.rego cmd/agentjail/policies/no_hook_self_disable.rego`

**Verify**:
- `opa test agentpolicy/policies/` → `PASS`.
- `go test ./cmd/agentjail/ -run TestCoreFileParity` → PASS.

### Step 4: Add Linux test cases (this is the regression proof)

These tests must FAIL before Steps 1–3 and PASS after. Model them on the
existing cases in each `*_test.rego`. The input builders already exist; the
`command_policy_test.rego` builder is:

```rego
bash_input(cmd) := {
	"hook_event":  "PreToolUse",
	"tool_name":   "Bash",
	"tool_input":  {"command": cmd, "description": ""},
	"session_id":  "test-session",
	"cwd":         "/Users/dev/project",
}
```

Add, mirroring the structure of the existing `test_*` cases in each file:

- **`file_policy_test.rego`**: deny cases for a Write to `/home/dev/.ssh/id_rsa`,
  `/home/dev/.aws/credentials`, `/root/.ssh/id_rsa`, and an agentjail-self case
  `/home/dev/.agentjail/policy.yaml` (expect the `file_policy/agentjail_self`
  rule_id). Use the same file-input builder the existing cases use (find it near
  the top of the file — it sets `tool_name` to `Write`/`Read` with a
  `file_path`). Match the exact expected verdict shape the existing deny cases
  assert.
- **`command_policy_test.rego`**: a deny case for
  `bash_input("cat /home/dev/.ssh/id_rsa")` and one for
  `bash_input("cat /root/.aws/credentials")`, asserting the same sensitive-path
  verdict the existing `/Users/` command cases assert.
- **`no_hook_self_disable_test.rego`**: a deny case for a Write to
  `/home/dev/.claude/settings.json`, mirroring the existing `/Users/dev/.claude/
  settings.json` case.

If you cannot determine the exact expected verdict object for a builder, copy an
existing passing case in the same file, change only the path to the `/home/` or
`/root/` variant, and keep its asserted verdict — the verdict for a Linux home
path must equal the verdict for the macOS equivalent.

**Verify**: `opa test agentpolicy/policies/` → `PASS: N/N` where N is now
greater than before (your new cases are counted and green).

### Step 5: Confirm no protected store regressed to `/Users`-only

Run:
`grep -nE 'regex\.match\(`[^`]*\^?/Users/\[\^/' agentpolicy/policies/file_policy.rego agentpolicy/policies/no_hook_self_disable.rego`

Every remaining match must be a line you intentionally left macOS-only:
`Library/Keychains` (file_policy.rego:238) and `Library/LaunchAgents`
(no_hook_self_disable.rego:88). If any *other* line still has a bare `/Users/`
anchor without the `/home`/`/root` alternation, you missed one — fix it.

**Verify**: the grep output contains only the two macOS-only lines.

## Test plan

- New `test_*` cases as listed in Step 4, in the three existing `*_test.rego`
  files, covering: `/home/<user>/` credential reads/writes, `/root/` credential
  access, and the self-protection rules (`agentjail_self`, hook self-disable) on
  Linux paths.
- Structural pattern: copy an adjacent passing case in the same file and change
  only the path.
- Verification: `opa test agentpolicy/policies/` → all pass including the new
  cases; `go test ./... -race` → all pass (parity tests green).

## Done criteria

ALL must hold:

- [ ] `opa test agentpolicy/policies/` reports `PASS: N/N` with N strictly greater than 334
- [ ] `go test ./... -race` exits 0 (includes `TestCoreFileParity`, `TestLibraryFileParity`)
- [ ] `grep -RnE '/home/\[\^/' agentpolicy/policies/file_policy.rego agentpolicy/policies/command_policy.rego agentpolicy/policies/no_hook_self_disable.rego` returns at least one match in each file
- [ ] Each edited source `.rego` is byte-identical to its `cmd/agentjail/policies/` mirror (`diff agentpolicy/policies/file_policy.rego cmd/agentjail/policies/file_policy.rego` → no output; same for the other two)
- [ ] Only the in-scope files are modified (`git status`)
- [ ] `plans/README.md` status row for 002 updated

## STOP conditions

Stop and report back (do not improvise) if:

- Any in-scope `.rego` file does not match the "Current state" excerpts (drift).
- An existing OPA test starts failing after Step 1 (it would mean a test relied
  on Linux paths being *unprotected* — surface it, don't delete the test).
- You find a sensitive-path regex anchored differently than the two styles
  documented here (e.g. a `$HOME`-only or `~`-only one) and are unsure how to
  widen it — report the exact line.
- `TestCoreFileParity` fails and `cp` of source → mirror does not fix it (the
  parity test may compare more files than expected; report what it says).

## Maintenance notes

- This widens regexes; it never narrows them — macOS behavior is unchanged, so
  the risk is false *positives* on Linux (denying a legitimate path), not false
  negatives. A reviewer should sanity-check that no `/home/<user>/<project>`
  working path accidentally matches a credential pattern (the patterns are all
  anchored to specific store names like `.ssh`, so this is unlikely).
- The more robust long-term fix is to inject the *actual* resolved home dir into
  OPA data (like `data.agentjail.config.file.temp_roots` is injected in
  `cmd/agentjail-daemon/main.go` `reload()` via `cfg.ToOPAData()`), so the rules
  match exactly one home rather than a `/home|/Users|/root` union. That is a
  larger change (daemon + every rule + tests) and is deliberately deferred. If
  someone takes it on, this plan's union-regex becomes redundant and can be
  replaced.
- When Linux daemon wiring lands (roadmap), add a Linux smoke test that runs a
  real `~/.ssh/id_rsa` read through the daemon and asserts DENY.
