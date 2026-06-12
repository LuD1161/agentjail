# Plan 001: Run `opa test` in CI and fix the broken `make test-all` target

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**:
> `git diff --stat 11129c5..HEAD -- .github/workflows/ci.yml Makefile`
> If either file changed since this plan was written, compare the "Current
> state" excerpts against the live code before proceeding; on a mismatch,
> treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: S
- **Risk**: LOW
- **Depends on**: none
- **Category**: dx
- **Planned at**: commit `11129c5`, 2026-06-11

## Why this matters

The repo has **334 OPA Rego policy tests** (`opa test agentpolicy/policies/`
passes 334/334 today) — these test the actual product, the policy rules that
decide allow/deny/ask. **CI never runs them.** `.github/workflows/ci.yml` runs
only `go build`, `go vet`, and `go test`. A regex typo or logic regression in a
`.rego` rule — exactly the class of bug that silently disables a security
guardrail — sails through CI. Separately, `make test-all` is broken: it `cd`s
into an `agentpermissions/` directory that does not exist, so the target hard-
fails for everyone. This plan makes the Rego suite a CI gate and fixes the
broken Make target. It is a prerequisite for the Rego-editing plans (002–004,
006) so their changes are verified on every push.

## Current state

- `.github/workflows/ci.yml` — CI workflow. Two jobs: `test` (matrix
  ubuntu-latest + macos-14) and `smoke` (macos-14). The `test` job, verbatim:

  ```yaml
  jobs:
    test:
      name: test (${{ matrix.os }})
      runs-on: ${{ matrix.os }}
      strategy:
        fail-fast: false
        matrix:
          os: [ubuntu-latest, macos-14]

      steps:
        - uses: actions/checkout@v4

        - uses: actions/setup-go@v5
          with:
            go-version-file: go.mod
            cache: true

        - name: build
          run: go build ./...

        - name: vet
          run: go vet ./...

        - name: test
          run: go test ./... -race
  ```

  There is **no** `opa test` step anywhere in the file.

- `Makefile` — the `opa-test` and `test-all` targets, verbatim:

  ```makefile
  test-all:  ## go test laptop + cloud trees with -race
  	go test ./... -race && (cd agentpermissions && go test ./... -race)

  opa-test:  ## opa test over agentpolicy/policies/ (requires opa on PATH)
  	opa test agentpolicy/policies/
  ```

  `agentpermissions/` does not exist (the workspace in `go.work` is only `.`,
  `./agentjail`, `./agentpolicy`). The intended "second tree" no longer exists;
  the `&& (cd … )` clause is dead and breaks the target.

- Convention for OPA in this repo: tests live as `*_test.rego` under
  `agentpolicy/policies/` (and `agentpolicy/policies/library/`), run with
  `opa test agentpolicy/policies/`. The Makefile `opa-test` target already
  encodes the exact command. CI installs tools via official actions where one
  exists; OPA publishes `open-policy-agent/setup-opa`.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Run Rego tests | `opa test agentpolicy/policies/` | `PASS: 334/334` (count may grow as later plans add tests) |
| Validate workflow YAML | `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml'))"` | exit 0, no output |
| Confirm Make target runs | `make test-all` | exit 0 (runs the Go suite; no `cd` error) |
| Go build (sanity) | `go build ./...` | exit 0 |

If `opa` is not on PATH locally, install it (macOS: `brew install opa`; Linux:
download the static binary from the OPA releases page) — it is only needed to
confirm the suite still passes; the CI step uses the setup-opa action.

## Scope

**In scope** (the only files you should modify):
- `.github/workflows/ci.yml`
- `Makefile`

**Out of scope** (do NOT touch):
- Any `.rego` file — this plan does not change policy. (That is plans 002–004.)
- The `smoke` job in `ci.yml` — leave it exactly as is.
- `go.work`, `go.mod` — do not change the module set or Go version here.

## Git workflow

- Branch: `advisor/001-opa-test-in-ci`
- Conventional Commits with sign-off (`git commit -s`). This repo requires DCO;
  enable the tracked hook once with `git config core.hooksPath .githooks` if you
  have not. Example message style from `git log`: `ci(release): inject PostHog
  write-only key into release builds via ldflags`.
- Suggested commits: one for the CI step, one for the Makefile fix.
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Add an `opa test` step to the CI `test` job

In `.github/workflows/ci.yml`, inside the `test` job's `steps:` list, add an OPA
install step and an OPA test step **after** the existing `test` (`go test`) step.
Add them at the same indentation as the other steps. Use the official setup
action so no manual download is needed:

```yaml
      - name: setup opa
        uses: open-policy-agent/setup-opa@v2
        with:
          version: latest

      - name: opa test
        run: opa test agentpolicy/policies/
```

Leave the `smoke` job untouched.

**Verify**:
- `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml'))"` → exit 0 (file is valid YAML).
- `grep -c "opa test" .github/workflows/ci.yml` → `1`.

### Step 2: Fix the broken `make test-all` target

In `Makefile`, replace the broken `test-all` recipe. The `agentpermissions/`
tree no longer exists, so drop the dead subshell. The workspace's three modules
are already covered by `go test ./...` (workspace-aware via `go.work`), so
`test-all` should run the Go suite and the OPA suite together. Change:

```makefile
test-all:  ## go test laptop + cloud trees with -race
	go test ./... -race && (cd agentpermissions && go test ./... -race)
```

to:

```makefile
test-all:  ## go test (all workspace modules) + opa test, all with -race
	go test ./... -race
	opa test agentpolicy/policies/
```

(Each recipe line runs in its own shell; Make stops on the first failing line,
so this preserves "fail if either suite fails".)

**Verify**:
- `grep -c "agentpermissions" Makefile` → `0`.
- `make test-all` → exit 0, prints the Go test output then `PASS: 334/334`
  (or higher). If `opa` is not installed locally, this line will error with
  "opa: command not found" — that is an environment gap, not a plan failure;
  note it and confirm `grep -c agentpermissions Makefile` is `0`.

## Test plan

This plan adds CI coverage; it writes no new application tests. Verification is
the two commands above plus a manual read-through of the diff to confirm:
- the `opa test` step appears once, after `go test`, correctly indented;
- the `smoke` job is byte-for-byte unchanged;
- `test-all` no longer references `agentpermissions`.

## Done criteria

ALL must hold:

- [ ] `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml'))"` exits 0
- [ ] `grep -c "opa test" .github/workflows/ci.yml` returns `1`
- [ ] `grep -c "agentpermissions" Makefile` returns `0`
- [ ] `opa test agentpolicy/policies/` still reports `PASS: 334/334` (run from repo root)
- [ ] Only `.github/workflows/ci.yml` and `Makefile` are modified (`git status`)
- [ ] `plans/README.md` status row for 001 updated

## STOP conditions

Stop and report back (do not improvise) if:

- `.github/workflows/ci.yml` or `Makefile` does not match the "Current state"
  excerpts (the repo drifted since this plan was written).
- `open-policy-agent/setup-opa@v2` does not exist or is not the current major
  version when you check the action's repo — report and ask which version to
  pin rather than guessing.
- `opa test agentpolicy/policies/` does NOT pass on the unmodified repo (a
  pre-existing failure means something else is wrong; do not mask it).

## Maintenance notes

- When later plans add `*_test.rego` files, the `PASS: N/N` count rises
  automatically — no CI change needed.
- A reviewer should confirm the `opa test` step runs on both matrix OSes (it is
  in the matrixed `test` job, so it does) and that the setup-opa action version
  is pinned to a tag, not a moving `@main`.
- Deferred: pinning OPA to an exact version (rather than `latest`) for fully
  reproducible CI — left out to avoid a version-bump treadmill; revisit if a
  `latest` OPA release ever breaks the suite.
