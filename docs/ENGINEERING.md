# Engineering principles

These constrain every change in this repo. They override convenience. If a task seems to require breaking one of these, that is a signal to stop and raise a finding, not to break it.

## 1. KISS — keep it simple

The simplest thing that could possibly work. Three lines of duplication beats a premature abstraction. A flat function beats a class hierarchy. A constant beats a config field.

- No "just in case" abstractions. Add the abstraction the third time you need it, not the first.
- No "framework" where a function would do.
- No DI containers, no code generators, no metaprogramming until two real callers require it.
- Naming: the shortest name that unambiguously describes the thing. `agentjail.MicroVM` not `agentjail.MicroVirtualMachineSupervisor`.
- A 100-line file is fine. A 1000-line file with one job is fine. Splitting "just to keep files small" is not a reason.

## 2. Inspirations — mature projects we steal patterns from

When in doubt, study how these systems solved similar problems. Do not reinvent.

| Problem we hit | Project to study | What to copy |
|---|---|---|
| microVM lifecycle, fast boot | **Firecracker**, **libkrun** | Minimal API surface; JSON-over-socket control plane; jailer pattern |
| Policy as data | **OPA** | In-process evaluation; partial rule sets; bundle distribution |
| Decision caching | **Linux page cache**, **Envoy RDS cache** | Static/dynamic key split (already adopted) |
| Wire-shape evolution | **Protobuf**, **Kubernetes API** | Additive evolution; never reuse a field number/name |
| In-kernel hooks | **eBPF LSM**, **Apple Endpoint Security** | Composable, minimal kernel surface, NOTIFY before AUTH |
| JIT human access UX | **opal.dev**, **Indent**, **StrongDM** | Request-with-reason + time-bound grant + approver identity in audit |
| OSS engineering bar | **Go stdlib**, **Postgres**, **SQLite** | Small interfaces, stable APIs, ruthless backwards compat |
| Test discipline | **SQLite test harness** | Hostile inputs, adversarial fixtures, deterministic replay |
| Release hygiene | **Tailscale** | Per-component CHANGELOGs, signed artifacts, predictable cadence |

When you copy a pattern, **note it in your findings** with a one-line citation.

## 3. No shortcuts

A shortcut today is debt tomorrow that someone else pays.

- **Fix the root cause, not the symptom.** A test fails → understand *why* it fails before silencing it.
- **Never `--no-verify`** on commits, never `--no-edit` on rebases, never `--force` on shared branches.
- **Never fake a pass.** If you cannot make the test green, mark the task `blocked` and explain.
- **No silent fallbacks.** A failure path is either fail-closed (cred, enforcement) or fail-open (audit, telemetry). Document which.
- **No "we'll refactor later" comments.** Either refactor now or write an ADR explaining why later is acceptable.
- **No dead code.** Remove what isn't used. Don't add what isn't yet needed.

## 4. Reliability

- Every external call has a context deadline. No naked `http.Get`, no naked `pool.Exec`.
- Every error has an explicit handler. `if err != nil { return err }` is fine; ignoring the error is not.
- Every shared state is behind a mutex or a channel. Implicit synchronization is a race-detector failure waiting to happen.
- All tests run with `-race` in CI.
- Determinism: no time-of-day dependencies in tests; inject a clock.
- All goroutines have a defined exit. No fire-and-forget.

## 5. Speed

Concrete targets per layer:

| Layer | Path | Target |
|---|---|---|
| agentjail | per-syscall decision | p95 < 5 ms end-to-end (PEP → decision → return) |
| agentjail | microVM cold boot | p95 < 200 ms (libkrun), p95 < 250 ms (Firecracker) |
| agentjail | redactor on 1 MB body | p95 < 10 ms |
| agentpolicy | single decision | p95 < 1 ms with warm cache |
| agentpolicy | cold-start | < 100 ms |

If your change misses a target, that is not a "we'll optimize later" — it's a finding that needs an ADR or a fix in the same PR.

## 6. Long-term vision

Code we ship today will be read in 2030. Optimize for the reader, not the writer.

- **Wire shapes are frozen and additively evolved.** `api/v1/` never breaks. New behavior gets new fields, optional, with safe defaults.
- **OSS layers work standalone.** agentjail must compile, test, and run useful work with nothing else in the tree. Same for agentpolicy.
- **Every significant decision lives in an ADR** (`docs/adr/NNNN-slug.md`). The why outlives the what.
- **Each layer ships its own README, CHANGELOG, ADR set.** Self-contained, fork-able.
- **No private external dependencies in OSS layers.** Anything in agentjail or agentpolicy must be installable by anyone, anywhere, no credentials.

## 7. Documentation discipline (mandatory for every commit)

Documentation drift is a bug.

- Every commit that resolves a previously-open design question adds an ADR (or amends one).
- Every layer-level decision (chose library X over Y, picked design A over B) is appended to the matching `<layer>/docs/DECISIONS.md`.
- Every public API change appends to the matching layer's CHANGELOG.
- Every README that lists a feature shipped: the feature lands and the README updates in the same commit.

## 8. Commit discipline

- Conventional Commits, signed off (`-s`).
- One commit = one cohesive change.
- After every commit: `go build && go vet && go test ./<changed-pkg>/...` passes.
- Push after each commit.
- Never amend a pushed commit unless explicitly asked.

## 9. When you cannot satisfy these

Stop. Write a finding. Mark the task `blocked` if you need a decision, `needs_review` if you've made a judgment call you want sanity-checked. **Do not paper over.**

---

**Read this before starting any contribution.** Reread it before submitting work for review. Work that violates any of these without an ADR justifying the deviation will be rejected.
