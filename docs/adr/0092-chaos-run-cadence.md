# 0092 - Chaos run cadence

Status: Accepted

## Context

The three chaos scenarios (`test/testbed/scenarios/chaos-*.sh`) inject the
failures the happy-path suite cannot see: the daemon dying mid-session, the
supervisor restarting it, the hook binary being stripped. They exist because
AGE-212 ran for three days with `shield.activated` climbing while `decisions`
stayed flat - a green padlock over an unenforced agent, which every green test
we had agreed was fine.

They are green on both platforms now: 45 pass / 2 skip on a Linux Lima guest,
and the same 45 pass / 2 skip on a macOS Tart guest (AGE-236). What was never
decided is **when they run**. Left undecided, the answer defaults to "never
again", which is the failure mode the scenarios were written to prevent.

Two facts shape the decision:

1. **They are slow by construction.** `hookwatch` is a 30s ticker
   (`internal/hookwatch/watcher.go:105,144`) with fsnotify on the fast path, so
   negative waits are 45s and re-inject waits 90s. Each scenario also stops and
   restarts a real daemon. A full pass is minutes, not seconds. Putting that in
   front of every PR buys a suite people learn to skip.
2. **They need a real VM, which hosted CI does not have.**
   `.github/workflows/ci.yml` runs on GitHub-hosted `ubuntu-latest` /
   `macos-14`. The testbed needs Lima/QEMU (Linux) or Tart (macOS); hosted
   Ubuntu runners have no KVM, so QEMU would fall back to software emulation,
   and hosted macOS runners cannot nest Tart.

## Decision

Chaos runs **locally, before pushing to `main`**, and **before a major
release**. Not on every PR, not on minor or patch releases, and **not in CI**.

`make chaos TESTBED=<name>` is the single entry point, so the cadence has one
thing to call and the scenario list lives in one place. It takes an explicit
scenario list rather than a `chaos-*.sh` glob - `chaos-lib.sh` matches that glob
and is a sourced library, not a scenario.

This puts chaos in the same class as `make e2e-release` (ADR 0053): a gate a
human runs on real hardware before the change escapes, not a job a runner runs
after. That is a choice, not a workaround. The VM constraint in fact 2 means
hosted CI is not available to us today, but even with a self-hosted runner the
gate stays local for now - the machine that can honestly run these scenarios is
the same machine the developer is already sitting at, and a gate that blocks the
push is worth more than a red badge that arrives after it.

The scoping follows from fact 1. A PR is where speed matters and the blast
radius is one branch. `main` is where an unenforced agent starts shipping, and a
major release is where the install base moves. Those are the two moments the
AGE-212 class is worth minutes to rule out.

**This cadence is enforced by discipline, not by tooling.** Nothing rejects a
push to `main` that skipped `make chaos`. That is the honest state of it, and it
is stated here rather than left for someone to discover.

## Consequences

- One command runs the suite on either platform, and the cadence question has a
  written answer instead of being rediscovered per release.
- **Nothing enforces this.** No workflow rejects a push to `main` that skipped
  the suite, so anyone reading a commit should assume chaos has NOT run on it
  unless someone says otherwise. Saying that plainly is the point: a documented
  cadence that silently never fires is precisely the "looks like coverage" lie
  AGE-236 was filed to kill, and it would be worse than no ADR. The mitigation
  is that the gate sits where the developer already is, not that a robot is
  watching.
- **This is reversible.** If discipline proves insufficient - the tell would be
  an AGE-212-class bug reaching `main` again - the answer is a self-hosted
  runner on each platform, and this ADR gets superseded rather than quietly
  ignored.
- Minor and patch releases ship without a chaos pass. That is a deliberate
  trade: the AGE-212 class comes from daemon/supervisor/hook lifecycle changes,
  which are not what a patch usually touches. A patch that *does* touch that
  lifecycle should run `make chaos` regardless of the version number - the
  cadence is a floor, not a ceiling.
- The scenarios stay out of `make e2e-release`, so the release gate stays fast
  enough that nobody is tempted to skip it (ADR 0053).
