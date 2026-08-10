# ADR 0053: Clean-VM testbed engine for end-to-end install testing

Status: Accepted (2026-07-07)

## Context

All existing test harnesses (`make smoke`, `test/e2e-newuser.sh`) run in a
`mktemp -d` on an already-configured developer machine. Nothing verifies the
true user path — clean OS → `install.sh` → Claude Code + agentjail wired →
policies actually enforcing — and agentjail is a machine-global singleton
(one `~/.agentjail`, one daemon service, one hook entry in
`~/.claude/settings.json`), so parallel feature worktrees cannot be
install-tested side by side on one machine.

Alternatives considered:

- **Containers (Docker/testcontainers)** — rejected: shared host kernel means
  the shield tier (Landlock/seccomp on Linux, Seatbelt on macOS) and
  systemd/launchd service installs cannot be tested faithfully.
- **Firecracker/libkrun** (existing research spikes) — rejected for testbeds:
  fast boot but we would own kernel/rootfs/network plumbing, and they have no
  persistence/snapshot ergonomics for the manual-first workflow.
- **Ephemeral cloud VMs** — rejected for now: cost, credentials, slower loop.

## Decision

Add `test/testbed/` — persistent, named, snapshot-resettable VMs that behave
like a real end-user machine:

- **Linux:** Lima/QEMU on a Linux host (`LIMA_HOME=$HOME/.local/share/lima`), Ubuntu LTS
  cloud image, no host mounts, `limactl snapshot` golden tag for reset.
- **macOS:** Tart on Apple-Silicon, golden `.tart` image, instant APFS clones.
- **Install path under test is the shipped one:** `make dist-tarball` builds a
  release-layout tarball fed to `install.sh` via its `LOCAL_TARBALL=` seam.
  The piped installer wires all detected agents once; provisioning immediately
  verifies daemon and hook readiness without a second install masking the first
  result. Never a source build in-guest.
- **Shell scripts, not a framework:** `testbed.sh` verbs
  (create/provision/ssh/test/gate/snapshot/reset/destroy) with a per-driver
  split (lima|tart) selected by host OS. Promotion to Go/YAML/CI is deferred
  until the shell version demonstrably hurts (see the tracking issue).
- **Trigger is the release, not a timer.** `make e2e-release` (`testbed.sh
  gate`) is a local pre-tag gate: clean VM → real installer → policy
  enforcement, non-zero exit blocks the tag. A nightly timer was explicitly
  rejected — this repo does not change nightly, and the gate's value is
  guaranteeing a release installs and enforces on a clean box. Kept local (not
  GitHub Actions) because Linux needs KVM and macOS needs a self-hosted Tart
  host, and releases are cut by hand.

## Consequences

- Parallel worktrees each get their own testbed; the host install is never
  touched by feature testing.
- Release confidence: the exact `curl | sh` user flow is exercised on a clean
  box before tagging (manual at first, automated in later rollout stages).
- Two real-world regressions were caught in the first provision run: Claude
  Code's node >= 22 requirement (template now uses NodeSource 22) and the
  main-branch build lacking Linux daemon support.
- Cost: ~600 MB cached Ubuntu image + ~3 GB per Linux testbed on the host's data volume;
  ~20–25 GB one-time golden on the Mac (APFS clones are copy-on-write).
- The Tart driver and chaos scenarios were validated on macOS in AGE-236;
  every release still requires a per-commit run on the target host.

## 2026-08-09 addendum: selected real-agent gate

`AGENTJAIL_TESTBED_AGENT` is the single host-to-guest selection contract. It
accepts `codex` and `claude-code`; Codex is the default while its integration is
under active acceptance testing. Provisioning installs only the selected agent,
and the release gate chooses that agent's live scenario. A selected real-agent
gate may not convert missing authentication into a successful skip.

`AGENTJAIL_TESTBED_NAME` is the VM-isolation contract for parallel worktrees.
The default includes the selected agent, and concurrent worktrees set distinct
names; no gate may assume the historical global `release-gate` VM is private.

The gate admits a VM only when current reclaimable memory can hold the guest
plus a host reserve and the backing volume has the required free disk. Defaults
match the 4 GiB/20 GiB Linux template, with 2 GiB RAM and 5 GiB disk held back
for the host; Tart operators set the requirements to their golden-image size.
An unreadable metric or insufficient resource fails before boot.

One EXIT lifecycle owns credentials, host temporaries, partial creation, and
the gate VM on Linux and macOS. The default destroys the gate VM after every
outcome to release RAM and disk; `AGENTJAIL_TESTBED_KEEP_VM=1` explicitly keeps
the disk cache but still stops the VM. Manual named testbeds remain persistent.

For Codex, the host copies only a file-based auth cache immediately before the
live scenario and removes it from the guest on normal completion or host-script
exit. Config, sessions, plugins, and MCP definitions do not cross the boundary.
This follows the official Codex Authentication documentation's headless-machine
cache-copy fallback. The release gate also verifies login status and installs
the host's exact CLI version under ADR 0130-codex-live-gate. The contract was
checked against Codex CLI `0.147.0` and the official documentation on
2026-08-09; each target host must record its own result for the commit under
test.
