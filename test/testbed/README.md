# agentjail testbeds — clean-VM sandboxes

Persistent, named VMs that behave like a **real end-user machine**: full
kernel, systemd/launchd, no Go toolchain, no host mounts. Each worktree gets
its own testbed, so parallel feature builds never fight over the host's single
agentjail install — and the host is never polluted.

agentjail is always installed **through the real user path**: a release-layout
tarball (`make dist-tarball`) fed to the shipped `install.sh` via its
`LOCAL_TARBALL=` seam. The installer wires every detected agent once, exactly
as a piped end-user install does; the testbed does not run a second install to
repair or alter that result. `AGENTJAIL_TESTBED_AGENT` selects the agent under
test; it defaults to `codex` and also accepts `claude-code`.

## Status / division of work

| Side | Host | Driver | Status |
|---|---|---|---|
| **Linux** | a Linux host | Lima/QEMU, `LIMA_HOME=$HOME/.local/share/lima` | ✅ **DONE — set up and validated end-to-end on the Linux host. Do not redo.** |
| **macOS** | your Apple-Silicon Mac | Tart | ✅ **DONE — `golden-macos-mitm` is the sole approved macOS golden.** |

## Quick reference (both OSes)

```sh
test/testbed/testbed.sh create <name>                 # new VM + golden snapshot
AGENTJAIL_TESTBED_AGENT=codex test/testbed/testbed.sh provision <name> [--worktree <path>]
test/testbed/testbed.sh ssh <name>
test/testbed/testbed.sh exec <name> -- <cmd>
test/testbed/testbed.sh test <name> [scenario] [--codex-auth <path>]
                                                       # run a scenario (default: e2e-smoke)
test/testbed/testbed.sh gate                          # RELEASE GATE (== make e2e-release)
test/testbed/testbed.sh snapshot <name> <tag>         # checkpoint
test/testbed/testbed.sh reset <name> [tag]            # revert to golden
test/testbed/testbed.sh ls
test/testbed/testbed.sh destroy <name>

# Live AWS STS + real Codex (macOS; pauses for one external profile command)
bash test/testbed/run-aws-sts-live.sh
```

Each `test` invocation leaves a structured, value-free result at
`/tmp/testbed/results/<scenario>.result.json` inside the guest. Raw terminal
recordings are never required for release evidence.

### High-fidelity release evidence

An independent review can retain the unsanitized artifacts from one clean gate
without relying on terminal output. Choose a new absolute directory outside the
repository (or under the gitignored `test/testbed/reports/` directory):

```sh
AGENTJAIL_TESTBED_RAW_EVIDENCE_DIR=/tmp/agentjail-gate-evidence \
  AGENTJAIL_TESTBED_AGENT=codex make e2e-release
```

The directory must be absent or empty. The gate records the guest baseline
before installation, copies the exact distribution tarball and installer inputs,
retains raw scenario artifacts until collection, and pulls the SQLite stores,
Codex session records, project proofs, and `/tmp/testbed` results before the VM
is stopped. `run-manifest.json` binds those files to the exact committed and
uncommitted source tree; `SHA256SUMS` binds the manifest itself. Model accounting
distinguishes broad endpoint rows from exact completed `POST
/backend-api/codex/responses` calls.

This mode deliberately contains unsanitized transcripts, paths, database
content, and credential material returned to the coding agent by the generic
bootstrap broker. Static session exposure is the explicit limitation in ADR
0140-generic-credentials; JIT/phantom delivery is a separate architectural
phase. Keep the directory owner-only, give it only to the authorized reviewer,
never add it to Git, and delete it after the review. The gate inventories every
long string path in the disposable Codex auth schema and byte-scans every
credential-bearing value—with a positive control—before removing the auth
cache. Stable identity metadata is inventoried but is not mislabeled as a
secret; it may legitimately appear in Codex's own logs. Logical database
queries are not a substitute for the byte-level
database/WAL/SHM scans required by ADR 0137-credential-residue.

`AGENTJAIL_TESTBED_NAME` selects the persistent VM name. It defaults to
`release-gate-<agent>`; set it to a worktree-specific name when another agent
may be using a testbed concurrently.

On Tart, generic creates and gates clone `TART_GOLDEN`, while a gate containing
`tunnel-agent` selects `TART_TUNNEL_GOLDEN`. Both default to the sole approved
`golden-macos-mitm` image. The installed extension does not redirect traffic
until AgentJail starts a tunnel session; tunnel gates additionally enforce the
strict activation and execution contract. To override the source explicitly:

```sh
TART_GOLDEN=golden-macos-mitm test/testbed/testbed.sh create mac-tunnel
```

### Host resource admission and cleanup

Before starting a VM, the harness reads reclaimable host memory and free space
on the Lima or Tart storage volume. A new VM defaults to a 4 GiB memory and
20 GiB disk requirement, with 2 GiB RAM and 5 GiB disk reserved for the host.
It fails before boot with the available and required amounts when either check
does not pass.

The requirements are configurable when a golden image uses different sizing:

```sh
AGENTJAIL_TESTBED_REQUIRED_MEMORY_GIB=6 \
AGENTJAIL_TESTBED_REQUIRED_DISK_GIB=30 \
AGENTJAIL_TESTBED_HOST_MEMORY_RESERVE_GIB=4 \
AGENTJAIL_TESTBED_HOST_DISK_RESERVE_GIB=10 \
make e2e-release
```

The backing volume defaults to `LIMA_HOME` on Linux and `~/.tart` on macOS.
Set `AGENTJAIL_TESTBED_STORAGE_DIR` when the VM driver stores disks elsewhere;
the directory must be on the same filesystem as the VM images.

The release gate owns its VM for the duration of the run. On success, failure,
Ctrl-C, or termination it removes injected authentication and temporary host
files, stops the VM, and deletes the gate VM to release both RAM and disk. Set
`AGENTJAIL_TESTBED_KEEP_VM=1` only when intentionally trading disk for a faster
next run; retained gate VMs are still stopped. Manual `create` testbeds remain
persistent by design, while a failed partial creation is always deleted.

### At most 2 testbeds exist at once

Each testbed is a full disk clone (~28G), and nothing ever reaped them - four
stale boxes had quietly accumulated ~113G before anyone looked. `create` now
refuses past `MAX_TESTBEDS` (default 2) and tells you what to destroy:

```
testbed: 2 testbed(s) already exist and the cap is 2: dev release-gate
Destroy one first:            test/testbed/testbed.sh destroy <name>
Or reuse one:                 ... reset <name> && ... provision <name>
Or raise the cap for one run: MAX_TESTBEDS=3 ... create <name>
```

It **refuses rather than evicting the oldest**: a testbed may be mid-investigation
in another terminal, and destroying it to make room is a surprise this repo does
not ship. The caller decides what to drop.

**The release gate is not exempt - it asks for a slot.** `make e2e-release` needs
its configured `tb-<name>` VM and is the one command with a job that must finish,
so at the cap it offers to clear a slot rather than only refusing:

```
testbed: destroy testbed dev to free a slot for the release gate? [y/N]
```

A `no` fails the gate, exactly as a full disk would. It frees **one** slot and
stops - never a clean sweep - and never touches its own box. Consent is the whole
point: the gate earns a slot by asking, it is not handed one.

`TESTBED_RECLAIM` controls this:

| value | behavior |
|---|---|
| `ask` (default) | prompt per testbed until there is room |
| `always` | destroy without asking - for an unattended gate |
| `never` | refuse and fail early |

An unattended gate (no TTY) **dies with instructions rather than hanging** on a
prompt nobody will answer - set `TESTBED_RECLAIM=always` for that case. It never
guesses.

This caps how many testbeds **exist** (a disk concern). How many may **run** at
once is a different axis: macOS caps concurrent VMs at ~2, which `gate` handles
by stopping other running testbeds up front (`tart_stop_other_testbeds`).

The driver (Lima vs Tart) is auto-selected by host OS. `provision` builds the
tarball from the given worktree (default: this repo checkout), pushes it, and
runs `guest-provision.sh` inside the guest, which:

1. installs only the selected agent through npm,
2. keeps Codex authentication out of provisioning and injects it only for
   each live scenario,
3. runs `install.sh` with `LOCAL_TARBALL=` once and fails unless that single
   non-interactive install leaves the daemon running and the selected agent wired,
4. creates a seed project `~/work/demo` (git repo with an `origin` → allowed
   local bare remote and an `exfil` → forbidden remote, plus a dirty file).

### Live Codex authentication

```sh
AGENTJAIL_TESTBED_AGENT=codex make e2e-release

# Parallel worktree example:
AGENTJAIL_TESTBED_AGENT=codex \
AGENTJAIL_TESTBED_NAME=codex-approval-worktree \
make e2e-release
```

The gate requires a private file-backed cache at
`${CODEX_AUTH_FILE:-${CODEX_HOME:-~/.codex}/auth.json}`, verifies `codex login
status`, and installs the host's exact Codex CLI version in the guest. Override
that version only with `CODEX_TESTBED_VERSION`. The official Codex authentication
guide documents file credential storage and the headless cache-copy workflow.

Only `auth.json` is copied, immediately before a live Codex scenario. Both the
guest and host lifecycle remove it afterward, including interrupted runs. Host
Codex configuration, sessions, plugins, and MCP definitions never cross the
boundary. Treat the cache like a password and never record or publish the guest
while it is present. See ADR 0130-codex-live-gate.

### Live AWS STS credentials

The offline `credentialed-cli` scenario proves discovery and credentialed CLI
semantics against local verifiers. The live AWS workflow separately proves a
one-hour least-privilege STS role against real STS and S3 through a direct
brokered command, then proves an identified Codex session discovers and requests
that exact credential without copying it into a shell command:

```sh
bash test/testbed/run-aws-sts-live.sh
```

The runner prepares one disposable Tart clone, then prints one command for the
operator to run in a normal host terminal with `AWS_PROFILE`. Source-profile
material never enters the VM. The external provisioner streams only the assumed
role into the guest broker, waits for the scenarios, and removes the exact AWS
resources afterward. Required checks fail on any SKIP, missing SQLite lifecycle
event, failed direct AWS invocation, credential leak, or incomplete cleanup. See
[`docs/runbooks/aws-sts-testbed.md`](../../docs/runbooks/aws-sts-testbed.md).

---

## Linux side (Linux host) — DONE, for reference only

Installed on the host: QEMU (apt `qemu-system-x86 qemu-utils`), Lima v2.1.4
(static tarball → `/usr/local`), user in `kvm` group, `LIMA_HOME=$HOME/.local/share/lima`
(root disk is small; VM disks live under the same data volume). Template:
`lima-template.yaml` — Ubuntu 24.04 cloud image, 4 CPU / 4 GiB / 20 GiB,
`mounts: []` for isolation, cloud-init installs node/git/tmux/sqlite3 and
enables `loginctl enable-linger` so `systemd --user` (the agentjail daemon)
survives ssh disconnects.

Validated flow (all green on 2026-07-07, kernel 6.8, Landlock active):

```sh
test/testbed/testbed.sh create dev
test/testbed/testbed.sh provision dev --worktree .
test/testbed/testbed.sh test dev        # -> 11 pass, 0 fail
test/testbed/testbed.sh ssh dev         # poke by hand: agentjail status; claude
```

`test/testbed/scenarios/e2e-smoke.sh` asserts both tiers on the INSTALLED
binaries:

- **Tier 1 (hook):** allow project write; deny `~/.ssh/authorized_keys`,
  `~/.aws/credentials`, `rm -rf /`; deny carries a remediation hint.
- **Tier 2 (shield):** with cwd = the project dir (like a real session),
  Landlock blocks `~/.ssh` write + private-key read and allows project writes.

### Chaos scenarios — failure injection

Every other scenario is a happy-path feature test: nothing kills the daemon.
That blind spot shipped a real 3-day outage (AGE-212) — the daemon stopped, the
supervisor never restarted it, the shield kept activating so the statusline
stayed green, and the hook fell back to `levelAllow`. The agent ran with **no
policy enforcement** and nobody noticed.

The signature of that whole bug class is **`shield.activated` climbing while
`decisions` stays flat**. The shield opens the store on its own path, so it
stays healthy precisely when enforcement is off.

| Scenario | Injects | Asserts |
|---|---|---|
| `chaos-daemon-outage` | daemon stopped mid-session; stale socket file | hook still renders a decision and never hangs; fail-open is **visible** on stdout `systemMessage` (ADR 0073 — Claude Code discards hook stderr on exit 0) on both the claude and codex paths; sentinel written; `doctor` reports the fail-open window; the divergence signature reproduces; daemon + sentinel restored |
| `agent-conformance` | native hook JSON for Claude, Codex, and Cursor | common project allow and sensitive-path / destructive-command denies produce the correct adapter-specific result without requiring provider login |
| `codex-approval` | real Codex 0.147 TUI through explicit non-tunnel `agentjail run`, a guest-local bare Git remote, and a user-authored custom Bash `ask` | built-in and previously unknown custom rules open the same `shell-command` prompt; approve executes once; decline, `never`, and `--ignore-rules` leave no effect; guest auth is removed on exit |
| `credentialed-cli` | arbitrary credential IDs with generic environment/file bindings, local SigV4/bearer verifiers, and real Codex with disposable auth | Codex selects exact IDs from optional labels/tags, completes authenticated reads, never selects the decoy, and leaves value-free lifecycle audits; an unavailable ID and unsafe process-control binding fail closed |
| `tunnel-agent` | real Codex through the installed PATH shim with `AGENTJAIL_REQUIRE_TUNNEL=1` | strict policy/bypass matrix executes; SQLite proves the extension registered the session and decrypted non-empty model requests/responses; no fallback or all-SKIP result can pass |
| `chaos-supervisor-restart` | `SIGTERM` (clean exit) then `SIGKILL` (crash) to the daemon PID | supervisor respawns on **both** paths; `Restart=always` / `KeepAlive=true` pinned per OS (ADR 0070 — the updater's clean `exit(0)` went un-restarted under `Restart=on-failure`); enforcement proven real again, not just `is-active` green |
| `chaos-hook-tamper` | hook entry stripped / settings file deleted, daemon up **and** down | hookwatch re-injects with the daemon up (ADR 0026); does **not** with the daemon down — the watchdog is a goroutine inside the daemon, blind during the outage it should mitigate; a full file delete is a pinned gap (hookwatch only repairs an existing file) |

```sh
make chaos TESTBED=<name>                          # all three, non-zero if any fail
test/testbed/testbed.sh test <name> chaos-daemon-outage   # just one
```

**Status:** green on both platforms - 45 pass / 2 skip on a Linux Lima guest and
the same 45 / 2 on a macOS Tart guest (AGE-236). Both skips are the honest kind:
`doctor`'s `Enforcement=fail` needs a >1h gap (unit-tested instead), and
`Restart=always` is not-macOS.

**Cadence:** run locally **before pushing to `main`**, and before a major
release. Not every PR, not minor/patch, and not in CI - this is a gate you run
on real hardware before the change escapes, same class as `make e2e-release`.
Nothing enforces it, so a commit has only had a chaos pass if someone ran one.
See [ADR 0098](../../docs/adr/0098-chaos-run-cadence.md).

All three are safe to re-run and restore the daemon and any config they touch on
every exit path (`trap`). They skip cleanly when a precondition is missing (no
systemd/launchd, daemon already down, no `sqlite3`). They are deliberately **not**
in `record-cli-report.sh`'s list: they take minutes, and a report of a
deliberately broken box is not the CLI tour.

### The freshness guard

These scenarios assert behaviour that tracks HEAD, but they drive the *installed*
binaries. `chaos-lib.sh` compares the two and **aborts** rather than report
results nothing verified - a hook built before the feature it is asserted against
once produced 5 confident FAILs for code it did not contain.

A guest has no checkout, so it cannot compute the expected version itself:
`testbed.sh` passes it in as `CHAOS_EXPECTED_VERSION` (`lib.sh` `chaos_env`),
derived from the same `git describe` the Makefile's `DIST_VERSION` uses.

Practical consequence: **edit the worktree, and every chaos run aborts until you
re-provision**, because the tree describes as `-dirty` while the installed binary
does not. That is working as intended - re-run `provision` and the tarball is
rebuilt from the current tree. `CHAOS_SKIP_VERSION_CHECK=1` bypasses the check
with a loud warning; reach for it knowingly, not reflexively.

Note the guard's one blind spot: `git describe --dirty` yields the same string
for *any* dirty tree, so it cannot tell dirty-tree-A from dirty-tree-B. It
catches stale, not different. Commit before a run you intend to trust.

Two important lessons baked into the scenario:

1. **Shield grants cwd read-write.** Test from a *project* dir, never `$HOME`
   — launching from `$HOME` grants all of home RW and `~/.ssh` looks
   "unprotected" when it isn't.
2. **IMDS/cloud-metadata guard is shield-tier and cloud-only** (ADR 0049): it
   only fires when 169.254.169.254 is reachable, so it is NOT testable in a
   plain VM. Don't assert it at the hook tier.

---

## macOS Tart setup reference

The shared scripts use Tart on Apple Silicon. The golden image and the three
chaos scenarios were validated on macOS for AGE-236; the selected Codex release
gate must still pass on the exact commit being released.

### 1. Install Tart

```sh
brew install cirruslabs/cli/tart
```

### 2. Bake the approved golden macOS image (~20–25 GB, one-time)

Use the **vanilla** image (no Xcode — we only need node + CLT-level tools);
prune the pull cache afterwards to stay near the 20 GB budget:

```sh
tart clone ghcr.io/cirruslabs/macos-sequoia-vanilla:latest golden-macos-mitm
tart set golden-macos-mitm --cpu 4 --memory 4096
tart run golden-macos-mitm
# wait for IP, then (default creds admin/admin):
IP=$(tart ip golden-macos-mitm)
ssh admin@$IP   # password: admin
# Inside the VM:
#   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
#   eval "$(/opt/homebrew/bin/brew shellenv)" && echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
#   brew install node tmux git sqlite
#   # Bake host SSH pubkey for non-interactive guest_exec/scp:
#   mkdir -p ~/.ssh && chmod 700 ~/.ssh
#   echo "<your-pubkey-here>" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys
# Then exit and freeze the golden:
tart stop golden-macos-mitm
rm -rf ~/.tart/cache        # reclaim the OCI pull cache (several GB)
```

**SSH auth for `testbed.sh`:** the golden image should have your SSH
pubkey in `~/.ssh/authorized_keys` so `guest_exec`/`guest_push` work
non-interactively. If you skip the pubkey step, set `TART_SSH_PASSWORD=admin`
and install `sshpass` (`brew install sshpass-mac`) as a fallback.

Golden stays stopped forever; testbeds are instant APFS clones of it.
OS updates: re-bake the golden, never update inside a testbed (huge deltas).
Apple EULA allows max **2 running** macOS guests — clones at rest are fine.

### 2a. Install and maintain the approved extension

macOS testing uses one golden image. Apple can leave a system-extension activation
pending until a user approves it, and a headless Tart guest has no GUI in which to
make that decision. Copy the exact containing app into the GUI-booted golden
without rebuilding or re-signing it, install it at the stable path, and approve it
in the guest:

```sh
tart run golden-macos-mitm
# Copy while preserving the bundle, signatures, permissions, and xattrs to:
#   /Applications/AgentJail.app
/Applications/AgentJail.app/Contents/MacOS/AgentJail install-extension
```

Approve only through **System Settings → General → Login Items & Extensions →
Network Extensions**. Do not automate or bypass this. Keep the containing app at
`/Applications/AgentJail.app`: Apple packages and manages the system
extension through that app, and deleting it can remove the extension.

The current image was rebuilt and headlessly clone-validated on 2026-08-15:

| Field | Baked value |
|---|---|
| App | `com.blinkerlm.agentjail.app`, version `0.0.6` build `6` |
| App CDHash | `c2dc61054cd2dfb8f06a3b6f399c805d0ca5e683` |
| App executable SHA-256 | `f8c8593571660acb46045756c5520dac12b7d786db979f661239e5a3b7007f4c` |
| Extension | `com.blinkerlm.agentjail.app.extension`, version `0.0.6` build `6` |
| Extension CDHash | `b54dbeece72d5b83cfd6f4364f1b4d4998a25351` |
| Extension executable SHA-256 | `d57160d10a9b9063930eef73e40305a97757c7adeb6bc948ae83b538c8e9267a` |
| Signing team | `Q98Z3744J2` |
| Distribution checks | Developer ID signed, notarized, stapled, and accepted by `codesign`, `stapler`, and `spctl` |
| Signed network entitlement | `app-proxy-provider-systemextension` |
| App profile | `AgentjailTunnel App DevID`, UUID `f7a87d79-f2dd-487a-864d-f7d841f527bf` |
| Extension profile | `AgentjailTunnel Ext DevID`, UUID `abd956e2-1eaf-4381-8430-abd16f7c2a1e` |
| Provisioning scope | both profiles use `ProvisionsAllDevices=true` |

`ProvisionsAllDevices=true` is why a Tart VM does not need device registration in
the Apple Developer console. Approval is still required because signing authority
and user consent are separate checks. Tart's disk clone preserves the guest's
system-extension registration database, so approval survives cloning even though a
new headless guest could not create that state itself.

After approval, stop the golden cleanly; the stopped VM is the saved image. Verify
through a temporary headless clone, not by mutating the golden. The 2026-08-13
headless validation preserved `[activated enabled]`. Two consecutive runs in
the rebaked VM and one fresh-clone run each executed three required scenario
groups with 10 assertions passed and no failures. The optional Claude scenario
skipped because the minimal clone did not have Claude installed.

```sh
systemextensionsctl list
# Required exact state:
# com.blinkerlm.agentjail.app.extension ... [activated enabled]
test/tunnel-e2e/smoke_darwin.sh --strict
```

Strict smoke reports `TUNNEL_EXECUTED` and `TUNNEL_SKIPPED` separately. It fails if
the extension is missing or inactive, or if no tunnel scenario executes. An
all-SKIP result is never successful tunnel verification.

Rebuild `golden-macos-mitm` when the app or extension version, CDHash, Team ID,
bundle ID, profiles, or entitlements change, or when a macOS update invalidates
the activation. The baked artifact passed notarization, stapling, and Gatekeeper
checks, but the internal disk-clone workflow is not a clean downloaded-customer
installation test and does not alone prove production distribution readiness.

Never bake a MITM CA into the golden. AgentJail generates a fresh in-memory CA
for every tunnel session, applies trust only to that process, and removes the
session material during cleanup. See ADR 0136-tunnel-golden-image.

### 3. Validate the selected agent on the current commit

```sh
test/testbed/testbed.sh create mac-dev        # clone + run + wait for IP
AGENTJAIL_TESTBED_AGENT=codex test/testbed/testbed.sh provision mac-dev
test/testbed/testbed.sh ssh mac-dev
```

Known things to verify / likely fixes (commit them when done):

- [x] **SSH auth**: `lib.sh` supports key-based auth (bake pubkey into golden)
      or `TART_SSH_PASSWORD=admin` with `sshpass-mac` as fallback. Login shell
      (`bash -lc`) ensures brew PATH is available.
- [x] **Shell profile**: `guest-provision.sh` writes token to `~/.zprofile`
      on Darwin, `~/.bashrc` on Linux.
- [x] **npm install**: `guest-provision.sh` skips `sudo` when brew is present
      on macOS (brew-installed node owns its global prefix).
- [x] **install.sh service install**: `e2e-smoke.sh` checks `launchctl list |
      grep agentjail` on macOS, `systemctl --user is-active` on Linux.
- [x] **Gatekeeper**: `guest-provision.sh` runs `xattr -dr com.apple.quarantine`
      on `~/.agentjail/bin` after `install.sh` on Darwin.
- [ ] **Per-commit Codex gate**: `AGENTJAIL_TESTBED_AGENT=codex make e2e-release`
      completes with a real authenticated Codex run and zero scenario skips.

### 4. Done when

`create → provision → ssh → agentjail status → claude` works on a fresh clone,
same as the Linux flow above. Commit fixes to this directory on your working
branch, signed off (`git commit -s`; sign off with your own Git identity),
then push to your remote.

### Pulling this on the Mac

The Linux work lives on your remote, on your working branch. On the Mac,
fetch and check out the same branch from your remote (e.g. `origin`):

```sh
cd ~/Repos/AgentJail-Repos/agentjail   # the local-dev working copy
git fetch origin
git checkout <your-branch>
git pull origin <your-branch>
```

Then follow "Mac side" steps 1–4 above. **You only need to do the Tart /
macOS work** — Linux is already done and validated on the Linux host; do not
re-run or re-implement the Lima side.

---

## Release gate (the only trigger — no nightly)

This engine runs **on every release, not on a timer**. Before tagging `vX.Y.Z`:

```sh
make e2e-release        # == testbed.sh gate --worktree .
```

It resets the configured gate testbed to the clean golden (or creates it),
provisions the current worktree through the real installer, then runs
`e2e-smoke`, the authenticated Codex `codex-approval` and `credentialed-cli`
workflows, and the authenticated Codex `tunnel-agent` scenario. On Tart, that
tunnel assertion selects `golden-macos-mitm`; before starting Codex it runs the
strict Darwin host/path/port/protocol/bypass matrix and preserves its separate
structured result. It **exits non-zero on insufficient
host resources, missing
authentication, scenario failure, or install failure** and deletes the gate VM
afterward by default. Run it on Linux for the Linux build and on macOS for the
macOS build.

The tunnel-claiming real-agent scenario launches through the PATH shim with
`AGENTJAIL_REQUIRE_TUNNEL=1`, which selects the public `--require-tunnel`
launch flag without changing normal shim behavior. Its source of truth is the
post-watermark `audit_log` lifecycle (`tunnel.session_registered` and any
`tunnel.extension_started` failure reason), not terminal output. A tunnel setup
failure therefore stops the scenario before a model wait or fallback DNS work.
`codex-approval` is deliberately non-tunnel: command approval and host-proxy
semantics do not need the global Network Extension and must not inherit that
unrelated lifecycle dependency.

CI note: this is deliberately a **local** gate, not a GitHub Actions job —
Linux needs KVM and macOS needs a self-hosted Tart host, and the release is cut
by hand anyway. If that changes, `make e2e-release` is the single entry point to
wire in.

## Design notes

- **Reset ≠ destroy.** Testbeds are meant to live for days (poke, retest,
  keep state). `reset` reverts to golden in seconds: Lima applies a qcow2
  snapshot tag; Tart deletes + re-clones (APFS, instant).
- **No host mounts** (`mounts: []` / no Tart dir shares): files travel via
  `limactl cp` / `scp` only. Isolation is the point.
- **Why VMs, not containers:** the shield tier needs a real kernel
  (Landlock/seccomp on Linux, Seatbelt on macOS) and a real service manager.
- Stage 3 (scripted scenarios in `scenarios/`) and Stage 4 (nightly timers +
  report) are tracked in the project's tracking issue — see the "Lean rollout
  plan" comment there.
