# agentjail testbeds — clean-VM sandboxes

Persistent, named VMs that behave like a **real end-user machine**: full
kernel, systemd/launchd, no Go toolchain, no host mounts. Each worktree gets
its own testbed, so parallel feature builds never fight over the host's single
agentjail install — and the host is never polluted.

agentjail is always installed **through the real user path**: a release-layout
tarball (`make dist-tarball`) fed to the shipped `install.sh` via its
`LOCAL_TARBALL=` seam. The installer wires every detected agent once, exactly
as a piped end-user install does; the testbed does not run a second install to
repair or alter that result. Claude Code is installed via npm, like a human
would.

## Status / division of work

| Side | Host | Driver | Status |
|---|---|---|---|
| **Linux** | a Linux host | Lima/QEMU, `LIMA_HOME=$HOME/.local/share/lima` | ✅ **DONE — set up and validated end-to-end on the Linux host. Do not redo.** |
| **macOS** | your Apple-Silicon Mac | Tart | ✅ **DONE - `golden-macos` baked, provision + all three chaos scenarios green (AGE-236).** |

## Quick reference (both OSes)

```sh
test/testbed/testbed.sh create <name>                 # new VM + golden snapshot
test/testbed/testbed.sh provision <name> [--worktree <path>] [--with-codex]
test/testbed/testbed.sh ssh <name>
test/testbed/testbed.sh exec <name> -- <cmd>
test/testbed/testbed.sh test <name> [scenario] [--codex-auth <path>]
                                                       # run a scenario (default: e2e-smoke)
test/testbed/testbed.sh gate                          # RELEASE GATE (== make e2e-release)
test/testbed/testbed.sh snapshot <name> <tag>         # checkpoint
test/testbed/testbed.sh reset <name> [tag]            # revert to golden
test/testbed/testbed.sh ls
test/testbed/testbed.sh destroy <name>
```

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
`tb-release-gate` and is the one command with a job that must finish, so at the
cap it offers to clear a slot rather than only refusing:

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

1. installs Claude Code (`npm i -g @anthropic-ai/claude-code`),
2. seeds the login token if `~/.agentjail-testbed/token` exists and is readable
   on the host; otherwise installed-policy scenarios continue and live-agent
   scenarios skip,
3. runs `install.sh` with `LOCAL_TARBALL=` once and fails unless that single
   install leaves the daemon running and every detected agent wired,
4. creates a seed project `~/work/demo` (git repo with an `origin` → allowed
   local bare remote and an `exfil` → forbidden remote, plus a dirty file).

### Credential seeding (one-time, per host)

```sh
claude setup-token          # prints a long-lived OAuth token
mkdir -p ~/.agentjail-testbed
vi ~/.agentjail-testbed/token   # paste the token, single line
chmod 600 ~/.agentjail-testbed/token
```

Provision exports it as `CLAUDE_CODE_OAUTH_TOKEN` in the guest's `~/.bashrc`
(zsh on macOS — see Mac TODO below). The token is never baked into an image
and never committed. A host sandbox may deliberately make the file unreadable;
that does not block the clean-install release gate, but authenticated live-agent
scenarios report `SKIP`.

For the live Codex approval scenario, opt in to copying only the current
Codex `auth.json` into the disposable guest:

```sh
test/testbed/run-codex-approval-gate.sh
```

This path pins Codex CLI 0.146.0. Authentication is copied immediately before
the scenario rather than during provisioning, and both the guest scenario and
host runner remove it afterward. It does not copy host Codex config, plugins,
MCP definitions, or sessions. The complete host-side transcript is written to
the ignored `dist/codex-approval-gate.log` file. Do not record or publish the
guest filesystem while credentials are present.

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
| `codex-approval` | real Codex 0.146 TUI, a guest-local bare Git remote, and a user-authored custom Bash `ask` | built-in and previously unknown custom rules open the same `shell-command` prompt; approve executes once; decline, `never`, and `--ignore-rules` leave no effect; guest auth is removed on exit |
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

## Mac side — WHAT THE MAC AGENT NEEDS TO DO

> Context for the agent working on the Mac: the Linux half already runs on the
> Linux host. **Only do the macOS/Tart work below.** The shared scripts
> (`testbed.sh`, `lib.sh`, `guest-provision.sh`) already contain a Tart driver,
> written blind on the Linux host — your job is to bake the golden image,
> then validate/fix that driver on real hardware.

### 1. Install Tart

```sh
brew install cirruslabs/cli/tart
```

### 2. Bake the golden macOS image (~20–25 GB, one-time)

Use the **vanilla** image (no Xcode — we only need node + CLT-level tools);
prune the pull cache afterwards to stay near the 20 GB budget:

```sh
tart clone ghcr.io/cirruslabs/macos-sequoia-vanilla:latest golden-macos
tart set golden-macos --cpu 4 --memory 4096
tart run --no-graphics golden-macos &
# wait for IP, then (default creds admin/admin):
IP=$(tart ip golden-macos)
ssh admin@$IP   # password: admin
# Inside the VM:
#   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
#   eval "$(/opt/homebrew/bin/brew shellenv)" && echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
#   brew install node tmux git sqlite
#   # Bake host SSH pubkey for non-interactive guest_exec/scp:
#   mkdir -p ~/.ssh && chmod 700 ~/.ssh
#   echo "<your-pubkey-here>" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys
# Then exit and freeze the golden:
tart stop golden-macos
rm -rf ~/.tart/cache        # reclaim the OCI pull cache (several GB)
```

**SSH auth for `testbed.sh`:** the golden image should have your SSH
pubkey in `~/.ssh/authorized_keys` so `guest_exec`/`guest_push` work
non-interactively. If you skip the pubkey step, set `TART_SSH_PASSWORD=admin`
and install `sshpass` (`brew install sshpass-mac`) as a fallback.

Golden stays stopped forever; testbeds are instant APFS clones of it.
OS updates: re-bake the golden, never update inside a testbed (huge deltas).
Apple EULA allows max **2 running** macOS guests — clones at rest are fine.

### 3. Validate the Tart driver in `testbed.sh` / `lib.sh`

The Tart code paths are marked UNVALIDATED. Walk this and fix what breaks:

```sh
test/testbed/testbed.sh create mac-dev        # clone + run + wait for IP
test/testbed/testbed.sh provision mac-dev     # builds darwin tarball on the Mac, installs in guest
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
- [ ] **End-to-end check**: inside the testbed, `agentjail status` green,
      `claude` runs with the hook wired, a write to `~/.ssh/x` gets denied.

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

It resets a `release-gate` testbed to the clean golden (or creates it the first
time — that run is slow, ~5–8 min for cloud-init + node; later runs reset in
seconds), provisions the current worktree through the real installer, runs the
`e2e-smoke` scenario, and **exits non-zero on any failure** so it can gate the
tag. Wired into the pre-release checklist in `AGENTS.md`. Run it on the Linux
host for the Linux build and on the Mac for the macOS build.

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
