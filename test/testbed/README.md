# agentjail testbeds — clean-VM sandboxes (follow-up)

Persistent, named VMs that behave like a **real end-user machine**: full
kernel, systemd/launchd, no Go toolchain, no host mounts. Each worktree gets
its own testbed, so parallel feature builds never fight over the host's single
agentjail install — and the host is never polluted.

agentjail is always installed **through the real user path**: a release-layout
tarball (`make dist-tarball`) fed to the shipped `install.sh` via its
`LOCAL_TARBALL=` seam, then `agentjail install --for claude-code`. Claude Code
is installed via npm, like a human would.

## Status / division of work

| Side | Host | Driver | Status |
|---|---|---|---|
| **Linux** | **a Linux host** (this box) | Lima/QEMU, `LIMA_HOME=$HOME/.local/share/lima` | ✅ **DONE — set up and validated end-to-end on a Linux host. Do not redo.** |
| **macOS** | an Apple-Silicon Mac | Tart | ⬜ TODO — **this is the only part the Mac-side agent needs to do** (see "Mac side" below) |

## Quick reference (both OSes)

```sh
test/testbed/testbed.sh create <name>                 # new VM + golden snapshot
test/testbed/testbed.sh provision <name> [--worktree <path>]
test/testbed/testbed.sh ssh <name>
test/testbed/testbed.sh exec <name> -- <cmd>
test/testbed/testbed.sh test <name> [scenario]        # run a scenario (default: e2e-smoke)
test/testbed/testbed.sh snapshot <name> <tag>         # checkpoint
test/testbed/testbed.sh reset <name> [tag]            # revert to golden
test/testbed/testbed.sh ls
test/testbed/testbed.sh destroy <name>
```

The driver (Lima vs Tart) is auto-selected by host OS. `provision` builds the
tarball from the given worktree (default: this repo checkout), pushes it, and
runs `guest-provision.sh` inside the guest, which:

1. installs Claude Code (`npm i -g @anthropic-ai/claude-code`),
2. seeds the login token if `~/.agentjail-testbed/token` exists on the host,
3. runs `install.sh` with `LOCAL_TARBALL=`, then `agentjail install --for claude-code`,
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
and never committed.

---

## Linux side (a Linux host) — DONE, for reference only

Installed on the server: QEMU (apt `qemu-system-x86 qemu-utils`), Lima v2.1.4
(static tarball → `/usr/local`), user in `kvm` group, `LIMA_HOME=$HOME/.local/share/lima`
(root disk is small; VM disks live on `/DATA`). Template:
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
> a Linux host. **Only do the macOS/Tart work below.** The shared scripts
> (`testbed.sh`, `lib.sh`, `guest-provision.sh`) already contain a Tart driver,
> written blind on the Linux server — your job is to bake the golden image,
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
# Then exit and freeze the golden:
tart stop golden-macos
rm -rf ~/.tart/cache        # reclaim the OCI pull cache (several GB)
```

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

- [ ] **SSH auth**: `lib.sh` uses `ssh admin@ip` — cirruslabs images accept
      password `admin`; for non-interactive `guest_exec`/`scp` you'll likely
      want `ssh-copy-id` during golden bake (add your pubkey to the golden so
      all clones inherit it), or `sshpass`. Pick one, bake it into step 2.
- [ ] **Shell profile**: `guest-provision.sh` appends the token export to
      `~/.bashrc`; macOS default shell is zsh — make it write `~/.zprofile`
      (or both) when on darwin.
- [ ] **npm install**: on the vanilla image `npm i -g` may need
      `sudo` (admin password) or brew-node prefix — verify.
- [ ] **install.sh service install**: `agentjail install` installs a launchd
      LaunchAgent — verify it loads inside the VM (`launchctl list | grep agentjail`).
- [ ] **Gatekeeper**: locally-built (unsigned) binaries may need
      `xattr -dr com.apple.quarantine ~/.agentjail/bin` or ad-hoc codesign
      inside the guest — `test/macos-gatekeeper/verify.sh` has prior art.
- [ ] **End-to-end check**: inside the testbed, `agentjail status` green,
      `claude` runs with the hook wired, a write to `~/.ssh/x` gets denied.

### 4. Done when

`create → provision → ssh → agentjail status → claude` works on a fresh clone,
same as the Linux flow above. Commit fixes to this directory on the
`security/2026-07-07-review-fixes` branch (signed, `git commit -s`, identity
`You <you@example.com>`), then push to `origin`.

### Pulling this on the Mac

The Linux work is on `origin` (branch `security/2026-07-07-review-fixes`).
On the laptop:

```sh
cd ~/Repos/AgentJail-Repos/agentjail   # the local-dev working copy
git fetch origin
git checkout security/2026-07-07-review-fixes
git pull origin security/2026-07-07-review-fixes
```

Then follow "Mac side" steps 1–4 above. **You only need to do the Tart /
macOS work** — Linux is already done and validated on a Linux host; do not
re-run or re-implement the Lima side.

---

## Design notes

- **Reset ≠ destroy.** Testbeds are meant to live for days (poke, retest,
  keep state). `reset` reverts to golden in seconds: Lima applies a qcow2
  snapshot tag; Tart deletes + re-clones (APFS, instant).
- **No host mounts** (`mounts: []` / no Tart dir shares): files travel via
  `limactl cp` / `scp` only. Isolation is the point.
- **Why VMs, not containers:** the shield tier needs a real kernel
  (Landlock/seccomp on Linux, Seatbelt on macOS) and a real service manager.
- Stage 3 (scripted scenarios in `scenarios/`) and Stage 4 (nightly timers +
  Planka report) are tracked in Linear follow-up — see the "Lean rollout plan"
  comment there.
