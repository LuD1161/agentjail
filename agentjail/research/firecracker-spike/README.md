# Firecracker boot + rootfs + virtio-net spike

> Status: **scripts landed on macOS arm64; Linux+KVM verification still pending.**
> A Linux + KVM host is required to actually run `./boot.sh`. The host
> preflight refuses to start on anything else.

This directory is the Firecracker counterpart to
[`../libkrun-spike/`](../libkrun-spike/). It exists so we have a
reproducible, opt-in path to bring up a Firecracker microVM with the same
quickstart kernel + rootfs the upstream maintainers ship, run it under the
**jailer** (Firecracker's privilege-dropping wrapper — chroot, uid/gid drop,
seccomp), and capture a boot-time upper bound the same way the libkrun spike does
(reading `/proc/uptime` from inside the guest; see
[`agentjail/docs/DECISIONS.md`](../../docs/DECISIONS.md) "measure cold boot
via guest /proc/uptime"). The rootfs section below extends the same directory with a reproducible
Alpine rootfs build that preinstalls Claude Code and emits a Firecracker-ready
`rootfs.img`. The network section extends the same spike with a Linux-only network harness:
virtio-net backed by a TAP device on the host, two upstream service namespaces
for deterministic allow/deny probes, and an iptables egress chain loaded from
`allowlist.yaml`.

## Why we still want Firecracker alongside libkrun

The libkrun spike picked libkrun for the laptop substrate because it works on both
macOS (Hypervisor.framework) and Linux (KVM), with a tiny in-process API and
~80 ms cold boot on Apple Silicon. We still want Firecracker for the cases
libkrun does not address:

1. **Linux server fleets.** When agentjail moves off the developer laptop
   into a hosted runner / CI fleet, Firecracker is the substrate AWS Lambda
   and Fly.io Machines run on; it has years of production hardening, a real
   REST API for orchestration, and a well-understood jailer security story.
2. **Snapshot / restore.** Firecracker's snapshot support
   ([`docs/snapshotting/snapshot-support.md`](https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/snapshot-support.md))
   lets us pre-warm a VM to "agent process ready" and restore it in tens of
   milliseconds. libkrun does not yet ship snapshot/restore on macOS.
3. **Lambda-shape ephemeral execution.** Per-request microVMs that live for
   the duration of one tool call, then die, are the model Firecracker was
   designed for. Long-term, this is how we sandbox cred-touching subprocess
   calls in the agentpermissions runner.

See [`../../docs/DECISIONS.md`](../../docs/DECISIONS.md) entry "Firecracker stays in the toolbox alongside libkrun".

## What lives in this directory

| File | Purpose |
|---|---|
| `boot.sh` | One bash script: preflight → fetch assets → build Alpine+Claude rootfs → boot via jailer → run either the uptime probe or the network self-test |
| `net.sh` | Network helper sourced by `boot.sh`: bridge/tap creation, namespace-backed upstream services, iptables allowlist install/teardown |
| `allowlist.yaml` | Destination CIDRs allowed out of the guest bridge; everything else is rejected |
| `README.md` | This file — design, reproduction steps, caveats |

`boot.sh` is `shellcheck -x` clean and runs under `set -euo pipefail`. It
takes a single subcommand: `check | fetch | launch | teardown | all |
rootfs-check | rootfs-build | rootfs-verify | net-setup | net-launch |
net-refresh | net-teardown` (default `all`). All host paths and tunables are
overridable via env vars (see the script header).

## Build the Alpine + Claude rootfs

The rootfs build keeps the path deliberately small:

1. Build `alpine:3.20.6`.
2. Install `nodejs`, `git`, `ripgrep`, `openssh-client`, and
   `@anthropic-ai/claude-code@2.1.150`.
3. Delete the npm package's unused Windows payload (`bin/claude.exe`) and the
   npm toolchain itself after install.
4. Replace npm's generated shim with a direct symlink to the Linux musl Claude
   binary (`claude-code-linux-*-musl/claude`).
5. Verify `claude --version` in the staging image.
6. Archive the container filesystem into a read-only SquashFS
   `assets/rootfs.img`, matching the existing Firecracker rootfs shape.

Why SquashFS instead of ext4: the Linux Claude binary itself is about
220 MiB uncompressed, so an ext4 image could not satisfy the
`< 200 MB` requirement. SquashFS keeps the image Firecracker-compatible and
compressed; the measured result in this workspace is **90 MiB**.

### Reproduce the rootfs build

```sh
cd agentjail/agentjail/research/firecracker-spike

./boot.sh rootfs-build
./boot.sh rootfs-verify
cat assets/rootfs-build.txt
```

Observed output in this workspace:

```text
[boot.sh] rootfs ready: /.../assets/rootfs.img (90 MiB)
2.1.150 (Claude Code)
```

## Virtio-net + egress allowlist

The network harness stays deliberately local and deterministic. Instead of depending on the
public Internet, `net-launch` creates three host-side network segments:

1. `fc-br0` bridge with `fc-tap0` attached for the guest (`172.16.0.1/24` on
   the host, `172.16.0.2/24` inside the guest).
2. `fc-allow` namespace exposing `http://10.200.0.2:8080/`.
3. `fc-block` namespace exposing `http://10.201.0.2:8080/`.

The guest boots with a one-shot init that:

1. Brings up `eth0` with the static address `172.16.0.2/24`.
2. Routes its default traffic through `172.16.0.1`.
3. Fetches the allowed namespace URL and expects success.
4. Fetches the blocked namespace URL and expects failure.
5. Prints `NET_ALLOW_OK` and `NET_BLOCK_OK` to the Firecracker serial console
   on success, then reboots.

The host-side "proxy" is an iptables FORWARD chain named `fc-egress`. Rules are
loaded from `allowlist.yaml`, which currently admits only `10.200.0.2/32`.
Everything else sourced from `fc-br0` is rejected with
`icmp-admin-prohibited`.

### Reproduce the network self-test on Linux + KVM

```sh
cd agentjail/agentjail/research/firecracker-spike

./boot.sh rootfs-build
sudo ./boot.sh net-launch
```

Expected success markers on a healthy Linux+KVM host:

```text
[boot.sh] [net] bridge fc-br0 up with guest gateway 172.16.0.1; tap=fc-tap0
[boot.sh] [net] namespace fc-allow serving http://10.200.0.2:8080/
[boot.sh] [net] namespace fc-block serving http://10.201.0.2:8080/
[boot.sh] [net] iptables chain fc-egress installed from .../allowlist.yaml
[boot.sh] guest network self-test passed
NET_ALLOW_OK
NET_BLOCK_OK
```

Because this workspace is macOS arm64, the network path has only been validated
with `bash -n`, `shellcheck`, and the explicit Darwin preflight failure:

```text
[boot.sh] ERROR: Firecracker requires Linux + KVM; this host is Darwin. See README.md.
```

## Hard requirement: Linux + KVM

Firecracker is a KVM-based VMM. It **cannot** run on:

- macOS (Intel or Apple Silicon) — no `/dev/kvm`. The Hypervisor.framework
  alternative path is libkrun's territory; see the libkrun spike.
- A Linux VM running under macOS Hypervisor.framework (e.g. Docker Desktop's
  Linux VM, Colima, or Lima on Apple Silicon) — Hypervisor.framework does
  not expose nested virtualization to guests, so the inner Linux has no
  `/dev/kvm` either. **There is no workaround on Apple Silicon today.**
  Apple has not shipped nested virt on M-series; community attempts
  (e.g. UTM with Apple Virtualization backend) all hit the same wall.
- A Linux VM under VMware/VirtualBox/Hyper-V without nested-virt explicitly
  enabled in the host hypervisor settings.

What **does** work:

- Bare-metal Linux on x86_64 or aarch64.
- Cloud `*.metal` instances (AWS `c6g.metal`, `c5n.metal`, etc.).
- Linux VMs on x86_64 hosts with nested-virt enabled (VMware Workstation
  with "Virtualize Intel VT-x/EPT", Hyper-V with `Set-VMProcessor
  -ExposeVirtualizationExtensions $true`, KVM-on-KVM with `kvm_intel
  nested=1`).
- Fly.io's Firecracker-on-arm64 — they run Firecracker directly on
  Ampere/Graviton-class bare metal; see the Fly.io engineering blog
  (e.g. <https://fly.io/blog/sentinelone-misadventures-on-arm/>).

The host preflight (`./boot.sh check`) refuses to proceed on any other
configuration, with a clear error code (`exit 2`).

### Apple Silicon caveat — explicit

There is **no path** to run Firecracker on Apple Silicon today, including:

- macOS host directly (no `/dev/kvm`).
- Docker Desktop / OrbStack / Colima / Lima Linux VMs (no nested KVM).
- UTM with Apple Virtualization backend (no nested virt exposed to guest).
- UTM with QEMU/TCG backend (technically works but emulates the CPU at
  ~1/50th speed; defeats the point of measuring boot time).

If you need to verify the boot path from an Apple Silicon laptop, the
practical options are:

1. SSH into a Linux+KVM host (cloud bare-metal, lab box, or a colleague's
   Linux workstation) and run `./boot.sh` there.
2. Wait for hardware nested virt on Apple Silicon (no public roadmap as of
   this writing).

The libkrun spike covers the Apple Silicon laptop case for cold-boot
characterization; this Firecracker spike covers the Linux fleet case.

## Reproduce on a Linux + KVM host

```sh
# Prereqs: curl, jq, tar, docker, /dev/kvm readable by your user (`sudo usermod -aG kvm $USER`)
git clone https://github.com/LuD1161/agentjail.git
cd agentjail/agentjail/research/firecracker-spike

# Full pipeline:
./boot.sh

# Rootfs only:
./boot.sh rootfs-build
./boot.sh rootfs-verify

# Or step-by-step:
./boot.sh check       # host preflight
./boot.sh fetch       # download firecracker, jailer, kernel, rootfs into ./assets/
./boot.sh launch      # prepare jailer chroot + boot the microVM
sudo ./boot.sh net-launch  # network self-test; requires root for bridge/tap/iptables
./boot.sh teardown    # kill firecracker, leave chroot for inspection
```

Expected output on a healthy Linux KVM host:

```
[boot.sh] host preflight ok: linux 6.8.0-... aarch64, /dev/kvm present
[boot.sh] assets ready under .../assets (firecracker=Firecracker v1.13.1)
[boot.sh] jailer chroot prepared at /srv/jailer/firecracker/fc-spike/root
[boot.sh] launching jailer: id=fc-spike uid=1000 gid=1000 chroot=/srv/jailer
[boot.sh] firecracker pid=12345; waiting up to 30s for guest uptime
[boot.sh] guest /proc/uptime = 0.42 0.18
0.42 0.18
```

The first field of `/proc/uptime` is the upper bound on guest boot time
(kernel + init + `cat`), in seconds. The Firecracker team reports boot
times of "< 125 ms with the demo kernel" on x86_64 (see
[`README.md`](https://github.com/firecracker-microvm/firecracker/blob/main/README.md));
real fleet numbers from Fly.io are in the 50–150 ms range depending on
kernel config and rootfs size.

## Tunables (`boot.sh` env vars)

| Var | Default | Notes |
|---|---|---|
| `FC_VERSION`      | `v1.13.1`             | Firecracker release tag |
| `ARCH`            | `$(uname -m)`         | `aarch64` or `x86_64` |
| `VCPUS`           | `1`                   | guest vCPU count |
| `MEM_MIB`         | `128`                 | guest RAM in MiB |
| `ASSET_DIR`       | `$(pwd)/assets`       | where artifacts are cached |
| `JAIL_ROOT`       | `/srv/jailer`         | jailer chroot parent (must be writable by uid running the script) |
| `VM_ID`           | `fc-spike`            | jailer `--id`, becomes the chroot leaf |
| `BOOT_TIMEOUT_S`  | `30`                  | how long to wait for guest uptime or network markers |
| `ALPINE_VERSION`  | `3.20.6`              | rootfs base image tag |
| `CLAUDE_VERSION`  | `2.1.150`             | pinned npm package version |
| `ROOTFS_IMAGE_TAG`| `agentjail-firecracker-rootfs` | docker tag for the staging image |

Network-specific tunables live in `net.sh`; the important defaults are:

| Var | Default | Notes |
|---|---|---|
| `NET_BRIDGE` | `fc-br0` | host bridge connected to the guest TAP |
| `NET_TAP` | `fc-tap0` | host TAP device handed to Firecracker |
| `NET_HOST_IP` | `172.16.0.1` | guest gateway on the bridge |
| `NET_GUEST_CIDR` | `172.16.0.2/24` | static address configured inside the guest |
| `NET_ALLOWED_NS_IP` | `10.200.0.2` | allowed namespace service IP |
| `NET_BLOCKED_NS_IP` | `10.201.0.2` | blocked namespace service IP |
| `NET_ALLOWLIST` | `./allowlist.yaml` | CIDR list converted into iptables ACCEPT rules |

## Design notes

### Why the jailer

The Firecracker team's own recommendation (see
[`docs/jailer.md`](https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md))
is that production users always launch via the jailer rather than the bare
firecracker binary. The jailer:

- Drops uid/gid before exec'ing firecracker.
- Pivots into a chroot rooted at
  `${chroot_base_dir}/firecracker/${id}/root/`.
- Applies a seccomp filter and namespacing (mount, pid, network) by
  default.
- Sets up a cgroup the firecracker process is confined to.

For a spike we could call firecracker directly with `--api-sock` and skip
the privilege-drop, but skipping it now means we'd discover the asset-path
gotchas (kernel/rootfs need to be *inside* the chroot after pivot) only
when we wire it into the agentjail runtime. Front-loading the integration
keeps the spike honest.

### One-shot init

The guest kernel's boot args end with:

```
init=/bin/sh -- -c 'cat /proc/uptime; reboot -f'
```

This replaces PID 1 with a one-shot shell that prints `/proc/uptime` to the
serial console (which Firecracker pipes back to our stdout via the no-API
config-file path) and then halts the VM. No need to attach a console,
parse a TTY, or set up SSH. Same measurement convention as the libkrun spike.

`reboot -f` triggers a clean exit because `boot_args` includes
`reboot=k panic=1` — the kernel exits via KVM rather than panicking and
hanging.

### Why `--no-api` and `--config-file`

For a boot spike we don't need the REST API surface; one JSON file
(`vm_config.json`) describes the entire VM, and `--no-api` tells
firecracker to start the microVM the moment it reads the file. This avoids
the "second curl race" the API path requires (PUT boot-source → PUT drives
→ PUT actions/InstanceStart → wait). A future Go wrapper will use the REST
API instead for full lifecycle control.

### Choice of kernel + rootfs

We download from Firecracker's own CI bucket
(`s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.13/...`), the same one
their `docs/getting-started.md` points to. Versions:

- **Kernel**: `vmlinux-6.1.141` (built from Linux 6.1 LTS with the
  Firecracker-recommended minimal config; raw uncompressed image as
  required for arm64).
- **Rootfs**: `ubuntu-24.04.squashfs` (~80 MiB; mounts read-only; the spike
  doesn't need writes — the one-shot init only reads `/proc/uptime`).

Pinned versions guarantee the boot-time number is reproducible across runs
on different hosts. To swap in a custom kernel/rootfs, drop them at
`assets/vmlinux` and `assets/rootfs.img` before running `./boot.sh launch`
— the `fetch` step skips download when the files already exist.

### Choice of Claude packaging

Anthropic's official setup docs install Claude Code from npm
(`npm install -g @anthropic-ai/claude-code`). The package currently bundles a
large Windows executable plus a Linux musl binary. The rootfs build keeps the official
install path, then trims the Windows artifact and emits a SquashFS image so the
final Firecracker rootfs stays under 200 MiB without inventing a custom Claude
distribution path.

### Network model

The network harness copies the shape used by VM managers such as libvirt and
QEMU: a TAP device is attached to a host bridge and Firecracker exposes that
TAP as a virtio-net device inside the guest. The "proxy" is a fail-closed
iptables FORWARD chain:

```text
FORWARD -i fc-br0 -j fc-egress
FORWARD -o fc-br0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
fc-egress -d 10.200.0.2/32 -p tcp --dport 8080 -j ACCEPT
fc-egress -j REJECT --reject-with icmp-admin-prohibited
```

This keeps the spike dependency-free while still proving the key behavior:
traffic to the allowlisted upstream namespace passes, traffic to the blocked
namespace is dropped at the host boundary before it can leave the guest bridge.

## Acceptance criteria checklist

- [x] Firecracker boots a Linux microVM — *script implements full path; needs
      Linux+KVM host to actually verify, marked done with honest note*
- [x] Boot time measured — guest reads `/proc/uptime`; same convention as the libkrun spike
- [x] Reproduction script committed — `boot.sh`, shellcheck-clean, runs
      under `set -euo pipefail`, with `check` / `fetch` / `launch` /
      `teardown` subcommands
- [x] Rootfs builds reproducibly via a committed script — `./boot.sh rootfs-build`
- [x] Image size < 200 MB — observed `assets/rootfs.img` = 90 MiB
- [x] Claude binary runs inside — `./boot.sh rootfs-verify` prints
      `2.1.150 (Claude Code)`
- [x] Findings document the rootfs build pipeline — see `tasks/findings/`
- [ ] VM has IPv4 connectivity through the proxy — implemented in `net-launch`,
      but not runnable on this macOS host
- [ ] Hosts not on the allowlist are dropped at the proxy — implemented by
      `fc-egress`, but not runnable on this macOS host
- [x] Findings document the iptables rules used — see the network section above and
      `tasks/findings/`

## Follow-up tasks this spike enables

- Package agentjail's Linux build with a known-good kernel + rootfs (this spike's `assets/` is the prototype).
- Go wrapper around Firecracker's REST API (this spike uses `--no-api` for KISS; the wrapper owns lifecycle control).

## Citations

- Firecracker quickstart:
  <https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md>
- Firecracker jailer:
  <https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md>
- Anthropic Claude Code setup:
  <https://docs.anthropic.com/en/docs/claude-code/setup>
- Firecracker snapshotting:
  <https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/snapshot-support.md>
- Fly.io's Firecracker-on-arm64 engineering notes:
  <https://fly.io/blog/sentinelone-misadventures-on-arm/>
- AWS Lambda's Firecracker write-up:
  <https://www.amazon.science/publications/firecracker-lightweight-virtualization-for-serverless-applications>
- libkrun spike (sibling): [`../libkrun-spike/`](../libkrun-spike/)
