# Building the libkrun guest kernel from source

This is the **reproducibility recipe** for the kernel `Image` that the
custom-kernel spike loads via `krun_set_kernel`. The "fast path" in
`README.md` extracts the prebuilt blob from libkrunfw; this doc
exists so anyone can rebuild it from upstream Linux sources, swap in
a different config, or iterate on the kernel side of the agentjail
substrate without spelunking the brew bottle.

## What you'll build

- **Linux:** 6.12.87 (the version pinned in
  `containers/libkrunfw` Makefile at the time we extracted the
  kernel — see `findings/` for the commit reference).
- **Arch:** aarch64.
- **Output:** `arch/arm64/boot/Image` (raw kernel image). Drop into
  `agentjail/research/libkrun-spike/kernel/Image`.
- **Config:** `config-libkrunfw_aarch64-6.12.87` (in this directory).
  Pulled verbatim from
  <https://raw.githubusercontent.com/containers/libkrunfw/main/config-libkrunfw_aarch64>.

## Where to build it

The simplest reproducible path is **on a Linux aarch64 host** (e.g.
an Asahi Linux laptop, an AWS Graviton instance, or a Linux VM on
Apple Silicon). Cross-compilation from macOS works but adds a
toolchain detour and is outside the spike's scope; if you take that
route the upstream `containers/libkrunfw` repo has scripts
(`build_on_krunvm.sh`, `build_on_krunvm_fedora.sh`) that automate it
inside a libkrun VM.

### Cost of a from-source build

| Resource | Cost |
|---|---|
| Disk (Linux source + build) | ~3 GB |
| Toolchain (gcc, binutils, bison, flex, libelf-dev, libssl-dev) | ~500 MB on Debian/Ubuntu |
| Wall time (aarch64 build host, 8 cores) | ~6 minutes |
| Wall time (cross from macOS via Docker buildx aarch64 emulation) | ~45 minutes |

These numbers are why the spike default is "extract from libkrunfw"
rather than "build from source": every iteration on the spike
shouldn't pay a 6-minute kernel build tax. **The `KERNEL_BUILD.md`
recipe is the escape hatch when you need to actually change the
kernel.**

## Step-by-step (aarch64 Linux host)

```sh
# 1. Prereqs (Debian/Ubuntu). The list is the libkrunfw-Makefile
#    intersection of what's needed for a default `make Image`.
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
    build-essential bc bison flex libelf-dev libssl-dev cpio \
    rsync wget xz-utils

# 2. Source.
LINUX_VER=6.12.87
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${LINUX_VER}.tar.xz
tar -xJf linux-${LINUX_VER}.tar.xz
cd linux-${LINUX_VER}

# 3. Drop in our pinned config (from agentjail/research/libkrun-spike/kernel/).
cp /path/to/agentjail/research/libkrun-spike/kernel/config-libkrunfw_aarch64-6.12.87 .config
make olddefconfig

# 4. Build.
make -j$(nproc) Image

# 5. Install into the spike.
cp arch/arm64/boot/Image /path/to/agentjail/research/libkrun-spike/kernel/Image
```

The resulting `Image` (raw, ~22 MB) is byte-identical to what
libkrunfw 5.3.0 ships, modulo the `KBUILD_BUILD_*` reproducibility
flags. libkrunfw upstream sets:

```
KBUILD_BUILD_TIMESTAMP="Fri May  8 14:25:15 CEST 2026"
KBUILD_BUILD_USER=root
KBUILD_BUILD_HOST=libkrunfw
```

— set the same to reproduce the exact bytes; omit them and the
binary differs only in the `.notes` build-info section.

## How to iterate on the kernel config

```sh
# Start from the pinned config.
cd linux-6.12.87
cp .../kernel/config-libkrunfw_aarch64-6.12.87 .config

# Pick one of:
make menuconfig        # ncurses UI
make nconfig           # newer ncurses UI
make olddefconfig      # adopt all defaults for any new symbols

# Diff against baseline before committing back.
diff .config .../kernel/config-libkrunfw_aarch64-6.12.87
```

Save the diff as a new file in this directory
(`config-libkrunfw_aarch64-<version>-<your-slug>`) and update
`README.md` to point at it. **Do not overwrite the pinned baseline
config.**

## Sanity-checking your kernel boots

```sh
# From agentjail/research/libkrun-spike/:
cp arch/arm64/boot/Image kernel/Image
make -C kernel boot
```

Expected output:

```
[spike] custom kernel: kernel/Image (NNNNNNN bytes)
[spike] krun_create_ctx + config: NN.NN ms
[spike] entering guest at host_t=NN.NN ms (krun_start_enter does not return)
hello uptime=0.0N
```

If `krun_set_kernel` fails with `-EINVAL` (= 22), the Image format is
wrong — verify you built `arch/arm64/boot/Image` and not `vmlinux`
(ELF) or `Image.gz`.

If `krun_start_enter` returns `-EIO` (= 5) or the VM hangs, the
kernel built but cannot find the virtio-fs root — check
`CONFIG_VIRTIO_FS=y` and `CONFIG_VIRTIO_MMIO=y` are set in your
`.config` (they are in the pinned baseline).

## Why the libkrunfw config and not firecracker-microvm/kernel-tools

Both would work. We picked libkrunfw's config because:

- It's the config the libkrun runtime already supports — same
  virtio devices (fs, vsock, net), same console wiring, same init
  expectations. firecracker's minimal-vmlinux configs target
  Firecracker's virtio-mmio layout, which libkrun supports but
  hasn't been characterised against in our boot-time numbers.
- It's the easier baseline for "extract the prebuilt one and iterate"
  — `make kernel` gives you a byte-identical Image without any
  toolchain at all.

Logged in `agentjail/docs/DECISIONS.md` under the custom kernel entry.
