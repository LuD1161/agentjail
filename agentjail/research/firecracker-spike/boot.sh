#!/usr/bin/env bash
# — Firecracker boot + rootfs + virtio-net spike.
#
# Downloads Firecracker + the project's quickstart kernel + a minimal rootfs,
# can build a custom Alpine+Claude rootfs image, then starts Firecracker via
# the jailer and boots a Linux microVM. The default boot path prints the guest's
# /proc/uptime as the cold-boot upper bound, mirroring the measurement
# convention used by the  libkrun spike. The net path wires virtio-net to a
# TAP-backed bridge and exercises a deterministic host-side allowlist.
#
# Hard requirement: a Linux host with KVM. Firecracker is a KVM-based VMM and
# cannot run on macOS (no /dev/kvm) or on Apple Silicon Linux VMs without
# nested virt. See README.md for the Apple Silicon caveat.
#
# Usage:
#   ./boot.sh               # full boot pipeline: fetch -> jailer-launch -> uptime -> teardown
#   ./boot.sh check         # only run the host preflight (kvm + arch)
#   ./boot.sh fetch         # only download artifacts into ./assets/
#   ./boot.sh launch        # boot-only path; prints guest /proc/uptime
#   ./boot.sh teardown      # kill any running firecracker/jailer
#   ./boot.sh rootfs-check  # docker availability preflight
#   ./boot.sh rootfs-build  # build Alpine rootfs.img with Claude preinstalled
#   ./boot.sh rootfs-verify # run `claude --version` in the built Alpine image
#   ./boot.sh net-setup     # create bridge/tap/namespaces + iptables allowlist (root)
#   ./boot.sh net-launch    # run the networked guest self-test (root)
#   ./boot.sh net-refresh   # reload only the iptables allowlist chain (root)
#   ./boot.sh net-teardown  # remove bridge/tap/namespaces + iptables rules (root)
#
# Environment overrides (all optional):
#   FC_VERSION       Firecracker release tag, default v1.13.1
#   ARCH             aarch64 | x86_64, default = $(uname -m)
#   VCPUS            guest vCPU count, default 1
#   MEM_MIB          guest RAM in MiB, default 128
#   ASSET_DIR        download destination, default ./assets
#   JAIL_ROOT        jailer chroot parent, default /srv/jailer
#   VM_ID            jailer --id, default fc-spike
#   BOOT_TIMEOUT_S   seconds to wait for the guest output, default 30
#   ALPINE_VERSION   rootfs base image tag, default 3.20.6
#   CLAUDE_VERSION   npm package version, default 2.1.150
#   ROOTFS_IMAGE_TAG docker tag used for the staging image
#   NET_*            see net.sh for bridge/tap/allowlist tunables
#
# Exit codes:
#   0  boot or network self-test succeeded
#   2  host preflight failed (not linux, no kvm, missing tool)
#   3  asset fetch failed
#   4  firecracker/jailer launch failed
#   5  guest never printed expected output within BOOT_TIMEOUT_S
#   6  rootfs build or verification failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

FC_VERSION="${FC_VERSION:-v1.13.1}"
ARCH="${ARCH:-$(uname -m)}"
VCPUS="${VCPUS:-1}"
MEM_MIB="${MEM_MIB:-128}"
ASSET_DIR="${ASSET_DIR:-${SCRIPT_DIR}/assets}"
JAIL_ROOT="${JAIL_ROOT:-/srv/jailer}"
VM_ID="${VM_ID:-fc-spike}"
BOOT_TIMEOUT_S="${BOOT_TIMEOUT_S:-30}"
ALPINE_VERSION="${ALPINE_VERSION:-3.20.6}"
CLAUDE_VERSION="${CLAUDE_VERSION:-2.1.150}"
ROOTFS_IMAGE_TAG="${ROOTFS_IMAGE_TAG:-agentjail-firecracker-rootfs}"
ROOTFS_CONTAINER_NAME="${ROOTFS_IMAGE_TAG}-export"
ROOTFS_WORK_DIR="${ROOTFS_WORK_DIR:-${SCRIPT_DIR}/.rootfs-work}"
ROOTFS_MAX_BYTES=$((200 * 1024 * 1024))
ROOTFS_IMAGE_PATH="${ASSET_DIR}/rootfs.img"
ROOTFS_METADATA_PATH="${ASSET_DIR}/rootfs-build.txt"

log { printf '[boot.sh] %s\n' "$*" >&2; }
die { log "ERROR: $*"; exit "${2:-1}"; }

firecracker_arch {
  case "$ARCH" in
    aarch64|arm64) printf 'aarch64' ;;
    x86_64|amd64) printf 'x86_64' ;;
    *) die "unsupported ARCH=$ARCH (need aarch64/arm64 or x86_64/amd64)" 2 ;;
  esac
}

docker_arch {
  case "$ARCH" in
    aarch64|arm64) printf 'arm64' ;;
    x86_64|amd64) printf 'amd64' ;;
    *) die "unsupported ARCH=$ARCH (need aarch64/arm64 or x86_64/amd64)" 2 ;;
  esac
}

# shellcheck disable=SC1091
. "${SCRIPT_DIR}/net.sh"

# ---------- host preflight ----------------------------------------------------

cmd_check {
  local os
  os="$(uname -s)"
  if [ "$os" != "Linux" ]; then
    die "Firecracker requires Linux + KVM; this host is $os. See README.md." 2
  fi
  if [ ! -e /dev/kvm ]; then
    die "/dev/kvm not present. Enable KVM or run on bare metal / nested-virt VM." 2
  fi
  if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
    die "/dev/kvm not readable+writable by uid=$(id -u). Add user to kvm group." 2
  fi
  firecracker_arch >/dev/null
  for tool in curl jq tar; do
    command -v "$tool" >/dev/null 2>&1 || die "missing host tool: $tool" 2
  done
  log "host preflight ok: linux $(uname -r) $(firecracker_arch), /dev/kvm present"
}

cmd_rootfs_check {
  command -v docker >/dev/null 2>&1 || die "missing host tool: docker" 2
  docker version >/dev/null 2>&1 || die "docker daemon not reachable" 2
  log "rootfs preflight ok: docker available"
}

# ---------- asset fetch -------------------------------------------------------

cmd_fetch {
  mkdir -p "$ASSET_DIR"
  cd "$ASSET_DIR"

  local fc_tgz fc_url
  fc_tgz="firecracker-${FC_VERSION}-$(firecracker_arch).tgz"
  fc_url="https:/github.com/firecracker-microvm/firecracker/releases/download/${FC_VERSION}/${fc_tgz}"
  if [ ! -x "./firecracker" ] || [ ! -x "./jailer" ]; then
    log "fetching firecracker $FC_VERSION ($ARCH) from $fc_url"
    curl --fail --location --silent --show-error -o "$fc_tgz" "$fc_url" \
      || die "firecracker download failed" 3
    tar -xzf "$fc_tgz"
    local extracted_dir
    extracted_dir="$(find . -maxdepth 1 -type d -name 'release-*' | head -n 1)"
    [ -n "$extracted_dir" ] || die "tarball layout changed; cannot find release-* dir" 3
    cp "$extracted_dir/firecracker-${FC_VERSION}-$(firecracker_arch)" ./firecracker
    cp "$extracted_dir/jailer-${FC_VERSION}-$(firecracker_arch)" ./jailer
    chmod +x ./firecracker ./jailer
  fi

  local kernel_url rootfs_url
  if [ "$(firecracker_arch)" = "aarch64" ]; then
    kernel_url="https:/s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.13/aarch64/vmlinux-6.1.141"
    rootfs_url="https:/s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.13/aarch64/ubuntu-24.04.squashfs"
  else
    kernel_url="https:/s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.13/x86_64/vmlinux-6.1.141"
    rootfs_url="https:/s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.13/x86_64/ubuntu-24.04.squashfs"
  fi

  [ -s ./vmlinux ] || curl --fail --location --silent --show-error -o ./vmlinux "$kernel_url" \
    || die "kernel download failed" 3
  [ -s ./rootfs.img ] || curl --fail --location --silent --show-error -o ./rootfs.img "$rootfs_url" \
    || die "rootfs download failed" 3

  log "assets ready under $ASSET_DIR (firecracker=$(./firecracker --version 2>&1 | head -n1))"
}

# ---------- alpine+claude rootfs build ---------------------------------------

cleanup_rootfs_artifacts {
  docker rm -f "$ROOTFS_CONTAINER_NAME" >/dev/null 2>&1 || true
  rm -rf "$ROOTFS_WORK_DIR"
}

rootfs_dockerfile {
  cat <<EOF
FROM alpine:${ALPINE_VERSION}

RUN apk add --no-cache \
    bash \
    ca-certificates \
    git \
    nodejs \
    npm \
    openssh-client \
    ripgrep \
  && npm install -g @anthropic-ai/claude-code@${CLAUDE_VERSION} \
  && npm cache clean --force \
  && case "\$(uname -m)" in \
       aarch64) claude_pkg='@anthropic-ai/claude-code-linux-arm64-musl' ;; \
       x86_64) claude_pkg='@anthropic-ai/claude-code-linux-x64-musl' ;; \
       *) echo "unsupported arch: \$(uname -m)" >&2; exit 1 ;; \
     esac \
  && rm -f /usr/local/bin/claude \
  && rm -f /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe \
  && ln -sf "/usr/local/lib/node_modules/@anthropic-ai/claude-code/node_modules/\${claude_pkg}/claude" /usr/local/bin/claude \
  && rm -rf /usr/lib/node_modules/npm \
  && rm -f /usr/bin/npm /usr/bin/npx /usr/bin/node-gyp \
  && adduser -D -h /home/agent agent \
  && install -d -m 0755 -o agent -g agent /home/agent/.claude /workspace

ENV HOME=/home/agent
ENV PATH=/usr/local/bin:/usr/bin:/bin
WORKDIR /workspace
CMD ["claude", "--version"]
EOF
}

cmd_rootfs_build {
  cmd_rootfs_check
  mkdir -p "$ASSET_DIR"
  cleanup_rootfs_artifacts
  mkdir -p "$ROOTFS_WORK_DIR"

  local dockerfile_path
  dockerfile_path="$ROOTFS_WORK_DIR/Dockerfile.rootfs"
  rootfs_dockerfile > "$dockerfile_path"

  log "building alpine rootfs image tag=$ROOTFS_IMAGE_TAG alpine=$ALPINE_VERSION claude=$CLAUDE_VERSION"
  docker build \
    --platform "linux/$(docker_arch)" \
    -t "$ROOTFS_IMAGE_TAG" \
    -f "$dockerfile_path" \
    "$ROOTFS_WORK_DIR" \
    >/dev/null || die "docker build failed" 6

  log "verifying Claude CLI inside staging image"
  docker run --rm --platform "linux/$(docker_arch)" "$ROOTFS_IMAGE_TAG" claude --version \
    | tee "$ROOTFS_WORK_DIR/claude-version.txt" \
    >/dev/null || die "claude --version failed inside staging image" 6

  log "packing squashfs rootfs image at $ROOTFS_IMAGE_PATH"
  docker run --rm \
    --platform "linux/$(docker_arch)" \
    -v "$ASSET_DIR:/out" \
    --entrypoint sh \
    "$ROOTFS_IMAGE_TAG" \
    -lc "
      set -eu
      apk add --no-cache squashfs-tools >/dev/null
      rm -rf /tmp/rootfs-stage
      mkdir -p /tmp/rootfs-stage
      tar \
        --exclude='./out' \
        --exclude='./proc' \
        --exclude='./sys' \
        --exclude='./dev' \
        --exclude='./tmp/rootfs-stage' \
        -C / -cf - . | tar -C /tmp/rootfs-stage -xf -
      rm -f /out/rootfs.img
      mksquashfs /tmp/rootfs-stage /out/rootfs.img -comp zstd -b 1M -noappend >/dev/null
    " >/dev/null || die "rootfs packaging failed" 6

  local rootfs_bytes rootfs_mib
  rootfs_bytes="$(wc -c < "$ROOTFS_IMAGE_PATH" | tr -d '[:space:]')"
  rootfs_mib=$(( (rootfs_bytes + 1048575) / 1048576 ))
  if [ "$rootfs_bytes" -ge "$ROOTFS_MAX_BYTES" ]; then
    die "rootfs.img is ${rootfs_mib} MiB; must stay under 200 MiB" 6
  fi

  {
    printf 'alpine=%s\n' "$ALPINE_VERSION"
    printf 'claude=%s\n' "$CLAUDE_VERSION"
    printf 'arch=%s\n' "$(docker_arch)"
    printf 'rootfs_bytes=%s\n' "$rootfs_bytes"
    printf 'rootfs_mib=%s\n' "$rootfs_mib"
    printf 'claude_version_output=%s\n' "$(tr -d '\r' < "$ROOTFS_WORK_DIR/claude-version.txt" | tr '\n' ' ' | sed 's/  */g')"
  } > "$ROOTFS_METADATA_PATH"

  rm -rf "$ROOTFS_WORK_DIR"
  log "rootfs ready: $ROOTFS_IMAGE_PATH (${rootfs_mib} MiB)"
}

cmd_rootfs_verify {
  cmd_rootfs_check
  docker image inspect "$ROOTFS_IMAGE_TAG" >/dev/null 2>&1 \
    || die "missing docker image $ROOTFS_IMAGE_TAG; run rootfs-build first" 6
  docker run --rm --platform "linux/$(docker_arch)" "$ROOTFS_IMAGE_TAG" claude --version \
    || die "claude --version failed inside staging image" 6
}

# ---------- jailer-managed launch --------------------------------------------

JAIL_DIR_CACHE=""

jail_dir {
  if [ -z "$JAIL_DIR_CACHE" ]; then
    JAIL_DIR_CACHE="${JAIL_ROOT}/firecracker/${VM_ID}/root"
  fi
  printf '%s' "$JAIL_DIR_CACHE"
}

boot_args_for_mode {
  local mode="${1:-boot}"
  case "$mode" in
    boot)
      printf "%s" "console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd init=/bin/sh -- -c 'cat /proc/uptime; reboot -f'"
      ;;
    network)
      net_boot_args
      ;;
    *)
      die "unknown boot mode: $mode" 4
      ;;
  esac
}

network_interfaces_json {
  local mode="${1:-boot}"
  if [ "$mode" = "network" ]; then
    cat <<JSON
  ,
  "network-interfaces": [
    {
      "iface_id": "eth0",
      "guest_mac": "${NET_GUEST_MAC}",
      "host_dev_name": "${NET_TAP}"
    }
  ]
JSON
  fi
}

cmd_prepare_chroot {
  local mode="${1:-boot}"
  local jd
  jd="$(jail_dir)"
  mkdir -p "$jd"
  ln -f "$ASSET_DIR/vmlinux" "$jd/vmlinux" 2>/dev/null || cp "$ASSET_DIR/vmlinux" "$jd/vmlinux"
  ln -f "$ASSET_DIR/rootfs.img" "$jd/rootfs.img" 2>/dev/null || cp "$ASSET_DIR/rootfs.img" "$jd/rootfs.img"
  cat > "$jd/vm_config.json" <<JSON
{
  "boot-source": {
    "kernel_image_path": "vmlinux",
    "boot_args": $(net_json_string "$(boot_args_for_mode "$mode")")
  },
  "drives": [
    {
      "drive_id": "rootfs",
      "path_on_host": "rootfs.img",
      "is_root_device": true,
      "is_read_only": true
    }
  ],
  "machine-config": {
    "vcpu_count": ${VCPUS},
    "mem_size_mib": ${MEM_MIB},
    "smt": false
  }
$(network_interfaces_json "$mode")
}
JSON
  log "jailer chroot prepared at $jd (mode=${mode})"
}

cmd_launch {
  local mode="${1:-boot}"
  cmd_prepare_chroot "$mode"
  local jd uid gid
  jd="$(jail_dir)"
  uid="$(id -u)"
  gid="$(id -g)"
  log "launching jailer: id=$VM_ID uid=$uid gid=$gid chroot=$JAIL_ROOT"
  "$ASSET_DIR/jailer" \
    --id "$VM_ID" \
    --exec-file "$ASSET_DIR/firecracker" \
    --uid "$uid" \
    --gid "$gid" \
    --chroot-base-dir "$JAIL_ROOT" \
    -- \
    --no-api \
    --config-file "vm_config.json" \
    --api-sock "fc.sock" \
    >"$jd/fc.stdout" 2>"$jd/fc.stderr" &
  echo $! > "$jd/fc.pid"
  log "firecracker pid=$(cat "$jd/fc.pid"); waiting up to ${BOOT_TIMEOUT_S}s for guest output"

  local waited=0
  while [ "$waited" -lt "$BOOT_TIMEOUT_S" ]; do
    if [ "$mode" = "network" ]; then
      if grep -q 'NET_ALLOW_OK' "$jd/fc.stdout" 2>/dev/null && grep -q 'NET_BLOCK_OK' "$jd/fc.stdout" 2>/dev/null; then
        log "guest network self-test passed"
        printf 'NET_ALLOW_OK\nNET_BLOCK_OK\n'
        return 0
      fi
      if grep -q 'NET_ALLOW_FAIL\|NET_BLOCK_FAIL' "$jd/fc.stdout" 2>/dev/null; then
        log "guest network self-test failed (see $jd/fc.stdout)"
        return 5
      fi
    elif grep -Eq '^[0-9]+\.[0-9]+ [0-9]+\.[0-9]+' "$jd/fc.stdout" 2>/dev/null; then
      local uptime
      uptime="$(grep -Eo '^[0-9]+\.[0-9]+ [0-9]+\.[0-9]+' "$jd/fc.stdout" | head -n1)"
      log "guest /proc/uptime = $uptime"
      printf '%s\n' "$uptime"
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done

  log "guest never printed expected output (see $jd/fc.stdout and $jd/fc.stderr)"
  return 5
}

# ---------- teardown ---------------------------------------------------------

cmd_teardown {
  local jd pid
  jd="$(jail_dir)"
  if [ -f "$jd/fc.pid" ]; then
    pid="$(cat "$jd/fc.pid" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      log "killing firecracker pid=$pid"
      kill -TERM "$pid" 2>/dev/null || true
      sleep 1
      kill -KILL "$pid" 2>/dev/null || true
    fi
    rm -f "$jd/fc.pid"
  fi
  log "teardown done"
}

# ---------- entry point ------------------------------------------------------

main {
  local sub="${1:-all}"
  case "$sub" in
    check) cmd_check ;;
    rootfs-check) cmd_rootfs_check ;;
    rootfs-build) cmd_rootfs_build ;;
    rootfs-verify) cmd_rootfs_verify ;;
    fetch) cmd_check; cmd_fetch ;;
    launch) cmd_check; cmd_launch ;;
    teardown) cmd_teardown ;;
    net-setup) cmd_net_setup ;;
    net-launch) cmd_net_launch ;;
    net-refresh) cmd_net_refresh ;;
    net-teardown) cmd_net_teardown ;;
    all)
      cmd_check
      cmd_fetch
      trap cmd_teardown EXIT
      cmd_launch
      ;;
    *)
      die "unknown subcommand: $sub (use one of: check fetch launch teardown all rootfs-check rootfs-build rootfs-verify net-setup net-launch net-refresh net-teardown)"
      ;;
  esac
}

main "$@"
