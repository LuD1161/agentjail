#!/usr/bin/env bash
# lib.sh — shared helpers for testbed.sh (AGE-146).
# Sourced, not executed.

set -euo pipefail

TB_PREFIX="tb-"
TESTBED_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$TESTBED_DIR/../.." && pwd)"

# Linux testbeds keep VM disks on the big data disk, not the root partition.
if [ "$(uname -s)" = "Linux" ] && [ -d /DATA ]; then
    export LIMA_HOME="${LIMA_HOME:-/DATA/lima}"
fi

die() { echo "testbed: $*" >&2; exit 1; }
log() { echo "==> $*" >&2; }

# Driver is chosen by host OS: Lima/QEMU on Linux (the home server),
# Tart on macOS (the laptop). Override with TESTBED_DRIVER for testing.
detect_driver() {
    if [ -n "${TESTBED_DRIVER:-}" ]; then echo "$TESTBED_DRIVER"; return; fi
    case "$(uname -s)" in
        Linux)  echo lima ;;
        Darwin) echo tart ;;
        *) die "unsupported host OS: $(uname -s)" ;;
    esac
}

DRIVER="$(detect_driver)"

inst() { echo "${TB_PREFIX}$1"; }

# ---- Lima driver -----------------------------------------------------------

lima_running() { limactl list --format '{{.Name}} {{.Status}}' | grep -q "^$(inst "$1") Running"; }

lima_guest_exec() {
    local name=$1; shift
    limactl shell --workdir "/home/${USER}.linux" "$(inst "$name")" bash -lc "$*"
}

lima_guest_push() {
    local name=$1 src=$2 dst=$3
    limactl cp "$src" "$(inst "$name"):$dst"
}

# ---- Tart driver (macOS) ---------------------------------------------------
# NOTE: written on the Linux server, UNVALIDATED on real hardware yet.
# The Mac-side agent validates/fixes these (see README.md "Mac side").

TART_GOLDEN="${TART_GOLDEN:-golden-macos}"
TART_SSH_USER="${TART_SSH_USER:-admin}"   # cirruslabs base images: admin/admin
TART_SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)

tart_ip() { tart ip "$(inst "$1")"; }

tart_guest_exec() {
    local name=$1; shift
    ssh "${TART_SSH_OPTS[@]}" "${TART_SSH_USER}@$(tart_ip "$name")" "$*"
}

tart_guest_push() {
    local name=$1 src=$2 dst=$3
    scp "${TART_SSH_OPTS[@]}" "$src" "${TART_SSH_USER}@$(tart_ip "$name"):$dst"
}

# ---- Driver-dispatched helpers ---------------------------------------------

guest_exec() { "${DRIVER}_guest_exec" "$@"; }
guest_push() { "${DRIVER}_guest_push" "$@"; }
