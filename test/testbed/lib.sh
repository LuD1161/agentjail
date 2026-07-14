#!/usr/bin/env bash
# lib.sh — shared helpers for testbed.sh.
# Sourced, not executed.

set -euo pipefail

TB_PREFIX="tb-"
TESTBED_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$TESTBED_DIR/../.." && pwd)"

# Linux testbeds keep VM disks on the big data disk, not the root partition.
if [ "$(uname -s)" = "Linux" ] && [ -d "$HOME/.local/share" ]; then
    export LIMA_HOME="${LIMA_HOME:-$HOME/.local/share/lima}"
fi

die() { echo "testbed: $*" >&2; exit 1; }
log() { echo "==> $*" >&2; }

# Driver is chosen by host OS: Lima/QEMU on Linux (a Linux host),
# Tart on macOS (the Mac). Override with TESTBED_DRIVER for testing.
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
lima_exists()  { limactl list --format '{{.Name}}' | grep -qx "$(inst "$1")"; }

lima_guest_exec() {
    local name=$1; shift
    limactl shell --workdir "/home/${USER}.linux" "$(inst "$name")" bash -lc "$*"
}

lima_guest_push() {
    local name=$1 src=$2 dst=$3
    limactl cp "$src" "$(inst "$name"):$dst"
}

lima_guest_pull() {
    local name=$1 src=$2 dst=$3
    limactl cp "$(inst "$name"):$src" "$dst"
}

# ---- Tart driver (macOS) ---------------------------------------------------

TART_GOLDEN="${TART_GOLDEN:-golden-macos}"
TART_SSH_USER="${TART_SSH_USER:-admin}"   # cirruslabs base images: admin/admin
TART_SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10)

# Non-interactive SSH auth: prefer key-based auth (baked into golden image).
# Falls back to sshpass with the default password if available. If neither
# works, ssh will prompt and hang - bake your pubkey into the golden image
# per the README.
_tart_ssh_prefix=()
if [ -n "${TART_SSH_PASSWORD:-}" ]; then
    command -v sshpass >/dev/null 2>&1 || die "TART_SSH_PASSWORD set but sshpass not found (brew install sshpass-mac)"
    _tart_ssh_prefix=(sshpass -p "$TART_SSH_PASSWORD")
fi

tart_ip()     { tart ip "$(inst "$1")"; }
tart_exists() { tart list | awk '{print $2}' | grep -qx "$(inst "$1")"; }

tart_guest_exec() {
    local name=$1; shift
    # Run through a login shell so brew-installed tools (node, git) are on PATH.
    ${_tart_ssh_prefix[@]+"${_tart_ssh_prefix[@]}"} ssh "${TART_SSH_OPTS[@]}" "${TART_SSH_USER}@$(tart_ip "$name")" "bash -lc $(printf '%q' "$*")"
}

tart_guest_push() {
    local name=$1 src=$2 dst=$3
    ${_tart_ssh_prefix[@]+"${_tart_ssh_prefix[@]}"} scp "${TART_SSH_OPTS[@]}" "$src" "${TART_SSH_USER}@$(tart_ip "$name"):$dst"
}

tart_guest_pull() {
    local name=$1 src=$2 dst=$3
    scp "${TART_SSH_OPTS[@]}" "${TART_SSH_USER}@$(tart_ip "$name"):$src" "$dst"
}

# ---- Driver-dispatched helpers ---------------------------------------------

guest_exec() { "${DRIVER}_guest_exec" "$@"; }
guest_push() { "${DRIVER}_guest_push" "$@"; }
guest_pull() { "${DRIVER}_guest_pull" "$@"; }
