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

# tart_ip_any <instance>: resolve a running VM's IP, trying the default dhcp
# resolver (fast, lease-file based) then the arp resolver (live ARP table) as a
# fallback for a booted VM whose DHCP lease the host can't see. Prints the IP on
# success; empty + non-zero on failure.
tart_ip_any() {
    tart ip "$1" --resolver dhcp 2>/dev/null || tart ip "$1" --resolver arp 2>/dev/null
}

# tart_running_count: number of currently-running Tart VMs (any name). macOS
# Virtualization.framework caps how many VMs run at once (commonly 2), so this
# is what actually blocks a fresh gate VM from starting - not the DHCP pool.
tart_running_count() {
    tart list 2>/dev/null | awk 'NR>1 && $NF ~ /running/' | wc -l | tr -d ' '
}

# tart_running_names: names of all currently-running Tart VMs. Name is column 2
# (Source is column 1; the Accessed column is multi-word so State is the last
# field, $NF).
tart_running_names() {
    tart list 2>/dev/null | awk 'NR>1 && $NF ~ /running/ {print $2}'
}

# tart_wait_ssh <name> <timeout-secs>: block until the guest answers SSH.
# do_create returns as soon as the VM has an IP, but sshd is not up for a few
# more seconds — provisioning used to SSH immediately and time out. Retries a
# trivial command until it succeeds or the deadline passes.
tart_wait_ssh() {
    local name="$1" secs="${2:-120}" i=0
    while ! tart_guest_exec "$name" true >/dev/null 2>&1; do
        i=$((i+3)); [ "$i" -lt "$secs" ] || return 1; sleep 3
    done
}

# tart_stop_other_testbeds <keep-instance>: stop every *running* tb-* VM other
# than <keep-instance>. macOS caps concurrently running VMs (~2); the gate runs
# exactly one testbed VM at a time, so it stops the others up front — this frees
# a slot AND prevents orphaned testbed VMs from accumulating. Non-testbed VMs
# (anything not prefixed tb-) are never touched.
tart_stop_other_testbeds() {
    local keep="$1" vm
    for vm in $(tart_running_names); do
        [ "$vm" = "$keep" ] && continue
        case "$vm" in
            "$TB_PREFIX"*)
                log "stopping other testbed VM to keep a single VM running: $vm"
                tart stop "$vm" >/dev/null 2>&1 || true
                ;;
        esac
    done
}

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
