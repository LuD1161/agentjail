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

# ---- host resources --------------------------------------------------------

# These are admission requirements, not guesses about total host capacity.
# Keep them aligned with lima-template.yaml and the Tart golden image.
TESTBED_REQUIRED_MEMORY_GIB="${AGENTJAIL_TESTBED_REQUIRED_MEMORY_GIB:-4}"
TESTBED_REQUIRED_DISK_GIB="${AGENTJAIL_TESTBED_REQUIRED_DISK_GIB:-20}"
TESTBED_HOST_MEMORY_RESERVE_GIB="${AGENTJAIL_TESTBED_HOST_MEMORY_RESERVE_GIB:-2}"
TESTBED_HOST_DISK_RESERVE_GIB="${AGENTJAIL_TESTBED_HOST_DISK_RESERVE_GIB:-5}"

validate_resource_gib() {
    local key="$1" value="$2"
    case "$value" in
        ''|*[!0-9]*) die "$key must be a whole number of GiB, got '$value'" ;;
    esac
    [ "$value" -gt 0 ] || die "$key must be greater than zero"
}

validate_resource_gib AGENTJAIL_TESTBED_REQUIRED_MEMORY_GIB "$TESTBED_REQUIRED_MEMORY_GIB"
validate_resource_gib AGENTJAIL_TESTBED_REQUIRED_DISK_GIB "$TESTBED_REQUIRED_DISK_GIB"
validate_resource_gib AGENTJAIL_TESTBED_HOST_MEMORY_RESERVE_GIB "$TESTBED_HOST_MEMORY_RESERVE_GIB"
validate_resource_gib AGENTJAIL_TESTBED_HOST_DISK_RESERVE_GIB "$TESTBED_HOST_DISK_RESERVE_GIB"

gib_bytes() { echo $(( $1 * 1024 * 1024 * 1024 )); }

bytes_gib() {
    awk -v bytes="$1" 'BEGIN { printf "%.1f", bytes / 1073741824 }'
}

host_available_memory_bytes() {
    case "$(uname -s)" in
        Linux)
            awk '/^MemAvailable:/ { printf "%.0f\n", $2 * 1024; found=1; exit }
                 END { if (!found) exit 1 }' /proc/meminfo
            ;;
        Darwin)
            vm_stat | darwin_available_memory_bytes
            ;;
        *) return 1 ;;
    esac
}

# Free + inactive + speculative pages conservatively approximate the memory
# macOS can reclaim without swapping; purgeable pages may overlap inactive.
darwin_available_memory_bytes() {
    awk '
        NR == 1 {
            if (match($0, /page size of [0-9]+ bytes/)) {
                size = substr($0, RSTART + 13, RLENGTH - 19)
            }
            next
        }
        /^Pages free:/        { freep=$3 }
        /^Pages inactive:/    { inactive=$3 }
        /^Pages speculative:/ { speculative=$3 }
        END {
            gsub(/\./, "", freep); gsub(/\./, "", inactive)
            gsub(/\./, "", speculative)
            if (!size) exit 1
            printf "%.0f\n", (freep + inactive + speculative) * size
        }'
}

testbed_storage_dir() {
    if [ -n "${AGENTJAIL_TESTBED_STORAGE_DIR:-}" ]; then
        echo "$AGENTJAIL_TESTBED_STORAGE_DIR"
        return
    fi
    case "$DRIVER" in
        lima) echo "${LIMA_HOME:-$HOME/.lima}" ;;
        tart) echo "$HOME/.tart" ;;
    esac
}

existing_parent() {
    local path="$1"
    while [ ! -e "$path" ]; do
        [ "$path" != "/" ] || break
        path="$(dirname "$path")"
    done
    echo "$path"
}

host_available_disk_bytes() {
    local path
    path="$(existing_parent "$(testbed_storage_dir)")"
    df -Pk "$path" | awk 'NR == 2 { printf "%.0f\n", $4 * 1024; found=1 }
                           END { if (!found) exit 1 }'
}

# assert_host_resources <name> <create|reuse>
#
# A new VM must fit its full configured disk plus the host reserve. A reused VM
# already owns its disk, but still needs the reserve for provisioning writes.
assert_host_resources() {
    local name="${1:?assert_host_resources: name required}"
    local allocation="${2:?assert_host_resources: create or reuse required}"
    case "$allocation" in create|reuse) ;; *) die "invalid resource allocation mode: $allocation" ;; esac

    local available_memory required_memory available_disk required_disk
    available_memory="$(host_available_memory_bytes)" \
        || die "cannot determine available host memory; refusing to start $(inst "$name")"
    required_memory="$(gib_bytes $((TESTBED_REQUIRED_MEMORY_GIB + TESTBED_HOST_MEMORY_RESERVE_GIB)))"
    if [ "$available_memory" -lt "$required_memory" ]; then
        die "insufficient host RAM for $(inst "$name"): $(bytes_gib "$available_memory") GiB available, $(bytes_gib "$required_memory") GiB required (${TESTBED_REQUIRED_MEMORY_GIB} GiB VM + ${TESTBED_HOST_MEMORY_RESERVE_GIB} GiB host reserve).
Stop another VM or lower AGENTJAIL_TESTBED_REQUIRED_MEMORY_GIB only if the guest is configured for it. No VM was started."
    fi

    available_disk="$(host_available_disk_bytes)" \
        || die "cannot determine free space for $(testbed_storage_dir); refusing to start $(inst "$name")"
    required_disk="$(gib_bytes "$TESTBED_HOST_DISK_RESERVE_GIB")"
    if [ "$allocation" = create ]; then
        required_disk=$((required_disk + $(gib_bytes "$TESTBED_REQUIRED_DISK_GIB")))
    fi
    if [ "$available_disk" -lt "$required_disk" ]; then
        local disk_detail="${TESTBED_HOST_DISK_RESERVE_GIB} GiB reserve"
        [ "$allocation" = reuse ] || disk_detail="$disk_detail + ${TESTBED_REQUIRED_DISK_GIB} GiB VM"
        die "insufficient host disk for $(inst "$name"): $(bytes_gib "$available_disk") GiB free at $(testbed_storage_dir), $(bytes_gib "$required_disk") GiB required ($disk_detail).
Free space or select a larger testbed storage volume. No VM was started."
    fi

    log "resource preflight passed: $(bytes_gib "$available_memory") GiB RAM available, $(bytes_gib "$available_disk") GiB disk free"
}

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
# Tunnel release assertions require the one-time approved guest disk.
# See ADR 0135-tunnel-golden-image.
TART_TUNNEL_GOLDEN="${TART_TUNNEL_GOLDEN:-golden-macos-mitm}"
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
    # Guest exec is non-interactive; inherited stdin makes Codex wait for EOF.
    # See ADR 0130-codex-live-gate.
    ${_tart_ssh_prefix[@]+"${_tart_ssh_prefix[@]}"} ssh -n "${TART_SSH_OPTS[@]}" "${TART_SSH_USER}@$(tart_ip "$name")" "bash -lc $(printf '%q' "$*")"
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

# ---- capacity ---------------------------------------------------------------

# MAX_TESTBEDS caps how many testbeds may EXIST, which is a disk concern and a
# different axis from how many may RUN at once (the macOS ~2-VM cap that
# tart_stop_other_testbeds handles). Each testbed is a full ~28G disk; stale
# boxes accumulate silently because nothing ever reaped them.
MAX_TESTBEDS="${MAX_TESTBEDS:-2}"

lima_testbed_names() { limactl list --format '{{.Name}}' 2>/dev/null | grep "^${TB_PREFIX}" || true; }
tart_testbed_names() { tart list 2>/dev/null | awk 'NR>1 {print $2}' | grep "^${TB_PREFIX}" || true; }

# testbed_names -> stdout: every existing testbed instance, one per line, or
# nothing. Only tb-prefixed VMs; a golden image is not a testbed.
testbed_names() { "${DRIVER}_testbed_names"; }

# testbed_count -> stdout: how many testbeds exist. Its own function because
# `grep -c` on empty input prints 0 but exits 1, which is the standard way a
# counter like this silently reports 1 at the empty state.
testbed_count() { printf '%s' "$(testbed_names)" | grep -c . || true; }

# gate_confirm_destroy <short-name> - may the gate destroy this testbed?
#
# TESTBED_RECLAIM: ask (default) | always | never. `always` exists for an
# unattended gate; without it, a non-TTY run dies rather than hanging on a read
# nobody will answer, or worse, guessing.
gate_confirm_destroy() {
    local short="${1:?gate_confirm_destroy: name required}"
    case "${TESTBED_RECLAIM:-ask}" in
        always) log "TESTBED_RECLAIM=always: destroying $short without asking"; return 0 ;;
        never)  return 1 ;;
    esac
    if [ ! -t 0 ]; then
        die "the gate needs a slot but stdin is not a terminal, so it cannot ask.
Destroy one first:         $0 destroy <name>
Or let the gate reclaim:   TESTBED_RECLAIM=always $0 gate
Or refuse and fail early:  TESTBED_RECLAIM=never $0 gate"
    fi
    local reply
    printf 'testbed: destroy testbed %s to free a slot for the release gate? [y/N] ' "$short" >&2
    read -r reply || return 1
    case "$reply" in [yY]|[yY][eE][sS]) return 0 ;; *) return 1 ;; esac
}

# gate_reclaim_slot <gate-instance> - make room for the gate, with consent.
#
# The gate is the one command with a job that must finish, so unlike `create` it
# offers to clear a slot instead of only refusing. It is NOT exempt from the cap
# (ADR 0098's one-rule-no-special-cases): it earns its slot by asking, and a `no`
# fails the gate exactly as a full disk would.
#
# Never destroys the gate's own box, and stops as soon as there is room -- it
# takes one slot, not a clean sweep.
gate_reclaim_slot() {
    local keep="${1:?gate_reclaim_slot: gate instance required}"
    # keep is the full instance name (tb-*); driver _exists re-applies the
    # prefix, so hand it the short name or it looks for tb-tb-* and never
    # matches, forcing a needless reclaim of the gate's own reused box.
    "${DRIVER}_exists" "${keep#"$TB_PREFIX"}" && return 0   # reusing the gate box needs no new slot
    [ "$(testbed_count)" -lt "$MAX_TESTBEDS" ] && return 0

    log "the gate needs a slot: $(testbed_count) testbed(s) exist, cap is $MAX_TESTBEDS"
    local vm short
    for vm in $(testbed_names); do
        [ "$(testbed_count)" -lt "$MAX_TESTBEDS" ] && break
        [ "$vm" = "$keep" ] && continue
        short="${vm#"$TB_PREFIX"}"
        if gate_confirm_destroy "$short"; then
            log "destroying $vm to free a slot for the gate"
            do_destroy "$short"
        fi
    done

    [ "$(testbed_count)" -lt "$MAX_TESTBEDS" ] || die "still at the cap ($(testbed_count)/$MAX_TESTBEDS): nothing was freed, so the gate has nowhere to run.
Destroy a testbed and re-run: $0 destroy <name>"
}

# assert_testbed_capacity <name> - refuse to create an N+1th testbed.
#
# Refuses rather than evicting the oldest: a testbed may be mid-investigation in
# another terminal, and destroying it to make room would be a silent surprise of
# exactly the kind this repo does not ship. The caller decides what to drop.
#
# Reusing an existing name is never a new testbed, so it always passes.
assert_testbed_capacity() {
    local name="${1:?assert_testbed_capacity: name required}"
    "${DRIVER}_exists" "$name" && return 0

    local count
    count="$(testbed_count)"
    [ "$count" -lt "$MAX_TESTBEDS" ] && return 0

    local listing
    listing="$(printf '%s' "$(testbed_names)" | sed "s/^${TB_PREFIX}//" | tr '\n' ' ')"
    die "$count testbed(s) already exist and the cap is $MAX_TESTBEDS: $listing
Each is a full disk clone, so they are capped rather than left to accumulate.
Destroy one first:            $0 destroy <name>
Or reuse one:                 $0 reset <name> && $0 provision <name>
Or raise the cap for one run: MAX_TESTBEDS=$((MAX_TESTBEDS + 1)) $0 create $name"
}

# ---- chaos scenario support ------------------------------------------------

# chaos_expected_version -> stdout: the version this checkout's dist-tarball
# would stamp. Must track the Makefile's DIST_VERSION expression exactly, or
# chaos-lib.sh's freshness comparison is meaningless. Empty (not fatal) outside
# a git checkout; chaos-lib.sh decides what to do about that.
chaos_expected_version() {
    git -C "$REPO_ROOT" describe --tags --always --dirty 2>/dev/null || true
}

# chaos_env -> stdout: shell-quoted env assignment prefix for a guest scenario
# run. A testbed guest has no checkout (no host mounts, by design), so the guard
# cannot derive the expected version itself -- the host passes it in.
# printf %q because a tag name is untrusted input that reaches a remote `bash -lc`.
chaos_env() {
    local v; v="$(chaos_expected_version)"
    [ -n "$v" ] || return 0
    printf 'CHAOS_EXPECTED_VERSION=%q' "$v"
}
