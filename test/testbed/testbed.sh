#!/usr/bin/env bash
# testbed.sh — persistent clean-VM sandboxes for agentjail (follow-up, Stage 1+2).
#
# A testbed is a named VM that behaves like a real end-user machine. One
# testbed per worktree/feature: install that build, run Claude Code against
# it, poke for days, reset to the golden snapshot when done.
#
#   testbed.sh create <name>              new VM from template + golden snapshot
#   testbed.sh ls                         list testbeds
#   testbed.sh ssh <name>                 interactive shell
#   testbed.sh exec <name> -- <cmd...>    run a command in the guest
#   testbed.sh provision <name> [--worktree <path>]
#                                         build tarball -> install.sh ->
#                                         Claude Code + agentjail, ready to use
#   testbed.sh test <name> [scenario]     run a scenario (default: e2e-smoke) in-guest
#   testbed.sh gate [--worktree <path>]   RELEASE GATE: clean box -> provision ->
#                                         scenario, non-zero exit on any failure.
#                                         Run before tagging a release.
#   testbed.sh snapshot <name> <tag>      checkpoint (Lima only)
#   testbed.sh reset <name> [tag]         revert to golden (or named) snapshot
#   testbed.sh destroy <name>             delete the VM
#
# Drivers: Lima/QEMU on Linux (a Linux host), Tart on macOS (laptop).
# Credential seeding: put a token from `claude setup-token` into
#   ~/.agentjail-testbed/token   (chmod 600)
# and provision will export CLAUDE_CODE_OAUTH_TOKEN inside the guest.

set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() { sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 1; }

cmd="${1:-}"; [ -n "$cmd" ] || usage
shift || true

# ---- create ----------------------------------------------------------------

do_create() {
    local name="${1:?usage: testbed.sh create <name>}"
    case "$DRIVER" in
        lima)
            log "creating $(inst "$name") from lima-template.yaml (first run downloads the Ubuntu image)"
            # 20m: first boot runs a full apt-get cloud-init pass, which can
            # exceed limactl's default readiness timeout on a busy host.
            limactl start --name "$(inst "$name")" --tty=false --timeout 20m "$TESTBED_DIR/lima-template.yaml"
            log "taking golden snapshot"
            limactl stop "$(inst "$name")"
            limactl snapshot create "$(inst "$name")" --tag golden
            limactl start "$(inst "$name")"
            log "testbed '$name' ready. Next: $0 provision $name"
            ;;
        tart)
            tart list | awk '{print $2}' | grep -qx "$TART_GOLDEN" \
                || die "golden image '$TART_GOLDEN' not found — see README.md 'Mac side' to bake it"
            log "cloning $TART_GOLDEN -> $(inst "$name") (APFS copy-on-write, instant)"
            tart clone "$TART_GOLDEN" "$(inst "$name")"
            log "starting VM headless"
            tart run --no-graphics "$(inst "$name")" >/dev/null 2>&1 &
            log "waiting for IP"
            local i=0
            until tart ip "$(inst "$name")" >/dev/null 2>&1; do
                sleep 2; i=$((i+1)); [ "$i" -lt 60 ] || die "VM never got an IP"
            done
            log "testbed '$name' ready. Next: $0 provision $name"
            ;;
    esac
}

# ---- provision --------------------------------------------------------------

do_provision() {
    local name="${1:?usage: testbed.sh provision <name> [--worktree <path>]}"; shift
    local worktree="$REPO_ROOT"
    while [ $# -gt 0 ]; do
        case "$1" in
            --worktree) worktree="$(cd "$2" && pwd)"; shift 2 ;;
            *) die "unknown provision flag: $1" ;;
        esac
    done

    local goos goarch
    case "$DRIVER" in
        lima) goos=linux ;;
        tart) goos=darwin ;;
    esac
    goarch=$(guest_exec "$name" "uname -m")
    case "$goarch" in
        x86_64|amd64) goarch=amd64 ;;
        arm64|aarch64) goarch=arm64 ;;
        *) die "unsupported guest arch: $goarch" ;;
    esac

    log "building dist tarball from $worktree ($goos/$goarch)"
    make -C "$worktree" dist-tarball DIST_GOOS="$goos" DIST_GOARCH="$goarch"
    local tarball
    tarball=$(ls -t "$worktree"/dist/agentjail-*-"$goos"-"$goarch".tar.gz | head -1)
    [ -n "$tarball" ] || die "dist-tarball produced no tarball"

    log "pushing tarball + install.sh + guest-provision.sh"
    guest_push "$name" "$tarball" /tmp/agentjail-local.tar.gz
    guest_push "$name" "$worktree/install.sh" /tmp/agentjail-install.sh
    guest_push "$name" "$TESTBED_DIR/guest-provision.sh" /tmp/guest-provision.sh

    local token_file="$HOME/.agentjail-testbed/token"
    if [ -f "$token_file" ]; then
        log "seeding Claude Code OAuth token"
        guest_push "$name" "$token_file" /tmp/claude-token
    else
        log "NOTE: no $token_file — Claude Code will be installed but not logged in."
        log "      Run 'claude setup-token' on the host and save the token there (chmod 600)."
    fi

    log "running guest-provision.sh inside the guest"
    guest_exec "$name" "bash /tmp/guest-provision.sh"
    log "provisioned. Try: $0 ssh $name   then: agentjail status && claude"
}

# ---- the rest ---------------------------------------------------------------

do_ls() {
    case "$DRIVER" in
        lima) limactl list | awk -v p="^${TB_PREFIX}" 'NR==1 || $1 ~ p' ;;
        tart) tart list | awk -v p="${TB_PREFIX}" 'NR==1 || $2 ~ "^"p' ;;
    esac
}

do_ssh() {
    local name="${1:?usage: testbed.sh ssh <name>}"
    case "$DRIVER" in
        lima) limactl shell --workdir "/home/${USER}.linux" "$(inst "$name")" ;;
        tart) ssh "${TART_SSH_OPTS[@]}" "${TART_SSH_USER}@$(tart_ip "$name")" ;;
    esac
}

do_exec() {
    local name="${1:?usage: testbed.sh exec <name> -- <cmd...>}"; shift
    [ "${1:-}" = "--" ] && shift
    guest_exec "$name" "$@"
}

# do_gate is the release gate: a fresh, clean box (reset to the post-cloud-init
# golden, or created if absent) provisioned from the given worktree and run
# through a scenario. Any failure -> non-zero exit, so it can gate `git tag`.
# The gate testbed is left at rest afterward (reset next run) for speed.
do_gate() {
    local worktree="$REPO_ROOT" name="release-gate" scenario="e2e-smoke"
    while [ $# -gt 0 ]; do
        case "$1" in
            --worktree) worktree="$(cd "$2" && pwd)"; shift 2 ;;
            --scenario) scenario="$2"; shift 2 ;;
            *) die "unknown gate flag: $1" ;;
        esac
    done

    log "RELEASE GATE starting (driver=$DRIVER, worktree=$worktree)"
    if "${DRIVER}_exists" "$name"; then
        log "reusing '$name' — resetting to clean golden"
        do_reset "$name"
    else
        do_create "$name"
    fi
    do_provision "$name" --worktree "$worktree"
    log "RELEASE GATE: running scenario '$scenario' on a clean box"
    if do_test "$name" "$scenario"; then
        log "RELEASE GATE ✓ PASS — safe to tag"
        return 0
    else
        die "RELEASE GATE ✗ FAIL — do NOT release"
    fi
}

do_test() {
    local name="${1:?usage: testbed.sh test <name> [scenario]}" scenario="${2:-e2e-smoke}"
    local script="$TESTBED_DIR/scenarios/${scenario}.sh"
    [ -f "$script" ] || die "scenario not found: $script"
    log "running scenario '$scenario' in '$name'"
    guest_push "$name" "$script" "/tmp/${scenario}.sh"
    guest_exec "$name" "bash /tmp/${scenario}.sh"
}

do_snapshot() {
    local name="${1:?usage: testbed.sh snapshot <name> <tag>}" tag="${2:?need a tag}"
    case "$DRIVER" in
        lima)
            limactl stop "$(inst "$name")"
            limactl snapshot create "$(inst "$name")" --tag "$tag"
            limactl start "$(inst "$name")"
            ;;
        tart)
            # Tart has no snapshot tags; a checkpoint is a clone at rest.
            tart stop "$(inst "$name")" || true
            tart clone "$(inst "$name")" "$(inst "$name")-$tag"
            log "checkpoint saved as VM '$(inst "$name")-$tag' (start manually if needed)"
            ;;
    esac
}

do_reset() {
    local name="${1:?usage: testbed.sh reset <name> [tag]}" tag="${2:-golden}"
    case "$DRIVER" in
        lima)
            limactl stop "$(inst "$name")" || true
            limactl snapshot apply "$(inst "$name")" --tag "$tag"
            limactl start "$(inst "$name")"
            ;;
        tart)
            log "tart reset = delete + re-clone from $TART_GOLDEN"
            tart stop "$(inst "$name")" 2>/dev/null || true
            tart delete "$(inst "$name")"
            do_create "$name"
            ;;
    esac
}

do_destroy() {
    local name="${1:?usage: testbed.sh destroy <name>}"
    case "$DRIVER" in
        lima) limactl delete -f "$(inst "$name")" ;;
        tart)
            tart stop "$(inst "$name")" 2>/dev/null || true
            tart delete "$(inst "$name")"
            ;;
    esac
}

case "$cmd" in
    create)    do_create "$@" ;;
    provision) do_provision "$@" ;;
    ls)        do_ls "$@" ;;
    ssh)       do_ssh "$@" ;;
    exec)      do_exec "$@" ;;
    test)      do_test "$@" ;;
    gate)      do_gate "$@" ;;
    snapshot)  do_snapshot "$@" ;;
    reset)     do_reset "$@" ;;
    destroy)   do_destroy "$@" ;;
    *)         usage ;;
esac
