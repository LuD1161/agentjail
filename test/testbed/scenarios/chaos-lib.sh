#!/usr/bin/env bash
# chaos-lib.sh - shared helper for the chaos-*.sh scenarios. Sourced, never
# executed directly: `. chaos-lib.sh` then call chaos_assert_fresh_binaries.
#
# AGE-236: a chaos run asserted behavior from a commit that landed AFTER the
# installed binary was built (21h newer), producing 5 confident FAILs against
# a feature the binary physically did not contain. "An unproven test is worse
# than no test" - a version mismatch must abort the run, not manufacture
# fake product bugs. See ADR 0073, ADR 0082-doctor-attests-enforcement.
#
# Defines functions only - sourcing this file has no side effects. The
# caller decides when (and whether) to call chaos_assert_fresh_binaries.

# Own name (not `timeout`) so sourcing this file never redefines a `timeout`
# function the calling scenario already declared for itself.
if command -v gtimeout >/dev/null 2>&1; then
    chaos_lib_timeout(){ command gtimeout "$@"; }
elif command -v timeout >/dev/null 2>&1; then
    chaos_lib_timeout(){ command timeout "$@"; }
else
    chaos_lib_timeout(){ shift; "$@"; }
fi

# _chaos_lib_repo_root -> stdout: toplevel of the checkout this file lives in,
# or empty if it isn't a git checkout at all (handled by the caller).
_chaos_lib_repo_root() {
    git -C "$(dirname "${BASH_SOURCE[0]:-$0}")" rev-parse --show-toplevel 2>/dev/null
}

# _chaos_lib_expected_version -> stdout: the version DIST_VERSION would
# compute for the working tree these scenarios came from. Must track the
# Makefile exactly (dist-tarball target) or the comparison is meaningless.
#
# Two sources, in order:
#   1. $CHAOS_EXPECTED_VERSION, set by testbed.sh (lib.sh chaos_env) on the
#      host. A testbed guest has no checkout, so this is the ONLY source there.
#   2. git describe, for a scenario run directly on a host checkout.
_chaos_lib_expected_version() {
    if [ -n "${CHAOS_EXPECTED_VERSION:-}" ]; then
        echo "$CHAOS_EXPECTED_VERSION"
        return 0
    fi
    local root
    root=$(_chaos_lib_repo_root) || return 1
    [ -n "$root" ] || return 1
    git -C "$root" describe --tags --always --dirty 2>/dev/null
}

# chaos_daemon_ready <hook> <project> - poll until the daemon is really SERVING,
# not merely up. Returns 0 when ready, non-zero after ~30s.
#
# Readiness is two conditions, and both are load-bearing: the hook must exit 0
# AND show no fail-open marker. Checking only the markers reports READY when the
# hook times out or dies, because a dead hook prints nothing for grep to find -
# i.e. it is most confident exactly when the daemon is least healthy. See AGE-236.
#
# Takes hook/project as args rather than reading the caller's globals: this is a
# contract, not a closure over one scenario's variables.
chaos_daemon_ready() {
    local hook="${1:?chaos_daemon_ready: hook path required}"
    local project="${2:?chaos_daemon_ready: project dir required}"

    [ -x "$hook" ] || return 1
    mkdir -p "$project" 2>/dev/null || true

    local i out rc
    for i in $(seq 1 30); do
        out=$(printf '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"%s/chaos-ready.txt","content":"x"},"session_id":"chaos-ready","cwd":"%s"}' "$project" "$project" \
            | chaos_lib_timeout 3 "$hook" 2>&1); rc=$?
        if [ "$rc" = 0 ] && ! echo "$out" | grep -qiE 'systemmessage|daemon unreachable|daemon not running'; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# chaos_assert_fresh_binaries [binary-path] - abort the scenario (exit 1) if
# the installed binary's reported version doesn't match the working tree's
# expected version. No --version flag exists on agentjail-hook (verified:
# cmd/agentjail-hook has no flag parsing at all), so `agentjail version` is
# the only queryable surface; its styled output still contains the version
# string verbatim (see cmd/agentjail/install_test.go
# TestPrintVersionOutputContainsVersionString), so a fixed-string containment
# check is enough - no ANSI stripping or token parsing required.
#
# Escape hatch: CHAOS_SKIP_VERSION_CHECK=1 lets a developer knowingly test a
# stale/local binary; it prints a loud warning but does not abort.
#
# Deliberately exits the whole (sourced) scenario process on failure/inability
# to verify, rather than returning a "skip" - a stale-binary run is a broken
# run whose PASS/FAIL lines cannot be trusted, not a clean skip that reads as
# coverage. It never prints "PASS" itself; that word belongs to the calling
# scenario's own ok().
chaos_assert_fresh_binaries() {
    local aj="${1:-$HOME/.agentjail/bin/agentjail}"

    if [ "${CHAOS_SKIP_VERSION_CHECK:-0}" = "1" ]; then
        echo "WARN  chaos-lib: CHAOS_SKIP_VERSION_CHECK=1 - running against $aj without a freshness check. Results may be against a stale binary." >&2
        return 0
    fi

    local expected
    expected=$(_chaos_lib_expected_version)
    if [ -z "$expected" ]; then
        echo "ABORT chaos-lib: could not compute the expected version - \$CHAOS_EXPECTED_VERSION is unset and $(dirname "${BASH_SOURCE[0]:-$0}") is not a git checkout with reachable tags. In a testbed guest, testbed.sh passes this in; if it is missing, the scenario was launched outside 'testbed.sh test'. Cannot verify the installed binary is fresh, so refusing to run rather than report fake results. Re-run via testbed.sh, run from a git checkout, or set CHAOS_SKIP_VERSION_CHECK=1 to proceed knowingly." >&2
        exit 1
    fi

    if [ ! -e "$aj" ]; then
        echo "ABORT chaos-lib: $aj does not exist - cannot verify freshness (this is a missing-binary condition, not a confirmed stale one). Install agentjail first, or set CHAOS_SKIP_VERSION_CHECK=1 to proceed knowingly." >&2
        exit 1
    fi
    if [ ! -x "$aj" ]; then
        echo "ABORT chaos-lib: $aj exists but is not executable - cannot verify freshness. Fix the install, or set CHAOS_SKIP_VERSION_CHECK=1 to proceed knowingly." >&2
        exit 1
    fi

    local out rc
    out=$(chaos_lib_timeout 20 "$aj" version 2>&1); rc=$?
    if [ "$rc" != 0 ]; then
        # $HOME/.agentjail is shield-denied under AGENTJAIL_SHIELDED=1 - that is
        # "cannot verify", never "verified stale". Name it explicitly so it is
        # not mistaken for a real mismatch.
        if echo "$out" | grep -qiE 'operation not permitted|permission denied'; then
            echo "ABORT chaos-lib: reading $aj was denied (Operation not permitted) - this looks like the agentjail shield denying \$HOME/.agentjail inside a shielded session. Run this scenario outside AGENTJAIL_SHIELDED=1, or set CHAOS_SKIP_VERSION_CHECK=1 to proceed knowingly." >&2
        else
            echo "ABORT chaos-lib: '$aj version' exited $rc - cannot verify freshness. Output: $out" >&2
        fi
        exit 1
    fi

    if echo "$out" | grep -qF "$expected"; then
        echo "chaos-lib: installed binary reports $expected, matches working tree - proceeding." >&2
        return 0
    fi

    if echo "$out" | grep -qw 'dev'; then
        # "dev" means an unversioned local `go build` (buildinfo.Version's
        # zero value) - it cannot prove freshness either way. Warn, don't
        # silently pass: the run may still be against stale code.
        echo "WARN  chaos-lib: $aj reports version 'dev' (unversioned local build) - cannot confirm it matches the working tree ($expected). Proceeding, but treat results with suspicion; rebuild with 'make dist-tarball' and reinstall for a trustworthy run." >&2
        return 0
    fi

    echo "ABORT chaos-lib: version mismatch. Working tree expects '$expected' (git describe --tags --always --dirty); installed $aj reports: $out" >&2
    echo "ABORT chaos-lib: rebuild and reinstall (make dist-tarball && install the tarball) before trusting this run, or set CHAOS_SKIP_VERSION_CHECK=1 to proceed knowingly." >&2
    exit 1
}
