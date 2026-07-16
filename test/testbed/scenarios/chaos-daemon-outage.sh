#!/usr/bin/env bash
# chaos-daemon-outage.sh — failure injection: the policy daemon goes away
# mid-session. Runs INSIDE a provisioned testbed guest.
#
# Guards the AGE-212 bug class: the shield keeps activating (statusline stays
# green) while the daemon is DOWN and the hook falls back to levelAllow, so the
# agent runs unenforced. The machine-detectable signature is `shield.activated`
# climbing while `decisions` stays flat.
# See ADR 0050-hook-fallback-sidecar, ADR 0073, ADR 0082-doctor-attests-enforcement.
#
# Covers: daemon dies mid-session (fail-open is VISIBLE), sustained-outage
# divergence, and a stale socket file left on disk.
#
# SAFE TO RE-RUN: the daemon is restored on every exit path (trap).
set -u
AJ="$HOME/.agentjail/bin/agentjail"
HOOK="$HOME/.agentjail/bin/agentjail-hook"
SHIELD="$HOME/.agentjail/bin/agentjail-shield"
PROJECT="$HOME/work/demo"
SOCK="$HOME/.agentjail/daemon.sock"
SENTINEL="$HOME/.agentjail/fail-open-warned"
DB="$HOME/.agentjail/agentjail.db"

# shellcheck source=test/testbed/scenarios/chaos-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/chaos-lib.sh"

command -v gtimeout >/dev/null 2>&1 && timeout(){ command gtimeout "$@"; }
command -v timeout  >/dev/null 2>&1 || timeout(){ shift; "$@"; }

PASS=0; FAIL=0; SKIP=0
ok()   { echo "PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "FAIL  $1"; FAIL=$((FAIL+1)); }
skip() { echo "SKIP  $1"; SKIP=$((SKIP+1)); }

OS=$(uname -s)
UNIT="agentjail-daemon"
LABEL="com.agentjail.daemon"
PLIST="$HOME/Library/LaunchAgents/com.agentjail.daemon.plist"

# --- service control (systemd --user on Linux, launchd on macOS) ------------
# stop/start use the supervisor's own verbs so the daemon STAYS down while we
# test — killing the PID would just be restarted by Restart=always/KeepAlive
# (that path is chaos-supervisor-restart.sh's job, not this one's).
svc_supported() {
    case "$OS" in
        Darwin) command -v launchctl >/dev/null 2>&1 && [ -f "$PLIST" ] ;;
        Linux)  command -v systemctl >/dev/null 2>&1 && systemctl --user show "$UNIT" >/dev/null 2>&1 ;;
        *) return 1 ;;
    esac
}
daemon_active() {
    case "$OS" in
        Darwin) launchctl list 2>/dev/null | awk -v l="$LABEL" '$3==l && $1!="-" {f=1} END{exit !f}' ;;
        *)      systemctl --user is-active "$UNIT" >/dev/null 2>&1 ;;
    esac
}
daemon_stop() {
    case "$OS" in
        Darwin) launchctl bootout "gui/$(id -u)/$LABEL" >/dev/null 2>&1 || true ;;
        *)      systemctl --user stop "$UNIT" >/dev/null 2>&1 || true ;;
    esac
}
daemon_start() {
    case "$OS" in
        Darwin) launchctl bootstrap "gui/$(id -u)" "$PLIST" >/dev/null 2>&1 \
                    || launchctl kickstart -k "gui/$(id -u)/$LABEL" >/dev/null 2>&1 || true ;;
        *)      systemctl --user start "$UNIT" >/dev/null 2>&1 || true ;;
    esac
}
wait_up()   { local i; for i in $(seq 1 30); do daemon_active && [ -S "$SOCK" ] && return 0; sleep 1; done; return 1; }
wait_down() { local i; for i in $(seq 1 30); do daemon_active || return 0; sleep 1; done; return 1; }

# Restore on EVERY exit path. A chaos test that leaves the box broken is worse
# than no test.
restore() {
    # A regular file we planted at the socket path must never outlive the run.
    [ -e "$SOCK" ] && [ ! -S "$SOCK" ] && rm -f "$SOCK"
    daemon_start
    wait_up >/dev/null 2>&1 || true
}
trap restore EXIT INT TERM

# --- preconditions ---------------------------------------------------------
if ! svc_supported; then
    skip "no supported service manager for $OS (need systemd --user or launchd + installed plist)"
    echo "=== RESULT: $PASS pass, $FAIL fail, $SKIP skip ==="
    exit 0
fi
for f in "$HOOK" "$AJ"; do
    [ -x "$f" ] || { skip "$(basename "$f") not installed"; echo "=== RESULT: $PASS pass, $FAIL fail, $SKIP skip ==="; exit 0; }
done
# These assertions track HEAD; the binaries under test may not. A stale binary
# reports fake FAILs against features it predates. See AGE-236, chaos-lib.sh.
chaos_assert_fresh_binaries "$AJ"
if ! daemon_active; then
    skip "daemon not active at scenario start — nothing to kill (run e2e-smoke first)"
    echo "=== RESULT: $PASS pass, $FAIL fail, $SKIP skip ==="
    exit 0
fi
mkdir -p "$PROJECT" 2>/dev/null || true

# hook_json builds a benign in-project Write call — the tool call a live
# session drives through the hook every few seconds.
hook_json() {
    printf '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"%s/chaos.txt","content":"hi"},"session_id":"chaos","cwd":"%s"}' "$PROJECT" "$PROJECT"
}
# drive_hook [extra-arg] -> sets HRC / HOUT / HERR
drive_hook() {
    local extra="${1:-}"
    if [ -n "$extra" ]; then
        HOUT=$(hook_json | timeout 20 "$HOOK" "$extra" 2>/tmp/chaos-hook.err); HRC=$?
    else
        HOUT=$(hook_json | timeout 20 "$HOOK" 2>/tmp/chaos-hook.err); HRC=$?
    fi
    HERR=$(cat /tmp/chaos-hook.err 2>/dev/null || true)
}
# extract_system_message <json> -> the systemMessage VALUE, not the whole blob.
# "daemon"/"restart" also appear in decision-reason fields, so grepping $HOUT
# directly produces false PASSes when no systemMessage exists at all.
extract_system_message() {
    echo "$1" | grep -o '"systemMessage":"[^"]*"' | sed -E 's/^"systemMessage":"(.*)"$/\1/'
}

# ===========================================================================
echo "=== baseline: daemon UP, hook is quiet ==="
# The control for every "fail-open is visible" assertion below: with the daemon
# up the SAME call must carry no warning. Without this the checks are vacuous.
drive_hook
[ "$HRC" = 0 ] && ok "baseline: in-project write allowed (exit 0)" || bad "baseline: in-project write exit $HRC (expected 0)"
if echo "$HOUT" | grep -q 'systemMessage'; then
    bad "baseline: no fail-open systemMessage while daemon is up"
else
    ok "baseline: no fail-open systemMessage while daemon is up"
fi

# ===========================================================================
echo "=== 1. daemon dies mid-session ==="
daemon_stop
if ! wait_down; then
    bad "daemon did not go down within 30s — cannot inject the outage"
    echo "=== RESULT: $PASS pass, $FAIL fail, $SKIP skip ==="
    exit 1
fi
ok "daemon stopped mid-session"

drive_hook
[ "$HRC" != 124 ] && ok "hook does not hang when the daemon is gone (no timeout)" || bad "hook HUNG with the daemon gone (timeout fired)"
# levelAllow (the shipped default) resolves to allow/exit 0; levelDeny/degraded
# would resolve to exit 2. Both are a decision path; a crash is not.
case "$HRC" in
    0|2) ok "hook still renders a decision with the daemon gone (exit $HRC)" ;;
    *)   bad "hook returned exit $HRC with the daemon gone (expected 0=allow or 2=deny)" ;;
esac

# The VISIBLE warning. ADR 0073: Claude Code discards hook stderr on exit 0, so
# stderr alone is NOT proof the user saw anything — the systemMessage on the
# exit-0 stdout JSON is what actually reaches the TUI. That invisible-stderr gap
# is the root cause of the 3-day outage; assert the stdout channel.
if [ "$HRC" = 0 ]; then
    SYSMSG=$(extract_system_message "$HOUT")
    if [ -n "$SYSMSG" ]; then
        ok "fail-open emits a systemMessage on stdout (the channel the user sees)"
        # Content checks nested here on purpose: with no systemMessage there is
        # nothing to grade, and "daemon"/"restart" still appear elsewhere in
        # $HOUT (e.g. decision reason fields) -- grading the whole blob is vacuous.
        if echo "$SYSMSG" | grep -qi 'daemon'; then
            ok "systemMessage names the daemon as the cause"
        else
            bad "systemMessage does not name the daemon"
        fi
        if echo "$SYSMSG" | grep -qiE 'restart|doctor'; then
            ok "systemMessage carries a recovery instruction (restart/doctor)"
        else
            bad "systemMessage carries no recovery instruction"
        fi
    else
        bad "fail-open emitted NO systemMessage on stdout — the warning is invisible (ADR 0073)"
    fi
else
    skip "stdout systemMessage checks (daemon_unreachable level is not 'allow'; hook denied instead)"
fi

# stderr banner is defence-in-depth, not the primary channel — assert it too.
if echo "$HERR" | grep -qi 'agentjail.*daemon'; then
    ok "fail-open prints a stderr banner naming the daemon"
else
    bad "fail-open printed no stderr banner naming the daemon"
fi

# Codex takes a separate code path (writeCodexSystemMessage) — the OS-drift
# lesson applies to agent backends too. Assert it, don't assume it.
drive_hook "--agent=codex"
if [ "$HRC" = 0 ]; then
    if [ -n "$(extract_system_message "$HOUT")" ]; then
        ok "codex fail-open path also emits a systemMessage"
    else
        bad "codex fail-open path emitted NO systemMessage"
    fi
else
    skip "codex systemMessage check (codex path exited $HRC, not the allow path)"
fi

# Forensics: the sentinel dates the start of the outage for `doctor`.
[ -f "$SENTINEL" ] && ok "fail-open sentinel written (dates the outage start)" || bad "fail-open sentinel not written"

# `doctor` must SAY the box is unprotected while it is unprotected.
DOC=$(timeout 60 "$AJ" doctor 2>&1)
if echo "$DOC" | grep -qi 'fail-open'; then
    ok "doctor reports the unresolved fail-open window while the daemon is down"
else
    bad "doctor is silent about the fail-open window while the daemon is down"
fi

# ===========================================================================
echo "=== 3. sustained outage: shield climbs while decisions stay flat ==="
# THE signature of AGE-212. The shield opens the store itself and emits
# shield.activated with no daemon involvement, which is exactly why it stays
# green while enforcement is off — useless as a health metric, ideal as a
# cross-check against `decisions`.
q()  { sqlite3 -readonly "$DB" "$1" 2>/dev/null; }
num() { case "${1:-}" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }

if ! command -v sqlite3 >/dev/null 2>&1; then
    skip "divergence signal (sqlite3 not installed in this guest)"
elif [ ! -f "$DB" ]; then
    skip "divergence signal (no store at ~/.agentjail/agentjail.db)"
elif [ ! -x "$SHIELD" ]; then
    skip "divergence signal (agentjail-shield not installed)"
else
    D0=$(q "SELECT COUNT(*) FROM decisions;")
    S0=$(q "SELECT COUNT(*) FROM audit_log WHERE event_type='shield.activated';")
    if ! num "${D0:-}" || ! num "${S0:-}"; then
        skip "divergence signal (could not read decisions/audit_log counts read-only)"
    else
        # Drive a sustained "session": shield activations + hook tool calls,
        # exactly what a working agent does, with the daemon down.
        cd "$PROJECT" 2>/dev/null || true
        for _ in 1 2 3 4 5; do
            timeout 30 "$SHIELD" -- true >/dev/null 2>&1 || true
            drive_hook
        done
        sleep 2
        D1=$(q "SELECT COUNT(*) FROM decisions;")
        S1=$(q "SELECT COUNT(*) FROM audit_log WHERE event_type='shield.activated';")
        if ! num "${D1:-}" || ! num "${S1:-}"; then
            skip "divergence signal (counts unreadable after the outage window)"
        else
            SD=$((S1 - S0)); DD=$((D1 - D0))
            echo "  shield.activated +$SD / decisions +$DD  (daemon DOWN)"
            if [ "$SD" -ge 1 ]; then
                ok "shield.activated climbs during the outage (+$SD) — the green padlock lies"
            else
                # Not a pass: if the shield never activated we did not reproduce
                # the bug and the 'decisions flat' half proves nothing.
                skip "shield.activated did not climb (+$SD) — shield never activated here (no Landlock/Seatbelt?), divergence not reproduced"
            fi
            if [ "$SD" -ge 1 ]; then
                if [ "$DD" -eq 0 ]; then
                    ok "decisions stays FLAT during the outage (+$DD) — the AGE-212 signature reproduced"
                else
                    bad "decisions advanced (+$DD) with the daemon down — expected flat"
                fi
            fi
        fi
    fi
fi

# ===========================================================================
echo "=== 4. stale socket file left on disk ==="
# Daemon dead but ~/.agentjail/daemon.sock still present: dial must fail fast
# and loudly, never hang the agent.
rm -f "$SOCK"
: > "$SOCK"   # a plain file at the socket path — the stale-inode case
if [ -e "$SOCK" ] && [ ! -S "$SOCK" ]; then
    ok "planted a stale non-socket file at the daemon socket path"
    drive_hook
    [ "$HRC" != 124 ] && ok "hook does not hang on a stale socket file" || bad "hook HUNG on a stale socket file"
    case "$HRC" in
        0|2) ok "hook renders a decision through a stale socket (exit $HRC)" ;;
        *)   bad "hook returned exit $HRC on a stale socket (expected 0 or 2)" ;;
    esac
    if [ "$HRC" = 0 ]; then
        [ -n "$(extract_system_message "$HOUT")" ] \
            && ok "stale socket also surfaces the fail-open systemMessage" \
            || bad "stale socket failed open SILENTLY (no systemMessage)"
    else
        skip "stale-socket systemMessage check (hook denied instead of allowing)"
    fi
    DOC2=$(timeout 60 "$AJ" doctor 2>&1); DRC=$?
    [ "$DRC" != 124 ] && ok "doctor survives a stale socket without hanging" || bad "doctor HUNG on a stale socket"
    rm -f "$SOCK"
else
    skip "stale socket file (could not plant a regular file at the socket path)"
fi

# ===========================================================================
echo "=== restore: daemon back up, warning re-arms ==="
daemon_start
if wait_up; then
    ok "daemon restarted and re-created a real socket"
    [ -S "$SOCK" ] && ok "daemon socket is a socket again (stale file replaced)" || bad "daemon socket path is not a socket after restart"
    # The daemon clears the sentinel on startup so the warning re-arms for the
    # NEXT outage. Without this the banner would fire at most once, ever.
    sleep 2
    [ -f "$SENTINEL" ] && bad "daemon did not clear the fail-open sentinel on startup (warning would not re-arm)" \
                       || ok "daemon cleared the fail-open sentinel on startup (warning re-armed)"
    drive_hook
    if echo "$HOUT" | grep -q 'systemMessage'; then
        bad "hook still warns after the daemon is back (stuck in fail-open)"
    else
        ok "hook is quiet again after the daemon is back"
    fi
else
    bad "daemon did NOT come back within 30s — box left degraded"
fi

echo "=== NOT asserted here (cannot be made honest in-guest) ==="
echo "  doctor 'Enforcement' = fail requires shield.activated to lead the newest"
echo "  decision by > 1h (enforcementGapMargin). A scenario cannot fast-forward"
echo "  the clock without writing to the store, so the raw count divergence above"
echo "  is the honest in-guest proxy. The 1h threshold is unit-tested instead"
echo "  (cmd/agentjail/doctor_protection_test.go)."
skip "doctor Enforcement=fail on a >1h gap (needs a >1h outage; unit-tested instead)"

echo "=== RESULT: $PASS pass, $FAIL fail, $SKIP skip ==="
[ "$FAIL" = 0 ]
