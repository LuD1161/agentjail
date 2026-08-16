#!/usr/bin/env bash
# reportlib.sh — sourced by testbed scenarios to emit a structured result JSON
# and (for two-terminal flows) an asciinema recording. Runs INSIDE the guest.
#
# Contract for a scenario:
#   source "$(dirname "$0")/../reportlib.sh"
#   scn_init "name" "one-line human intent"
#   scn_check "label" "<expected>" "<actual>"     # repeat; PASS iff expected==actual
#   scn_skip "label" "reason"                      # explicit unexecuted assertion
#   scn_finish                                     # writes $SCN_JSON, exits nonzero on any fail
#
# The recorder (testbed.sh record) sets these env vars before running a scenario:
#   SCN_JSON  — path to write the result JSON (default: /dev/null, so scenarios
#               still run standalone under `testbed.sh test`)
#   SCN_CAST  — path a two-terminal scenario should write its recording to
# Single-terminal scenarios are recorded by the runner wrapping the whole script
# in `asciinema rec`; they need no recording code of their own.

set -uo pipefail

: "${SCN_JSON:=/dev/null}"
: "${SCN_CAST:=/tmp/scenario.cast}"
export TERM="${TERM:-xterm-256color}"

_SCN_NAME=""; _SCN_INTENT=""; _SCN_PASSES=0; _SCN_FAILS=0; _SCN_SKIPS=0
_SCN_CHECKS_JSON=""; _SCN_T0=0

_now() { date +%s.%N; }

scn_init() {
    _SCN_NAME="$1"; _SCN_INTENT="${2:-}"
    _SCN_PASSES=0; _SCN_FAILS=0; _SCN_SKIPS=0; _SCN_CHECKS_JSON=""
    _SCN_T0=$(_now)
    echo "### scenario: $_SCN_NAME — $_SCN_INTENT"
}

# scn_check LABEL EXPECTED ACTUAL — record one assertion.
scn_check() {
    local label="$1" expect="$2" actual="$3" pass=false status=fail
    if [ "$expect" = "$actual" ]; then
        pass=true; status=pass; _SCN_PASSES=$((_SCN_PASSES+1))
    else
        _SCN_FAILS=$((_SCN_FAILS+1))
    fi
    if $pass; then echo "  PASS  $label"; else echo "  FAIL  $label (want '$expect', got '$actual')"; fi
    local obj
    obj=$(jq -nc --arg l "$label" --arg e "$expect" --arg a "$actual" \
        --arg s "$status" --argjson p "$pass" \
        '{label:$l, expected:$e, actual:$a, status:$s, pass:$p}')
    _SCN_CHECKS_JSON="${_SCN_CHECKS_JSON:+$_SCN_CHECKS_JSON,}$obj"
}

# scn_ok LABEL / scn_fail LABEL / scn_skip LABEL REASON — status checks.
scn_ok()   { scn_check "$1" ok ok; }
scn_fail() { scn_check "$1" ok fail; }
scn_skip() {
    local label="$1" reason="${2:-not executed}" obj
    _SCN_SKIPS=$((_SCN_SKIPS+1))
    echo "  SKIP  $label ($reason)"
    obj=$(jq -nc --arg l "$label" --arg r "$reason" \
        '{label:$l, expected:"executed", actual:"skipped", status:"skip", pass:false, reason:$r}')
    _SCN_CHECKS_JSON="${_SCN_CHECKS_JSON:+$_SCN_CHECKS_JSON,}$obj"
}

scn_finish() {
    local dur result os_name recording_json=null
    dur=$(awk -v a="$_SCN_T0" -v b="$(_now)" 'BEGIN{printf "%.2f", b-a}')
    if [ "$_SCN_FAILS" -gt 0 ]; then
        result=fail
    elif [ "$_SCN_PASSES" -gt 0 ]; then
        result=pass
    else
        result=skip
    fi
    local ver; ver=$("$HOME/.agentjail/bin/agentjail" status 2>/dev/null | grep -oE 'dev-[a-f0-9]+|v[0-9]+\.[0-9]+\.[0-9]+' | head -1); ver="${ver:-unknown}"
    os_name="$(uname -s | tr '[:upper:]' '[:lower:]')"
    if [ -f "$SCN_CAST" ]; then
        recording_json=$(jq -nc --arg name "$(basename "$SCN_CAST")" '$name')
    fi
    jq -nc \
        --arg name "$_SCN_NAME" --arg intent "$_SCN_INTENT" --arg os "$os_name" \
        --arg ver "$ver" --arg result "$result" --argjson dur "$dur" \
        --argjson checks "[${_SCN_CHECKS_JSON:-}]" \
        --argjson passed "$_SCN_PASSES" --argjson failed "$_SCN_FAILS" \
        --argjson skipped "$_SCN_SKIPS" \
        --argjson recording "$recording_json" \
        '{scenario:$name, intent:$intent, os:$os, agentjail_version:$ver,
          result:$result, duration_s:$dur,
          counts:{pass:$passed, fail:$failed, skip:$skipped},
          checks:$checks, recording:$recording}' \
        > "$SCN_JSON"
    echo "### RESULT: $_SCN_NAME = $result ($_SCN_PASSES pass, $_SCN_FAILS fail, $_SCN_SKIPS skip, ${dur}s)"
    [ "$_SCN_FAILS" -eq 0 ]
}

# scn_record_tmux SESSION DRIVE_FN — record a two-terminal flow.
# Lays out a 2-pane tmux window (pane 0 = agent, pane 1 = operator), runs
# DRIVE_FN in the background (it should `tmux send-keys` to $SESSION:0.0 and
# :0.1 with pauses), and records the attached session to $SCN_CAST. DRIVE_FN
# returns when the demo is done; this kills the session, ending the recording.
# Correctness assertions are done separately by the scenario (scn_check) — the
# recording is the VISUAL artifact, not the source of truth.
scn_record_tmux() {
    local sess="$1" drive="$2"
    tmux kill-session -t "$sess" 2>/dev/null
    tmux new-session -d -s "$sess" -x 200 -y 50
    tmux split-window -h -t "$sess"
    tmux select-pane -t "$sess:0.0" -T "AGENT (sandboxed)"    2>/dev/null || true
    tmux select-pane -t "$sess:0.1" -T "OPERATOR (you)"       2>/dev/null || true
    tmux set -t "$sess" pane-border-status top 2>/dev/null || true
    ( "$drive"; sleep 0.5; tmux kill-session -t "$sess" 2>/dev/null ) &
    asciinema rec --overwrite -c "tmux attach -t $sess" "$SCN_CAST" >/dev/null 2>&1
    wait 2>/dev/null || true
}

# scn_pane SESSION PANE "command" — send a command to a pane (0=agent,1=operator).
scn_pane() { tmux send-keys -t "$1:0.$2" "$3" Enter; }
