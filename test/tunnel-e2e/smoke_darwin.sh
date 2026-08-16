#!/usr/bin/env bash
# Darwin tunnel smoke test.
#
# Reuses the host/path allow-deny shapes in test/tunnel-e2e/scenarios.sh and
# adds the strict release probes for port/protocol and direct no-proxy bypass.
# It drives them through the macOS CLI tunnel path
# (`agentjail-shield --tunnel`, backed by AgentjailTunnel.app + the
# NETransparentProxyProvider system extension - see macos/README.md).
#
# The system extension requires one-time interactive user approval, which
# cannot be scripted. Default mode detects missing prerequisites and SKIPs
# loudly. `--strict` requires an activated extension and at least one executed
# tunnel scenario; it fails instead of treating all-SKIP as verification.
# See ADR 0135-tunnel-golden-image.
#
# Usage: test/tunnel-e2e/smoke_darwin.sh [--strict]
#
# Exit: default mode permits all-SKIP; strict mode never does.

set -uo pipefail

STRICT=0
case "${1:-}" in
    "") ;;
    --strict) STRICT=1 ;;
    *) echo "usage: $0 [--strict]" >&2; exit 2 ;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EXT_ID="com.blinkerlm.agentjail.app.extension"
NETWORK_DB="$HOME/.agentjail/network.db"
RESULT_PATH="${TUNNEL_SMOKE_RESULT:-}"

PASS=0; FAIL=0; SKIP=0; EXECUTED=0; SCENARIO_SKIP=0
EXT_STATE="unavailable"

ok()   { printf "  \033[32mPASS\033[0m  %s\n" "$1"; PASS=$((PASS+1)); }
bad()  { printf "  \033[31mFAIL\033[0m  %s\n     %s\n" "$1" "${2:-}"; FAIL=$((FAIL+1)); }
skip() { printf "  \033[33mSKIP\033[0m  %s (%s)\n" "$1" "${2:-}"; SKIP=$((SKIP+1)); }
group() { printf "\n\033[1m%s\033[0m\n" "$1"; }

write_result() {
    [ -n "$RESULT_PATH" ] || return 0
    local status="PASS" mode="default"
    [ "$STRICT" = "1" ] && mode="strict"
    if [ "$FAIL" -gt 0 ]; then
        status="FAIL"
    elif [ "$EXECUTED" -eq 0 ]; then
        status="SKIP"
    fi
    mkdir -p "$(dirname "$RESULT_PATH")"
    printf '{"scenario":"darwin-tunnel-smoke","mode":"%s","status":"%s","extension":"%s","executed":%d,"skipped":%d,"pass":%d,"fail":%d}\n' \
        "$mode" "$status" "$EXT_STATE" "$EXECUTED" "$SCENARIO_SKIP" "$PASS" "$FAIL" > "$RESULT_PATH"
}
trap write_result EXIT

run_with_timeout() {
    local seconds="$1" command_pid watchdog_pid rc
    shift
    "$@" &
    command_pid=$!
    (
        sleep "$seconds"
        kill -TERM "$command_pid" 2>/dev/null || exit 0
        sleep 2
        kill -KILL "$command_pid" 2>/dev/null || true
    ) &
    watchdog_pid=$!
    wait "$command_pid"
    rc=$?
    kill "$watchdog_pid" 2>/dev/null || true
    wait "$watchdog_pid" 2>/dev/null || true
    return "$rc"
}

group "preconditions"

if [ "$(uname -s)" != "Darwin" ]; then
    if [ "$STRICT" = "1" ]; then
        bad "darwin tunnel smoke" "strict mode requires macOS"
        printf "\n  PASS=%d  FAIL=%d  SKIP=%d  TUNNEL_EXECUTED=%d  TUNNEL_SKIPPED=%d\n" "$PASS" "$FAIL" "$SKIP" "$EXECUTED" "$SCENARIO_SKIP"
        exit 1
    fi
    skip "darwin tunnel smoke" "not running on macOS"
    printf "\n  PASS=%d  FAIL=%d  SKIP=%d  TUNNEL_EXECUTED=%d  TUNNEL_SKIPPED=%d\n" "$PASS" "$FAIL" "$SKIP" "$EXECUTED" "$SCENARIO_SKIP"
    exit 0
fi

SHIELD_BIN="$(command -v agentjail-shield || true)"
if [ -z "$SHIELD_BIN" ]; then
    # fall back to a local build so this script is useful straight out of
    # a worktree without requiring an installed agentjail-shield on PATH.
    if [ -x "$REPO_ROOT/build/agentjail-shield" ]; then
        SHIELD_BIN="$REPO_ROOT/build/agentjail-shield"
    fi
fi
if [ -n "$SHIELD_BIN" ]; then
    ok "agentjail-shield found ($SHIELD_BIN)"
else
    skip "agentjail-shield found" "not on PATH and no build/agentjail-shield - run 'make build' or install agentjail"
fi

EXT_APPROVED=0
if command -v systemextensionsctl >/dev/null 2>&1; then
    EXT_LIST="$(systemextensionsctl list 2>&1 || true)"
    EXT_LINE="$(grep -F "$EXT_ID" <<<"$EXT_LIST" | tail -1)"
    if grep -qi "\[activated enabled\]" <<<"$EXT_LINE"; then
        EXT_APPROVED=1
        EXT_STATE="activated_enabled"
        ok "system extension $EXT_ID installed and approved"
    elif [ -n "$EXT_LINE" ]; then
        EXT_STATE="inactive"
        skip "system extension $EXT_ID installed and approved" "present but inactive: $EXT_LINE"
    else
        skip "system extension $EXT_ID installed and approved" "missing - install the containing app and approve it once in the GUI (see macos/README.md)"
    fi
else
    skip "system extension $EXT_ID installed and approved" "systemextensionsctl not found"
fi

SQLITE_OK=0
if command -v sqlite3 >/dev/null 2>&1; then
    SQLITE_OK=1
    ok "sqlite3 available"
else
    skip "sqlite3 available" "sqlite3 not installed"
fi

CAN_RUN=0
if [ -n "$SHIELD_BIN" ] && [ "$EXT_APPROVED" = "1" ]; then
    CAN_RUN=1
fi

# ================================================================ STRICT MATRIX
group "M - strict policy and bypass matrix"

if [ "$CAN_RUN" = "1" ]; then
    EXECUTED=$((EXECUTED+1))
    MATRIX_WORK="$(mktemp -d)"
    MATRIX_PACKS="$MATRIX_WORK/netpacks"
    mkdir -p "$MATRIX_PACKS"
    cat > "$MATRIX_PACKS/deny-host.yaml" <<'EOF'
id: darwin-deny-host
info:
  name: deny example.com outright
  severity: high
match:
  host:
    - example.com
action: deny
reason: "darwin strict smoke: host denied"
EOF
    cat > "$MATRIX_PACKS/deny-path.yaml" <<'EOF'
id: darwin-deny-path
info:
  name: deny a path subtree on an otherwise reachable host
  severity: high
match:
  host:
    - api.github.com
  path:
    - "re:^/repos/"
action: deny
reason: "darwin strict smoke: path denied"
EOF
    cat > "$MATRIX_PACKS/deny-http-port.yaml" <<'EOF'
id: darwin-deny-http-port
info:
  name: deny cleartext HTTP on the port-specific raw TCP path
  severity: high
match:
  protocol:
    - http
  host:
    - www.cloudflare.com:80
action: deny
reason: "darwin strict smoke: cleartext port denied"
EOF

    MATRIX_OUT="$(run_with_timeout 90 env AGENTJAIL_NETPACKS_DIR="$MATRIX_PACKS" \
        "$SHIELD_BIN" --tunnel -- bash -c '
        curl -sS -o /dev/null -w "ALLOW_HTTPS:%{http_code}\n" --max-time 15 https://www.cloudflare.com/
        curl -sS -o /dev/null -w "DENY_HOST:%{http_code}\n" --max-time 15 https://example.com/
        curl -sS -o /dev/null -w "DENY_PATH:%{http_code}\n" --max-time 15 https://api.github.com/repos/torvalds/linux
        curl -sS -o /dev/null -w "DENY_HTTP80:%{http_code}\n" --max-time 15 http://www.cloudflare.com/ || true
        env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy \
          curl --noproxy "*" -sS -o /dev/null -w "DENY_DIRECT:%{http_code}\n" --max-time 15 https://example.com/
        true
    ' 2>&1)"
    rm -rf "$MATRIX_WORK"

    grep -q "ALLOW_HTTPS:200" <<<"$MATRIX_OUT" \
        && ok "M1 allowed HTTPS succeeds on port 443" \
        || bad "M1 allowed HTTPS succeeds on port 443" "$(grep -o 'ALLOW_HTTPS:[0-9]*' <<<"$MATRIX_OUT" | tail -1)"

    if grep -q "DENY_HOST:403" <<<"$MATRIX_OUT" && grep -q "template=darwin-deny-host" <<<"$MATRIX_OUT"; then
        ok "M2 denied host is blocked by the named policy"
    else
        bad "M2 denied host is blocked by the named policy" "status=$(grep -o 'DENY_HOST:[0-9]*' <<<"$MATRIX_OUT" | tail -1); template=$(grep -c 'template=darwin-deny-host' <<<"$MATRIX_OUT")"
    fi

    if grep -q "DENY_PATH:403" <<<"$MATRIX_OUT" && grep -q "template=darwin-deny-path" <<<"$MATRIX_OUT"; then
        ok "M3 denied path is blocked by the named policy"
    else
        bad "M3 denied path is blocked by the named policy" "status=$(grep -o 'DENY_PATH:[0-9]*' <<<"$MATRIX_OUT" | tail -1); template=$(grep -c 'template=darwin-deny-path' <<<"$MATRIX_OUT")"
    fi

    if grep -q "DENY_HTTP80:000" <<<"$MATRIX_OUT" && grep -q "template=darwin-deny-http-port" <<<"$MATRIX_OUT"; then
        ok "M4 cleartext HTTP on port 80 is denied on the raw protocol path"
    else
        bad "M4 cleartext HTTP on port 80 is denied on the raw protocol path" "status=$(grep -o 'DENY_HTTP80:[0-9]*' <<<"$MATRIX_OUT" | tail -1); template=$(grep -c 'template=darwin-deny-http-port' <<<"$MATRIX_OUT")"
    fi

    if grep -q "DENY_DIRECT:403" <<<"$MATRIX_OUT" && [ "$(grep -c 'template=darwin-deny-host' <<<"$MATRIX_OUT")" -ge 2 ]; then
        ok "M5 unsetting proxy variables and --noproxy cannot bypass the tunnel policy"
    else
        bad "M5 unsetting proxy variables and --noproxy cannot bypass the tunnel policy" "status=$(grep -o 'DENY_DIRECT:[0-9]*' <<<"$MATRIX_OUT" | tail -1); host-deny-count=$(grep -c 'template=darwin-deny-host' <<<"$MATRIX_OUT")"
    fi
else
    SCENARIO_SKIP=$((SCENARIO_SKIP+1))
    skip "strict policy and bypass matrix" "extension not approved or agentjail-shield unavailable"
fi

# ================================================================ GROUP A8
group "A8 - HTTPS request through the tunnel returns 200 (TLS trust via injected CA)"

if [ "$CAN_RUN" = "1" ]; then
    EXECUTED=$((EXECUTED+1))
    OUT="$(run_with_timeout 60 "$SHIELD_BIN" --tunnel -- bash -c '
        if command -v node >/dev/null 2>&1; then
            node -e "fetch(\"https://www.cloudflare.com/\").then(r=>{console.log(\"A8:\"+r.status)}).catch(e=>{console.log(\"A8:ERR \"+e.message)})"
        else
            curl -s -o /dev/null -w "A8:%{http_code}\n" --max-time 15 https://www.cloudflare.com/
        fi
    ' 2>&1)"
    if grep -q "A8:200" <<<"$OUT"; then
        ok "A8  HTTPS request under the tunnel returns 200"
    else
        bad "A8  HTTPS request under the tunnel returns 200" "$(grep 'A8:' <<<"$OUT" | tail -1)"
    fi
else
    SCENARIO_SKIP=$((SCENARIO_SKIP+1))
    skip "A8  HTTPS request under the tunnel returns 200" "extension not approved or agentjail-shield unavailable"
fi

# ================================================================ GROUP A11
group "A11 - requests through the tunnel are logged to network.db"

if [ "$CAN_RUN" = "1" ] && [ "$SQLITE_OK" = "1" ]; then
    EXECUTED=$((EXECUTED+1))
    BEFORE_ID="$(sqlite3 "$NETWORK_DB" 'select coalesce(max(id),0) from network_requests;' 2>/dev/null || echo 0)"
    run_with_timeout 60 "$SHIELD_BIN" --tunnel -- bash -c \
        'curl -s -o /dev/null --max-time 15 https://api.github.com/; echo done' >/dev/null 2>&1
    if [ -f "$NETWORK_DB" ]; then
        N="$(sqlite3 "$NETWORK_DB" "select count(*) from network_requests where id > $BEFORE_ID and host='api.github.com';" 2>/dev/null || echo 0)"
        if [ "${N:-0}" -gt 0 ]; then
            ok "A11 requests recorded to network.db (n=$N)"
        else
            bad "A11 requests recorded to network.db" "count=$N"
        fi
    else
        bad "A11 requests recorded to network.db" "$NETWORK_DB does not exist after a request"
    fi
else
    SCENARIO_SKIP=$((SCENARIO_SKIP+1))
    skip "A11 requests recorded to network.db" "extension not approved, agentjail-shield unavailable, or sqlite3 missing"
fi

# ================================================================ GROUP A12
group "A12 - Claude Code completes a real request through the tunnel"

CLAUDE_BIN="$(command -v claude || true)"
if [ -z "$CLAUDE_BIN" ]; then
    SCENARIO_SKIP=$((SCENARIO_SKIP+1))
    skip "A12 Claude Code through the tunnel" "claude not installed"
elif [ "$CAN_RUN" != "1" ]; then
    SCENARIO_SKIP=$((SCENARIO_SKIP+1))
    skip "A12 Claude Code through the tunnel" "extension not approved or agentjail-shield unavailable"
else
    EXECUTED=$((EXECUTED+1))
    CC="$(run_with_timeout 90 "$SHIELD_BIN" --tunnel -- claude -p "reply with exactly: TUNNELOK" --max-turns 1 2>&1 | tail -3)"
    if grep -q "TUNNELOK" <<<"$CC"; then
        ok "A12 Claude Code completes a real API call through the tunnel"
    else
        bad "A12 Claude Code through the tunnel" "$(tail -2 <<<"$CC")"
    fi
fi

# ================================================================ summary
group "Summary"
if [ "$STRICT" = "1" ]; then
    [ "$EXT_APPROVED" = "1" ] || bad "strict extension contract" "$EXT_ID is missing or inactive"
    [ "$EXECUTED" -gt 0 ] || bad "strict execution contract" "every tunnel scenario skipped"
fi
printf "  PASS=%d  FAIL=%d  SKIP=%d  TUNNEL_EXECUTED=%d  TUNNEL_SKIPPED=%d\n" "$PASS" "$FAIL" "$SKIP" "$EXECUTED" "$SCENARIO_SKIP"
[ "$FAIL" -gt 0 ] && exit 1
exit 0
