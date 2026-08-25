#!/usr/bin/env bash
# Darwin tunnel smoke test.
#
# Reuses the host/path allow-deny shapes in test/tunnel-e2e/scenarios.sh and
# adds the strict release probes for port/protocol and direct no-proxy bypass.
# It drives them through the macOS CLI tunnel path
# (`agentjail-shield --tunnel`, backed by AgentJail.app + the
# NETransparentProxyProvider system extension - see macos/README.md).
#
# The system extension requires one-time interactive user approval, which
# cannot be scripted. Default mode detects missing prerequisites and SKIPs
# loudly. `--strict` requires an activated extension and at least one executed
# tunnel scenario; it fails instead of treating all-SKIP as verification.
# See ADR 0136-tunnel-golden-image.
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
EXT_ID="com.blinkerlm.agentjail.extension"
NETWORK_DB="$HOME/.agentjail/network.db"
RESULT_PATH="${TUNNEL_SMOKE_RESULT:-}"

PASS=0; FAIL=0; SKIP=0; EXECUTED=0; SCENARIO_SKIP=0
EXT_STATE="unavailable"

ok()   { printf "  \033[32mPASS\033[0m  %s\n" "$1"; PASS=$((PASS+1)); }
bad()  { printf "  \033[31mFAIL\033[0m  %s\n     %s\n" "$1" "${2:-}"; FAIL=$((FAIL+1)); }
skip() { printf "  \033[33mSKIP\033[0m  %s (%s)\n" "$1" "${2:-}"; SKIP=$((SKIP+1)); }
group() { printf "\n\033[1m%s\033[0m\n" "$1"; }

wait_for_db_count() {
    local minimum="$1" query="$2" count=0 _attempt
    for _attempt in $(seq 1 30); do
        count="$(sqlite3 "$NETWORK_DB" "$query" 2>/dev/null || echo 0)"
        [[ "$count" =~ ^[0-9]+$ ]] || count=0
        if [ "$count" -ge "$minimum" ]; then
            printf '%s\n' "$count"
            return 0
        fi
        sleep 0.1
    done
    printf '%s\n' "$count"
    return 1
}

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
    EXT_LINES="$(grep -F "$EXT_ID" <<<"$EXT_LIST" || true)"
    EXT_LINE="$(grep -i "\[activated enabled\]" <<<"$EXT_LINES" | tail -1)"
    if [ -n "$EXT_LINE" ]; then
        EXT_APPROVED=1
        EXT_STATE="activated_enabled"
        ok "system extension $EXT_ID installed and approved"
    elif [ -n "$EXT_LINES" ]; then
        EXT_STATE="inactive"
        skip "system extension $EXT_ID installed and approved" "present but inactive: $EXT_LINES"
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

MATRIX_OUT=""
ALLOW_ROWS=0; HOST_DENIALS=0; PATH_DENIALS=0; HTTP80_DENIALS=0; API_ROWS=0
if [ "$CAN_RUN" = "1" ]; then
    EXECUTED=$((EXECUTED+1))
    MATRIX_BEFORE_ID=0
    if [ "$SQLITE_OK" = "1" ]; then
        MATRIX_BEFORE_ID="$(sqlite3 "$NETWORK_DB" 'select coalesce(max(id),0) from network_requests;' 2>/dev/null || echo 0)"
    fi
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
    - www.cloudflare.com
  port:
    - 80
action: deny
reason: "darwin strict smoke: cleartext port denied"
EOF

    MATRIX_OUT="$(run_with_timeout 90 env AGENTJAIL_NETPACKS_DIR="$MATRIX_PACKS" \
        "$SHIELD_BIN" --require-tunnel -- bash -c '
        curl -sS -o /dev/null -w "ALLOW_HTTPS:%{http_code}\n" --max-time 15 https://www.cloudflare.com/
        curl -sS -o /dev/null -w "AUDIT_HTTPS:%{http_code}\n" --max-time 15 https://api.github.com/
        curl -sS -o /dev/null -w "DENY_HOST:%{http_code}\n" --max-time 15 https://example.com/
        curl -sS -o /dev/null -w "DENY_PATH:%{http_code}\n" --max-time 15 https://api.github.com/repos/torvalds/linux
        curl -sS -o /dev/null -w "DENY_HTTP80:%{http_code}\n" --max-time 15 http://www.cloudflare.com/ || true
        env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy \
          curl --noproxy "*" -sS -o /dev/null -w "DENY_DIRECT:%{http_code}\n" --max-time 15 https://example.com/
        true
    ' 2>&1)"
    rm -rf "$MATRIX_WORK"

    # Policy proof is a post-watermark durable row; stderr is diagnostic only.
    # See docs/runbooks/macos-tunnel-release.md.
    if [ "$SQLITE_OK" = "1" ] && [ -f "$NETWORK_DB" ]; then
        ALLOW_ROWS="$(wait_for_db_count 1 "select count(*) from network_requests where id > $MATRIX_BEFORE_ID and host='www.cloudflare.com' and status_code=200;")" || true
        API_ROWS="$(wait_for_db_count 1 "select count(*) from network_requests where id > $MATRIX_BEFORE_ID and host='api.github.com' and path='/' and status_code=200;")" || true
        HOST_DENIALS="$(wait_for_db_count 2 "select count(*) from network_requests where id > $MATRIX_BEFORE_ID and host='example.com' and status_code=403 and policy_action='deny' and policy_template='darwin-deny-host';")" || true
        PATH_DENIALS="$(wait_for_db_count 1 "select count(*) from network_requests where id > $MATRIX_BEFORE_ID and host='api.github.com' and path='/repos/torvalds/linux' and status_code=403 and policy_action='deny' and policy_template='darwin-deny-path';")" || true
        HTTP80_DENIALS="$(wait_for_db_count 1 "select count(*) from network_requests where id > $MATRIX_BEFORE_ID and host in ('www.cloudflare.com','www.cloudflare.com:80') and policy_action='deny' and policy_template='darwin-deny-http-port';")" || true
    fi

    if grep -q "ALLOW_HTTPS:200" <<<"$MATRIX_OUT" && [ "${ALLOW_ROWS:-0}" -ge 1 ]; then
        ok "M1 allowed HTTPS succeeds through the captured port-443 path"
    else
        bad "M1 allowed HTTPS succeeds through the captured port-443 path" "status=$(grep -o 'ALLOW_HTTPS:[0-9]*' <<<"$MATRIX_OUT" | tail -1); durable-capture-rows=$ALLOW_ROWS"
    fi

    if grep -q "DENY_HOST:403" <<<"$MATRIX_OUT" && [ "${HOST_DENIALS:-0}" -ge 1 ]; then
        ok "M2 denied host is blocked by the named policy"
    else
        bad "M2 denied host is blocked by the named policy" "status=$(grep -o 'DENY_HOST:[0-9]*' <<<"$MATRIX_OUT" | tail -1); durable-policy-rows=$HOST_DENIALS"
    fi

    if grep -q "DENY_PATH:403" <<<"$MATRIX_OUT" && [ "${PATH_DENIALS:-0}" -ge 1 ]; then
        ok "M3 denied path is blocked by the named policy"
    else
        bad "M3 denied path is blocked by the named policy" "status=$(grep -o 'DENY_PATH:[0-9]*' <<<"$MATRIX_OUT" | tail -1); durable-policy-rows=$PATH_DENIALS"
    fi

    if grep -q "DENY_HTTP80:000" <<<"$MATRIX_OUT" && [ "${HTTP80_DENIALS:-0}" -ge 1 ]; then
        ok "M4 cleartext HTTP on port 80 is denied on the raw protocol path"
    else
        bad "M4 cleartext HTTP on port 80 is denied on the raw protocol path" "status=$(grep -o 'DENY_HTTP80:[0-9]*' <<<"$MATRIX_OUT" | tail -1); durable-policy-rows=$HTTP80_DENIALS"
    fi

    if grep -q "DENY_DIRECT:403" <<<"$MATRIX_OUT" && [ "${HOST_DENIALS:-0}" -ge 2 ]; then
        ok "M5 unsetting proxy variables and --noproxy cannot bypass the tunnel policy"
    else
        bad "M5 unsetting proxy variables and --noproxy cannot bypass the tunnel policy" "status=$(grep -o 'DENY_DIRECT:[0-9]*' <<<"$MATRIX_OUT" | tail -1); durable-host-denials=$HOST_DENIALS"
    fi
else
    SCENARIO_SKIP=$((SCENARIO_SKIP+1))
    skip "strict policy and bypass matrix" "extension not approved or agentjail-shield unavailable"
fi

# ================================================================ GROUP A8
group "A8 - HTTPS request through the tunnel returns 200 (TLS trust via injected CA)"

if [ "$CAN_RUN" = "1" ]; then
    EXECUTED=$((EXECUTED+1))
    if [ "${ALLOW_ROWS:-0}" -ge 1 ]; then
        ok "A8 HTTPS succeeds through the captured tunnel path"
    else
        bad "A8 HTTPS succeeds through the captured tunnel path" "status=$(grep -o 'ALLOW_HTTPS:[0-9]*' <<<"$MATRIX_OUT" | tail -1); durable-capture-rows=$ALLOW_ROWS"
    fi
else
    SCENARIO_SKIP=$((SCENARIO_SKIP+1))
    skip "A8  HTTPS request under the tunnel returns 200" "extension not approved or agentjail-shield unavailable"
fi

# ================================================================ GROUP A11
group "A11 - requests through the tunnel are logged to network.db"

if [ "$CAN_RUN" = "1" ] && [ "$SQLITE_OK" = "1" ]; then
    EXECUTED=$((EXECUTED+1))
    if [ "${API_ROWS:-0}" -gt 0 ]; then
        ok "A11 requests recorded to network.db (n=$API_ROWS)"
    else
        bad "A11 requests recorded to network.db" "status=$(grep -o 'AUDIT_HTTPS:[0-9]*' <<<"$MATRIX_OUT" | tail -1); count=$API_ROWS"
    fi
else
    SCENARIO_SKIP=$((SCENARIO_SKIP+1))
    skip "A11 requests recorded to network.db" "extension not approved, agentjail-shield unavailable, or sqlite3 missing"
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
