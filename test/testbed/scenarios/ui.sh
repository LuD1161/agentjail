#!/usr/bin/env bash
# ui.sh — local web UI server: start `agentjail ui` headless (backgrounded,
# capped with a timeout), determine its listening port, curl it, assert
# HTTP 200 + a plausible <title>, then kill it. Runs INSIDE a provisioned
# testbed guest.
set -u
AJ="$HOME/.agentjail/bin/agentjail"
PROJECT="$HOME/work/demo"

command -v gtimeout >/dev/null 2>&1 && timeout(){ command gtimeout "$@"; }
command -v timeout  >/dev/null 2>&1 || timeout(){ shift; "$@"; }

PASS=0; FAIL=0; SKIP=0
ok()   { echo "PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "FAIL  $1"; FAIL=$((FAIL+1)); }
skip() { echo "SKIP  $1"; SKIP=$((SKIP+1)); }

UILOG=/tmp/ui-scenario.log
UIHTML=/tmp/ui-scenario.html
rm -f "$UILOG" "$UIHTML"

echo "=== ui — start headless, probe, stop ==="
( timeout 12 "$AJ" ui >"$UILOG" 2>&1 & )
sleep 5

echo "  ui log:"
sed 's/^/    /' "$UILOG" 2>/dev/null | head -10

UIPORT=$(grep -oE ':[0-9]{4,5}' "$UILOG" 2>/dev/null | tr -d ':' | head -1)
if [ -z "${UIPORT:-}" ]; then
    UIPORT=$(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | grep -i agentjail | grep -oE ':[0-9]{4,5}' | tr -d ':' | head -1)
fi
if [ -z "${UIPORT:-}" ]; then
    echo "  (could not determine ui port from log/lsof; falling back to documented default 9101)"
    UIPORT=9101
fi

if [ -n "${UIPORT:-}" ]; then
    ok "ui listening port: $UIPORT"
    CODE=$(curl -s -o "$UIHTML" -w '%{http_code}' "http://127.0.0.1:${UIPORT}/" 2>/dev/null)
    echo "  GET http://127.0.0.1:${UIPORT}/ -> HTTP $CODE"
    [ "$CODE" = "200" ] && ok "ui served HTTP 200" || bad "ui did not serve HTTP 200 (got ${CODE:-none})"
    TITLE=$(grep -oiE '<title>[^<]*' "$UIHTML" 2>/dev/null | head -1)
    echo "  title: ${TITLE:-<none>}"
    echo "$TITLE" | grep -qi "agentjail ui" && ok "ui page title contains 'agentjail ui'" || bad "ui page title does not contain 'agentjail ui' (got: ${TITLE:-<none>})"
else
    bad "could not determine ui listening port from log or lsof"
fi

pkill -f "agentjail ui" 2>/dev/null || true
sleep 1
if pgrep -f "agentjail ui" >/dev/null 2>&1; then
    bad "ui process still running after pkill"
else
    ok "ui process stopped"
fi

echo "=== RESULT: $PASS pass, $FAIL fail, $SKIP skip ==="
[ "$FAIL" = 0 ]
