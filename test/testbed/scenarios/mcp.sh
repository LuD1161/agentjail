#!/usr/bin/env bash
# mcp.sh — MCP inspection surface (`mcp list`/`tools`/`scan`/`where`) plus the
# anti-self-approval guard: `mcp allow`/`mcp block` must be REFUSED when there
# is no interactive terminal, never silently mutate policy. Runs INSIDE a
# provisioned testbed guest.
set -u
AJ="$HOME/.agentjail/bin/agentjail"
PROJECT="$HOME/work/demo"

command -v gtimeout >/dev/null 2>&1 && timeout(){ command gtimeout "$@"; }
command -v timeout  >/dev/null 2>&1 || timeout(){ shift; "$@"; }

PASS=0; FAIL=0; SKIP=0
ok()   { echo "PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "FAIL  $1"; FAIL=$((FAIL+1)); }
skip() { echo "SKIP  $1"; SKIP=$((SKIP+1)); }

filt() { grep -vE 'resolving allowed_hosts|IPs resolved for allowed_hosts|could not resolve .*: lookup'; }

echo "=== mcp list ==="
OUT=$(timeout 30 "$AJ" mcp list 2>&1 | filt)
echo "$OUT" | head -30
echo "$OUT" | grep -qi "Installed MCP servers" && ok "mcp list shows Installed MCP servers" || bad "mcp list missing Installed MCP servers section"
echo "$OUT" | grep -qi "MCP allowed" && ok "mcp list shows MCP allowed" || bad "mcp list missing MCP allowed section"
echo "$OUT" | grep -qi "MCP blocked" && ok "mcp list shows MCP blocked" || bad "mcp list missing MCP blocked section"

echo "=== mcp tools (before scan) ==="
OUT=$(timeout 30 "$AJ" mcp tools 2>&1 | filt)
echo "$OUT" | head -10
echo "$OUT" | grep -qi "no MCP tool data found" && ok "mcp tools (pre-scan) reports no data / suggests scan" || bad "mcp tools (pre-scan) message not as expected"

echo "=== mcp scan ==="
OUT=$(timeout 60 "$AJ" mcp scan 2>&1 | filt)
echo "$OUT" | head -30
echo "$OUT" | grep -qi "MCP Server Scan" && ok "mcp scan header present" || bad "mcp scan header missing"
echo "$OUT" | grep -qi "Configured Servers" && ok "mcp scan shows Configured Servers" || bad "mcp scan missing Configured Servers"
echo "$OUT" | grep -qi "Summary" && ok "mcp scan shows Summary line" || bad "mcp scan missing Summary line"

echo "=== mcp where ==="
# Locate an actually-installed MCP server rather than assuming a specific host's
# set (the guest inherits whatever global MCPs the host had — fff/linear/etc).
WHO=$(timeout 30 "$AJ" mcp list 2>&1 | filt | awk '/Installed MCP servers/{f=1;next} f&&/✓/{print $2; exit}')
if [ -n "$WHO" ]; then
    OUT=$(timeout 30 "$AJ" mcp where "$WHO" 2>&1 | filt)
    echo "$OUT" | head -10
    echo "$OUT" | grep -qi "$WHO.*used in" && ok "mcp where reports usage locations ($WHO)" || bad "mcp where message not as expected"
else
    skip "mcp where (no installed MCP servers to locate)"
fi

echo "=== mcp allow / mcp block — anti-self-approval guard (non-TTY) ==="
OUT=$(timeout 30 "$AJ" mcp allow context7 < /dev/null 2>&1); RC=$?
echo "$OUT"
if echo "$OUT" | grep -qi "REFUSED" && echo "$OUT" | grep -qi "no interactive terminal"; then
    ok "mcp allow refused (no interactive terminal detected)"
else
    bad "mcp allow did not show expected REFUSED/no-interactive-terminal message"
fi
echo "$OUT" | grep -qi "self-approving an MCP server" && ok "mcp allow refusal names self-approval risk" || bad "mcp allow refusal missing self-approval wording"
[ "$RC" = 1 ] && ok "mcp allow exits 1 in non-TTY" || bad "mcp allow exit code $RC (expected 1)"

OUT=$(timeout 30 "$AJ" mcp block evilcorp < /dev/null 2>&1); RC=$?
echo "$OUT"
if echo "$OUT" | grep -qi "REFUSED" && echo "$OUT" | grep -qi "no interactive terminal"; then
    ok "mcp block refused (no interactive terminal detected)"
else
    bad "mcp block did not show expected REFUSED/no-interactive-terminal message"
fi
echo "$OUT" | grep -qi "self-approving an MCP server" && ok "mcp block refusal names self-approval risk" || bad "mcp block refusal missing self-approval wording"
[ "$RC" = 1 ] && ok "mcp block exits 1 in non-TTY" || bad "mcp block exit code $RC (expected 1)"

skip "mcp allow/block happy-path (requires interactive TTY confirmation)"

echo "=== RESULT: $PASS pass, $FAIL fail, $SKIP skip ==="
[ "$FAIL" = 0 ]
