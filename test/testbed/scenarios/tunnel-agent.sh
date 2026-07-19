#!/usr/bin/env bash
# tunnel-agent.sh — a REAL Claude Code task through the transparent tunnel.
#
# The only scenario that runs a live agent (not curl, not a hook-JSON probe)
# through `agentjail-shield --tunnel` and asserts the tunnel DECRYPTED and
# captured its own model traffic. This is the fixture the curl matrix cannot be:
# a real multi-turn model loop over TLS to api.anthropic.com, which is exactly
# what the h2 MITM has to intercept. See AGE-223 and plans/010-linux-tunnel-h2-e2e.
#
# Bodies are NOT persisted (ADR 0077) — we assert on per-request metadata:
# decrypted host, path, byte counts, and redaction hygiene.
#
# Needs (seeded by guest-provision): claude logged in, sqlite3, jq.
# testbed-mode: single
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/reportlib.sh"

SHIELD="$HOME/.agentjail/bin/agentjail-shield"
DB="$HOME/.agentjail/network.db"
WORK="$HOME/work/pelican"

scn_init "tunnel-agent" "real Claude session through --tunnel; tunnel decrypts its own model traffic"

if ! command -v claude >/dev/null; then scn_fail "claude installed"; scn_finish; exit; fi
if ! command -v sqlite3 >/dev/null; then scn_fail "sqlite3 installed"; scn_finish; exit; fi
[ -x "$SHIELD" ] && scn_ok "agentjail-shield installed" || { scn_fail "agentjail-shield installed"; scn_finish; exit; }

rm -rf "$WORK"; mkdir -p "$WORK"; cd "$WORK" || { scn_fail "workspace writable"; scn_finish; exit; }
git init -q 2>/dev/null || true

BEFORE="$(sqlite3 "$DB" 'select coalesce(max(id),0) from network_requests;' 2>/dev/null || echo 0)"
echo "  workspace: $WORK"
echo "  network.db watermark before: $BEFORE"

# A concrete developer task with real tool use: draw a pelican in inline SVG.
# One self-contained file, no CDN — the point is the model loop, not the art.
TASK="Create pelican.html in the current directory: a single self-contained HTML page with an inline SVG drawing of a pelican (no external CDN links, no frameworks). Keep it under 120 lines. Then stage and commit it with git. Report the file you created."

# guest_exec runs non-interactive bash, so the rcfile where provision exported
# CLAUDE_CODE_OAUTH_TOKEN is never sourced. Load the seeded token here so the
# real `claude -p` is authenticated.
[ -f "$HOME/.claude-token" ] && export CLAUDE_CODE_OAUTH_TOKEN="$(cat "$HOME/.claude-token")"
[ -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ] && scn_ok "Claude token present in scenario env" || scn_fail "Claude token present in scenario env"

echo "  === running the agent through the tunnel ==="
RUN_LOG="$WORK/.run.log"
timeout 900 "$SHIELD" --tunnel --mitm -- \
  claude -p "$TASK" \
  --allowedTools "Write" "Edit" "Bash" "Read" \
  --output-format text \
  >"$RUN_LOG" 2>&1 || true
tail -6 "$RUN_LOG" | grep -vE "landlock_add_rule|skip /home|denying read" | sed 's/^/    /'

# 0. The transparent tunnel must actually come up — a netproxy fallback means the
#    h2 MITM path was never exercised (e.g. unprivileged userns blocked).
if grep -qiE 'falling back to netproxy|tunnel not available' "$RUN_LOG"; then
  scn_fail "transparent tunnel came up (no netproxy fallback)"
  echo "  --- fallback reason + userns diagnostics ---"
  grep -iE 'tunnel unavailable|could not create|could not attach|tun-helper' "$RUN_LOG" | sed 's/^/    reason: /'
  echo "    apparmor_restrict_unprivileged_userns=$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null)"
  echo "    unshare -Urn: $(unshare -Urn true 2>&1 && echo OK || echo BLOCKED)"
  echo "    /dev/net/tun: $(ls -l /dev/net/tun 2>&1)"
  echo "    newuidmap: $(command -v newuidmap || echo MISSING)  newgidmap: $(command -v newgidmap || echo MISSING)"
  echo "    /etc/subuid: $(grep "^$USER:" /etc/subuid 2>/dev/null || echo 'no entry')"
else
  scn_ok "transparent tunnel came up (no netproxy fallback)"
fi

# 1. The agent actually did the work (proves the session ran, not just started).
[ -f "$WORK/pelican.html" ] && scn_ok "agent produced pelican.html" || scn_fail "agent produced pelican.html"
grep -qi "<svg" "$WORK/pelican.html" 2>/dev/null && scn_ok "artifact contains inline SVG" || scn_fail "artifact contains inline SVG"

# 2. The tunnel DECRYPTED the model traffic. A tunnel that fell back to netproxy,
#    or that failed to MITM the TLS, captures zero rows for the Anthropic host.
NEW_TOTAL="$(sqlite3 "$DB" "select count(*) from network_requests where id > $BEFORE;" 2>/dev/null || echo 0)"
API_REQS="$(sqlite3 "$DB" "select count(*) from network_requests where id > $BEFORE and host like '%anthropic%' and path like '%messages%';" 2>/dev/null || echo 0)"
API_RESP="$(sqlite3 "$DB" "select coalesce(sum(response_size),0) from network_requests where id > $BEFORE and host like '%anthropic%';" 2>/dev/null || echo 0)"
echo "  captured: $NEW_TOTAL new rows, $API_REQS model turns, ${API_RESP}B decrypted response"
[ "$NEW_TOTAL" -gt 0 ] && scn_ok "tunnel captured new requests" || scn_fail "tunnel captured new requests"
[ "$API_REQS" -gt 0 ] && scn_ok "tunnel decrypted model turns (/v1/messages)" || scn_fail "tunnel decrypted model turns (/v1/messages)"
[ "$API_RESP" -gt 0 ] && scn_ok "tunnel saw decrypted response bytes" || scn_fail "tunnel saw decrypted response bytes"

# 3. Credential hygiene — the capture is only publishable if nothing secret
#    reaches the DB in the clear. AGE-232 was exactly this (Dd-Api-Key leak).
LEAKS="$(sqlite3 "$DB" "select request_headers||' '||coalesce(response_headers,'') from network_requests where id > $BEFORE;" 2>/dev/null \
  | grep -oiE '"[a-z0-9_-]*(key|token|auth|secret|cookie|session)[a-z0-9_-]*":"[^"]{0,80}"' \
  | grep -viE '"\[REDACTED\]"' | grep -viE 'session-id|session_id' | sort -u)"
if [ -z "$LEAKS" ]; then
  scn_ok "every credential-shaped header is [REDACTED]"
else
  echo "  LEAK — reached the DB unredacted:"; sed 's/^/    /' <<<"$LEAKS"
  scn_fail "every credential-shaped header is [REDACTED]"
fi

scn_finish
