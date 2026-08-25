#!/usr/bin/env bash
# tunnel-agent.sh — a REAL Codex task through the transparent tunnel.
#
# The only scenario that runs a live agent (not curl, not a hook-JSON probe)
# through `agentjail-shield --tunnel` and asserts the tunnel DECRYPTED and
# captured its own model traffic. This is the fixture the curl matrix cannot be:
# a real model loop over TLS to OpenAI, which is exactly
# what the h2 MITM has to intercept. See AGE-223 and plans/010-linux-tunnel-h2-e2e.
#
# Bodies are NOT persisted (ADR 0077) — we assert on per-request metadata:
# decrypted host, path, byte counts, and redaction hygiene.
#
# Needs: Codex installed plus a disposable auth cache injected by testbed.sh.
# testbed-mode: single
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/reportlib.sh"
command -v gtimeout >/dev/null 2>&1 && timeout(){ command gtimeout "$@"; }
command -v timeout >/dev/null 2>&1 || timeout(){ shift; "$@"; }

SHIELD="$HOME/.agentjail/bin/agentjail-shield"
CODEX_SHIM="$HOME/.agentjail/bin/codex"
DB="$HOME/.agentjail/network.db"
AUDIT_DB="$HOME/.agentjail/agentjail.db"
WORK="$HOME/work/pelican"

# Auth is copied only for this scenario and removed on every exit. Treat it as
# a password. See ADR 0130-codex-live-gate.
cleanup() {
    rm -f /tmp/codex-auth.json "$HOME/.codex/auth.json"
}
trap cleanup EXIT INT TERM

scn_init "tunnel-agent" "real Codex session through --tunnel; tunnel decrypts its own model traffic"
[ -x "$SHIELD" ] && scn_ok "agentjail-shield installed" || { scn_fail "agentjail-shield installed"; scn_finish; exit; }
command -v codex >/dev/null 2>&1 && scn_ok "Codex CLI installed" || { scn_fail "Codex CLI installed"; scn_finish; exit; }
[ -x "$CODEX_SHIM" ] && scn_ok "Codex PATH shim installed" || { scn_fail "Codex PATH shim installed"; scn_finish; exit; }
command -v sqlite3 >/dev/null 2>&1 || { scn_fail "sqlite3 installed"; scn_finish; exit; }
if [ "$(uname -s)" = "Darwin" ]; then
    EXT_ID="com.blinkerlm.agentjail.app.extension"
    EXT_LINES="$(systemextensionsctl list 2>&1 | grep -F "$EXT_ID" || true)"
    EXT_LINE="$(grep -i '\[activated enabled\]' <<<"$EXT_LINES" | tail -1)"
    if [ -n "$EXT_LINE" ]; then
        scn_ok "macOS tunnel extension is present and activated"
    else
        echo "  extension state: ${EXT_LINES:-missing}"
        scn_fail "macOS tunnel extension is present and activated"
        scn_finish
        exit
    fi
    if [ -x /Applications/AgentJail.app/Contents/MacOS/AgentJail ]; then
        scn_ok "containing tunnel app remains installed in /Applications"
    else
        scn_fail "containing tunnel app remains installed in /Applications"
        scn_finish
        exit
    fi
    STRICT_SMOKE="/tmp/testbed/tunnel-e2e/smoke_darwin.sh"
    STRICT_RESULT="${SCN_JSON:-/tmp/testbed/results/tunnel-agent.result.json}"
    STRICT_RESULT="${STRICT_RESULT%.result.json}.strict.result.json"
    if [ ! -f "$STRICT_SMOKE" ]; then
        scn_fail "strict Darwin tunnel matrix is available"
        scn_finish
        exit
    fi
    if PATH="$HOME/.agentjail/bin:$PATH" TUNNEL_SMOKE_RESULT="$STRICT_RESULT" \
        bash "$STRICT_SMOKE" --strict; then
        scn_ok "strict Darwin host/path/port/protocol/bypass matrix passes"
    else
        scn_fail "strict Darwin host/path/port/protocol/bypass matrix passes"
        scn_finish
        exit
    fi
fi
if [ ! -f /tmp/codex-auth.json ]; then
    scn_fail "disposable Codex auth was explicitly provided"
    scn_finish
    exit
fi
mkdir -p "$HOME/.codex"
chmod 700 "$HOME/.codex"
install -m 0600 /tmp/codex-auth.json "$HOME/.codex/auth.json"
rm -f /tmp/codex-auth.json
codex login status >/dev/null 2>&1 \
    && scn_ok "Codex accepts the disposable authenticated session" \
    || { scn_fail "Codex accepts the disposable authenticated session"; scn_finish; exit; }

rm -rf "$WORK"; mkdir -p "$WORK"; cd "$WORK" || { scn_fail "workspace writable"; scn_finish; exit; }
git init -q 2>/dev/null || true

BEFORE="$(sqlite3 "$DB" 'select coalesce(max(id),0) from network_requests;' 2>/dev/null || echo 0)"
AUDIT_BEFORE="$(sqlite3 "$AUDIT_DB" 'select coalesce(max(id),0) from audit_log;' 2>/dev/null || echo 0)"
echo "  workspace: $WORK"
echo "  network.db watermark before: $BEFORE"

# A concrete developer task with real tool use: draw a pelican in inline SVG.
# One self-contained file, no CDN — the point is the model loop, not the art.
TASK="Create pelican.html in the current directory: a single self-contained HTML page with an inline SVG drawing of a pelican (no external CDN links, no frameworks). Keep it under 120 lines. Then stage and commit it with git. Report the file you created."

echo "  === running the agent through the tunnel ==="
RUN_LOG="$WORK/.run.log"
RUN_RC=0
AGENTJAIL_REQUIRE_TUNNEL=1 timeout 900 "$CODEX_SHIM" --dangerously-bypass-approvals-and-sandbox \
  --dangerously-bypass-hook-trust -C "$WORK" \
  exec --ephemeral "$TASK" \
  >"$RUN_LOG" 2>&1 || RUN_RC=$?
tail -6 "$RUN_LOG" | grep -vE "landlock_add_rule|skip /home|denying read" | sed 's/^/    /'

# 0. SQLite lifecycle events are the source of truth. Terminal output is kept
#    only as bounded diagnostics and cannot turn a fallback into a pass.
TUNNEL_SESSION="$(sqlite3 "$AUDIT_DB" "select session_id from audit_log where id > $AUDIT_BEFORE and event_type='tunnel.session_registered' and coalesce(json_extract(detail,'$.failure_reason'),'') = '' order by id desc limit 1;" 2>/dev/null || true)"
TUNNEL_FAILURE="$(sqlite3 "$AUDIT_DB" "select json_extract(detail,'$.failure_reason') from audit_log where id > $AUDIT_BEFORE and event_type='tunnel.extension_started' and coalesce(json_extract(detail,'$.failure_reason'),'') != '' order by id desc limit 1;" 2>/dev/null || true)"
if [ "$RUN_RC" -eq 0 ] && [ -n "$TUNNEL_SESSION" ] && [ -z "$TUNNEL_FAILURE" ]; then
  scn_ok "structured lifecycle proves the required tunnel started"
else
  echo "  tunnel launch: exit=$RUN_RC session=${TUNNEL_SESSION:+present} failure=${TUNNEL_FAILURE:-none}"
  scn_fail "structured lifecycle proves the required tunnel started"
fi

# 1. The agent actually did the work (proves the session ran, not just started).
[ -f "$WORK/pelican.html" ] && scn_ok "agent produced pelican.html" || scn_fail "agent produced pelican.html"
grep -qi "<svg" "$WORK/pelican.html" 2>/dev/null && scn_ok "artifact contains inline SVG" || scn_fail "artifact contains inline SVG"

# 2. The tunnel DECRYPTED the model traffic. A tunnel that fell back to netproxy,
#    or that failed to MITM TLS, captures zero OpenAI/Codex model rows.
NEW_TOTAL="$(sqlite3 "$DB" "select count(*) from network_requests where id > $BEFORE;" 2>/dev/null || echo 0)"
MODEL_ROWS="$(sqlite3 "$DB" "select count(*) from network_requests where id > $BEFORE and (host like '%openai%' or host like '%chatgpt%') and (path like '%responses%' or path like '%codex%');" 2>/dev/null || echo 0)"
RESPONSE_POSTS="$(sqlite3 "$DB" "select count(*) from network_requests where id > $BEFORE and method='POST' and path='/backend-api/codex/responses';" 2>/dev/null || echo 0)"
# SSE clients may cancel after consuming 2xx response bytes; task completion is
# independently proven above. See ADR 0092-persist-request-bodies (D1).
RESPONSE_COMPLETED="$(sqlite3 "$DB" "select count(*) from network_requests where id > $BEFORE and method='POST' and path='/backend-api/codex/responses' and status_code between 200 and 299 and response_size > 0 and coalesce(error,'')='';" 2>/dev/null || echo 0)"
RESPONSE_ERRORS="$(sqlite3 "$DB" "select count(*) from network_requests where id > $BEFORE and method='POST' and path='/backend-api/codex/responses' and coalesce(error,'')<>'';" 2>/dev/null || echo 0)"
RESPONSE_CLIENT_CANCELED="$(sqlite3 "$DB" "select count(*) from network_requests where id > $BEFORE and method='POST' and path='/backend-api/codex/responses' and status_code between 200 and 299 and response_size > 0 and error='write response to client: context canceled';" 2>/dev/null || echo 0)"
RESPONSE_ACCEPTED="$((RESPONSE_COMPLETED + RESPONSE_CLIENT_CANCELED))"
RESPONSE_UNEXPECTED_ERRORS="$((RESPONSE_POSTS - RESPONSE_ACCEPTED))"
REQUEST_BODY_PATHS="$(sqlite3 "$DB" "select count(*) from network_requests where id > $BEFORE and method='POST' and path='/backend-api/codex/responses' and coalesce(request_body_path,'')<>'';" 2>/dev/null || echo 0)"
RESPONSE_BODY_PATHS="$(sqlite3 "$DB" "select count(*) from network_requests where id > $BEFORE and method='POST' and path='/backend-api/codex/responses' and coalesce(response_body_path,'')<>'';" 2>/dev/null || echo 0)"
API_REQ_BYTES="$(sqlite3 "$DB" "select coalesce(sum(request_size),0) from network_requests where id > $BEFORE and (host like '%openai%' or host like '%chatgpt%');" 2>/dev/null || echo 0)"
API_RESP="$(sqlite3 "$DB" "select coalesce(sum(response_size),0) from network_requests where id > $BEFORE and (host like '%openai%' or host like '%chatgpt%');" 2>/dev/null || echo 0)"
METRICS="${SCN_JSON%.result.json}.metrics.json"
jq -nc --argjson rows "$NEW_TOTAL" --argjson model_rows "$MODEL_ROWS" \
  --argjson response_posts "$RESPONSE_POSTS" --argjson completed "$RESPONSE_COMPLETED" \
  --argjson response_errors "$RESPONSE_ERRORS" --argjson accepted "$RESPONSE_ACCEPTED" \
  --argjson client_canceled "$RESPONSE_CLIENT_CANCELED" \
  --argjson unexpected_errors "$RESPONSE_UNEXPECTED_ERRORS" --argjson request_bytes "$API_REQ_BYTES" \
  --argjson response_bytes "$API_RESP" --argjson request_body_paths "$REQUEST_BODY_PATHS" \
  --argjson response_body_paths "$RESPONSE_BODY_PATHS" \
  '{schema_version:1,network_rows:$rows,model_endpoint_rows:$model_rows,response_posts:$response_posts,response_posts_accepted:$accepted,response_posts_completed:$completed,response_posts_with_error:$response_errors,response_posts_client_canceled:$client_canceled,response_posts_unexpected_errors:$unexpected_errors,request_bytes:$request_bytes,response_bytes:$response_bytes,request_body_paths:$request_body_paths,response_body_paths:$response_body_paths}' \
  >"$METRICS"
echo "  captured: $NEW_TOTAL new rows, $MODEL_ROWS model endpoint rows, $RESPONSE_POSTS response POSTs ($RESPONSE_COMPLETED completed, $RESPONSE_CLIENT_CANCELED client-canceled, $RESPONSE_UNEXPECTED_ERRORS unexpected errors), ${API_REQ_BYTES}B decrypted request, ${API_RESP}B decrypted response"
[ "$NEW_TOTAL" -gt 0 ] && scn_ok "tunnel captured new requests" || scn_fail "tunnel captured new requests"
[ "$RESPONSE_POSTS" -gt 0 ] && [ "$RESPONSE_ACCEPTED" -eq "$RESPONSE_POSTS" ] && [ "$RESPONSE_UNEXPECTED_ERRORS" -eq 0 ] && scn_ok "tunnel captured only successful or client-canceled Codex response streams" || scn_fail "tunnel captured only successful or client-canceled Codex response streams"
[ "$API_REQ_BYTES" -gt 0 ] && scn_ok "tunnel saw decrypted request bytes" || scn_fail "tunnel saw decrypted request bytes"
[ "$API_RESP" -gt 0 ] && scn_ok "tunnel saw decrypted response bytes" || scn_fail "tunnel saw decrypted response bytes"
[ "$REQUEST_BODY_PATHS" -gt 0 ] && [ "$RESPONSE_BODY_PATHS" -gt 0 ] && scn_ok "tunnel persisted encrypted or explicitly degraded request and response bodies" || scn_fail "tunnel persisted encrypted or explicitly degraded request and response bodies"

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

scn_auth_scan "$WORK"

scn_finish
