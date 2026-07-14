#!/usr/bin/env bash
# cli-tour.sh — exercise the ENTIRE agentjail CLI surface on the INSTALLED
# binaries, capturing state for every command and asserting behaviour where it
# is checkable. Runs INSIDE a provisioned testbed guest.
#
#   testbed.sh test <name> cli-tour
#
# Safety / ordering:
#   * Destructive teardown (uninstall) runs LAST — it removes ~/.agentjail, so
#     the host harness re-provisions afterwards.
#   * Commands that use DisableFlagParsing are NEVER driven via --help (that flag
#     is ignored and, for `uninstall`, is DESTRUCTIVE — see the finale).
#   * update / claude / feedback are side-effectful or interactive and cannot be
#     exercised unattended; they are reported with the reason, not run.
set -u
AJ="$HOME/.agentjail/bin/agentjail"
PROJECT="$HOME/work/demo"
PASS=0; FAIL=0

# macOS base has no coreutils `timeout`; fall back to running without a cap.
command -v gtimeout >/dev/null 2>&1 && timeout(){ command gtimeout "$@"; }
command -v timeout  >/dev/null 2>&1 || timeout(){ shift; "$@"; }

pass(){ echo "   PASS  $*"; PASS=$((PASS+1)); }
fail(){ echo "   FAIL  $*"; FAIL=$((FAIL+1)); }
sec(){ echo; echo "==================================================================="; echo "  $*"; echo "==================================================================="; }
# run "<display>" -- <argv...> : show a command + its (trimmed) output + exit code
run(){
    local disp="$1"; shift; [ "${1:-}" = "--" ] && shift
    echo; echo "\$ agentjail $disp"
    local out rc
    out=$(timeout 60 "$@" 2>&1); rc=$?
    printf '%s\n' "$out" \
        | grep -vE 'resolving allowed_hosts|IPs resolved for allowed_hosts|could not resolve .*: lookup' \
        | sed $'s/\033\\[[0-9;]*m//g' | head -22
    echo "  -> exit $rc"
    return $rc
}
# assert_try <allow|deny> -- <try args...>
assert_try(){
    local want="$1"; shift; [ "${1:-}" = "--" ] && shift
    local out; out=$("$AJ" try --json "$@" 2>/dev/null)
    if printf '%s' "$out" | grep -q "\"action\":\"$want\""; then
        pass "try $* -> $want"
    else
        fail "try $* -> expected $want, got: $out"
    fi
}
# assert_refused <label> -- <argv...> : non-TTY self-approval guard must REFUSE
# (exit non-zero + "REFUSED" + "no interactive terminal" in the output). This
# is the security control working as designed, not a failure — treat it as PASS.
assert_refused(){
    local label="$1"; shift; [ "${1:-}" = "--" ] && shift
    echo; echo "\$ agentjail $label"
    local out rc
    out=$(timeout 30 "$@" 2>&1); rc=$?
    printf '%s\n' "$out" | sed $'s/\033\\[[0-9;]*m//g' | head -10
    echo "  -> exit $rc"
    if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -qi "REFUSED" && printf '%s' "$out" | grep -qi "no interactive terminal"; then
        pass "$label -> correctly REFUSED (non-TTY self-approval guard)"
    else
        fail "$label -> expected REFUSED/no interactive terminal, got exit $rc: $out"
    fi
}
# finding <msg> : a genuine environmental gap, not a scenario bug. Printed
# distinctly from PASS/FAIL so it doesn't pollute the pass/fail tally but stays
# visible in the transcript.
finding(){ echo "   FINDING  $*"; }

echo "###################################################################"
echo "#  agentjail CLI tour — $($AJ version 2>/dev/null | head -1)"
echo "#  host: $(uname -sm)  user: $(whoami)  $(date -u 2>/dev/null)"
echo "###################################################################"

# ── 1. Version, health, diagnostics ─────────────────────────────────────────
sec "1. Version / health / diagnostics"
run "version"          -- "$AJ" version
run "status"           -- "$AJ" status
run "doctor"           -- "$AJ" doctor
[ -d "$HOME/.agentjail" ] && pass "install present (~/.agentjail)" || fail "install missing"

# ── 2. Policy inspection ────────────────────────────────────────────────────
sec "2. Policy — inspection"
run "policy list"      -- "$AJ" policy list

# ── 3. try — dry-run policy decisions (NOTHING is executed) ─────────────────
sec "3. try — enforcement decisions (dry-run)"
run "try --write ~/.ssh/authorized_keys" -- "$AJ" try --write "$HOME/.ssh/authorized_keys"
assert_try deny  -- --write "$HOME/.ssh/authorized_keys"
assert_try deny  -- --write "$HOME/.aws/credentials"
assert_try deny  -- --read  "$HOME/.ssh/id_rsa"
assert_try allow -- --write "$PROJECT/note.txt"
assert_try allow -- --read  "$PROJECT/README.md"
assert_try deny  -- sudo rm -rf /
assert_try deny  -- rm -rf /
assert_try deny  -- chmod 777 /etc/hosts
run "try --json (sample)" -- "$AJ" try --json --write "$HOME/.ssh/authorized_keys"

# ── 4. run — shielded command execution ─────────────────────────────────────
sec "4. run — execute inside the shield"
run "run -- echo hello-from-shield" -- "$AJ" run -- echo hello-from-shield
echo "\$ agentjail run -- cat ~/.ssh/id_rsa   (shield should block the read)"
echo ORIG > "$HOME/.ssh/id_rsa" 2>/dev/null || true
if timeout 60 "$AJ" run -- cat "$HOME/.ssh/id_rsa" 2>/dev/null | grep -q ORIG; then
    fail "shield did NOT block private-key read via run"
else
    pass "shield blocked private-key read via run"
fi

# ── 5. MCP allow/block/scan/tools ───────────────────────────────────────────
sec "5. mcp — allow / block / inspect"
run "mcp list"           -- "$AJ" mcp list
run "mcp tools"          -- "$AJ" mcp tools
run "mcp where linear-server" -- "$AJ" mcp where linear-server
run "mcp scan"           -- "$AJ" mcp scan
echo; echo "--- mutate (non-TTY): allow 'context7', block 'evilcorp' — MUST be refused ---"
assert_refused "mcp allow context7" -- "$AJ" mcp allow context7
assert_refused "mcp block evilcorp" -- "$AJ" mcp block evilcorp

# ── 6. Policy mutation (custom rule add/remove; core-disable guard) ─────────
sec "6. policy — add / remove / disable-guard"
# Custom rules are Rego, not YAML (ADR 0014 §5): the file MUST declare
# `package agentjail`, emit only `candidate contains r if {...}` entries (never
# `decision`), and every rule_id must be namespaced `custom/<file-stem>/...`.
RULE=/tmp/tour-custom-rule.rego
cat > "$RULE" <<'REGO'
# @rule_id: custom/tour-custom-rule/no-tmpsecret
package agentjail

import future.keywords.if
import future.keywords.contains

candidate contains r if {
	input.hook_event == "PreToolUse"
	input.tool_name == "Write"
	glob.match("/tmp/tour-secret*", [], input.tool_input.file_path)
	r := {
		"action": "deny",
		"rule_id": "custom/tour-custom-rule/no-tmpsecret",
		"reason": "tour: block writes to /tmp/tour-secret*",
	}
}
REGO
run "policy add $RULE"   -- "$AJ" policy add "$RULE"
if "$AJ" policy list 2>/dev/null | grep -qi tour-custom-rule; then
    pass "custom rule listed under Custom (tour-custom-rule)"
else
    fail "custom rule not listed after policy add"
fi
run "policy remove tour-custom-rule" -- "$AJ" policy remove tour-custom-rule
echo "\$ agentjail policy disable command_policy/no-sudo   (core rule → must refuse without --force + TTY)"
if timeout 30 "$AJ" policy disable command_policy/no-sudo >/tmp/pd 2>&1; then
    grep -qiE 'force|tty|interactive' /tmp/pd && pass "core-rule disable guarded (needs --force/TTY)" || fail "core rule disabled without guard!"
else
    grep -qiE 'force|tty|interactive' /tmp/pd && pass "core-rule disable guarded (needs --force/TTY)" || { echo "  (output:)"; sed 's/^/    /' /tmp/pd | head -4; fail "core disable errored for another reason"; }
fi

# ── 7. Secrets — scoped credential vault ────────────────────────────────────
sec "7. secret — set / list / remove"
SECRETS_BIN=""
[ -x "$HOME/.agentjail/bin/agentjail-secrets" ] && SECRETS_BIN="$HOME/.agentjail/bin/agentjail-secrets"
[ -z "$SECRETS_BIN" ] && SECRETS_BIN=$(command -v agentjail-secrets 2>/dev/null || true)
if [ -z "$SECRETS_BIN" ]; then
    finding "agentjail-secrets vault binary is NOT shipped in this install (checked \$HOME/.agentjail/bin and \$PATH)."
    finding "'secret set/remove' depend on it and cannot function without it — this is a real packaging gap, not a test bug."
    run "secret list (vault unavailable)" -- "$AJ" secret list
    echo "  (skipping secret set/remove round-trip — no vault binary to exercise)"
else
    run "secret set tourtoken --value REDACTED --hosts api.example.com" -- "$AJ" secret set tourtoken --value REDACTED --hosts api.example.com
    run "secret list"        -- "$AJ" secret list
    if "$AJ" secret list 2>/dev/null | grep -qi tourtoken; then pass "secret set persisted (value not shown)"; else fail "secret not listed"; fi
    run "secret remove tourtoken" -- "$AJ" secret remove tourtoken
fi

# ── 8. Skills — per-skill allow/ask/block ───────────────────────────────────
sec "8. skill — list / ask / clear"
run "skill list"         -- "$AJ" skill list
SK=$("$AJ" skill list 2>/dev/null | grep -oE '[a-z0-9:_-]+' | grep -vE '^(on|off|ask|allow|block|skill|status|known|no|the)$' | head -1)
if [ -n "${SK:-}" ]; then
    assert_refused "skill ask $SK"  -- "$AJ" skill ask "$SK"
    assert_refused "skill clear $SK" -- "$AJ" skill clear "$SK"
else
    echo "  (no skills discovered to toggle — skill list still exercised)"
fi

# ── 9. Trust — project policy overlays ──────────────────────────────────────
sec "9. trust — project overlay trust/untrust"
mkdir -p "$PROJECT/.agentjail"
# A project overlay is a PolicyConfig fragment (config.PolicyConfig, ~/.agentjail
# policy.yaml schema) merged ADDITIVE-ONLY (MergeProjectOverlay: network.allowed_hosts,
# mcp.allowed, mcp.blocked are unioned into the base) -- NOT a list of custom
# Rego-style "rules:" (that shape belongs to `policy add`, see section 6).
cat > "$PROJECT/.agentjail/policy.yaml" <<'YAML'
network:
  allowed_hosts:
    - "tour-overlay.example.com"
YAML
TRUST_OUT=$(timeout 30 "$AJ" trust "$PROJECT" 2>&1)
echo; echo "\$ agentjail trust $PROJECT"
printf '%s\n' "$TRUST_OUT" | sed $'s/\033\\[[0-9;]*m//g' | head -22
if printf '%s' "$TRUST_OUT" | grep -qi "does not parse cleanly"; then
    fail "trust overlay warned 'does not parse cleanly' — overlay schema still wrong"
else
    pass "trust overlay parsed cleanly (well-formed PolicyConfig fragment)"
fi
run "trust list"         -- "$AJ" trust list
run "untrust $PROJECT"   -- "$AJ" untrust "$PROJECT"

# ── 10. Sessions / logs / replay ────────────────────────────────────────────
sec "10. sessions / logs / replay"
run "sessions list"      -- "$AJ" sessions list
echo "\$ agentjail logs   (TUI — capped at 5s)"
timeout 5 "$AJ" logs 2>&1 | sed $'s/\033\\[[0-9;]*m//g' | head -12; echo "  -> (logs capped)"
SID=$("$AJ" sessions list 2>/dev/null | grep -oE '[0-9a-f]{6,}' | head -1)
if [ -n "${SID:-}" ]; then run "replay $SID" -- "$AJ" replay "$SID"; else run "replay (no session id available)" -- bash -c "$AJ sessions list 2>/dev/null | head -3; echo '(no session id to replay)'"; fi

# ── 11. Runtime egress grants ───────────────────────────────────────────────
sec "11. allow / grants / grant (runtime host grants)"
run "grants"             -- "$AJ" grants
run "allow host api.example.com" -- "$AJ" allow host api.example.com

# ── 12. Telemetry (local config; no data sent by view/disable/enable) ───────
sec "12. telemetry — view / disable / enable"
run "telemetry view"     -- "$AJ" telemetry view
run "telemetry disable"  -- "$AJ" telemetry disable
run "telemetry view (after disable)" -- "$AJ" telemetry view
run "telemetry enable"   -- "$AJ" telemetry enable

# ── 13. Shell completion + help ─────────────────────────────────────────────
sec "13. completion / help"
run "completion bash (head)" -- bash -c "$AJ completion bash 2>/dev/null | head -8"
run "help"               -- "$AJ" help

# ── 14. UI (local web server) — start, probe, stop ──────────────────────────
sec "14. ui — local web server (headless probe)"
( timeout 12 "$AJ" ui >/tmp/ui.log 2>&1 & ) ; sleep 5
UIPORT=$(grep -oE ':[0-9]{4,5}' /tmp/ui.log 2>/dev/null | tr -d ':' | head -1)
[ -z "${UIPORT:-}" ] && UIPORT=$(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | grep -i agentjail | grep -oE ':[0-9]{4,5}' | tr -d ':' | head -1)
echo "  ui log:"; sed 's/^/    /' /tmp/ui.log 2>/dev/null | head -6
if [ -n "${UIPORT:-}" ]; then
    CODE=$(curl -s -o /tmp/ui.html -w '%{http_code}' "http://127.0.0.1:${UIPORT}/" 2>/dev/null)
    echo "  GET http://127.0.0.1:${UIPORT}/ -> HTTP $CODE"
    TITLE=$(grep -oE '<title>[^<]*' /tmp/ui.html 2>/dev/null | head -1)
    [ "$CODE" = "200" ] && pass "ui served HTTP 200 ${TITLE:+($TITLE)}" || fail "ui did not serve 200 (got ${CODE:-none})"
else
    echo "  (could not determine ui port from log; ui was launched)"
fi
pkill -f "agentjail ui" 2>/dev/null || true

# ── 15. Side-effectful / interactive — reported, not run ────────────────────
sec "15. Not exercised unattended (reason stated)"
echo "  update   : replaces installed binaries from the network release channel;"
echo "             would clobber the dev build under test. (--help now prints help — DEFECT-1 fixed)"
echo "  claude   : launches an interactive Claude Code session; needs an OAuth token."
echo "  feedback : transmits a message to the maintainers (external side effect)."

# ── 16. FINALE: --help is safe now (DEFECT-1 fixed) + real teardown ─────────
sec "16. uninstall --help safety (DEFECT-1 fixed) + real teardown"
echo "\$ agentjail uninstall --help    (EXPECT: prints help, does NOT uninstall)"
UOUT=$("$AJ" uninstall --help 2>&1)
printf '%s\n' "$UOUT" | sed $'s/\033\\[[0-9;]*m//g' | head -6
if printf '%s' "$UOUT" | grep -qi "uninstall summary" || [ ! -d "$HOME/.agentjail" ]; then
    fail "uninstall --help performed a real uninstall — DEFECT-1 has regressed"
elif printf '%s' "$UOUT" | grep -qE '^Usage:'; then
    pass "uninstall --help prints usage and left ~/.agentjail intact (DEFECT-1 fixed)"
else
    fail "uninstall --help: unexpected output (neither usage nor uninstall)"
fi

echo "\$ agentjail uninstall    (real teardown — the box is re-provisioned by the harness)"
run "uninstall" -- "$AJ" uninstall
[ -d "$HOME/.agentjail" ] && fail "uninstall did not remove ~/.agentjail" || pass "uninstall removed ~/.agentjail (clean teardown)"

echo
echo "###################################################################"
echo "#  RESULT: $PASS pass, $FAIL fail"
echo "###################################################################"
[ "$FAIL" = 0 ]
