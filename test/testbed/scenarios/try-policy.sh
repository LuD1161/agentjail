#!/usr/bin/env bash
# try-policy.sh — the full `agentjail try` dry-run decision matrix across
# file rules (--read/--write) and command rules, asserting on `try --json`'s
# `.action` field. Nothing here executes any tool — `try` is dry-run by
# design. Runs INSIDE a provisioned testbed guest.
set -u
AJ="$HOME/.agentjail/bin/agentjail"
PROJECT="$HOME/work/demo"

command -v gtimeout >/dev/null 2>&1 && timeout(){ command gtimeout "$@"; }
command -v timeout  >/dev/null 2>&1 || timeout(){ shift; "$@"; }

PASS=0; FAIL=0; SKIP=0
ok()   { echo "PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "FAIL  $1"; FAIL=$((FAIL+1)); }
skip() { echo "SKIP  $1"; SKIP=$((SKIP+1)); }

# assert_try <allow|deny> <label> -- <try-args...>
assert_try() {
    local want="$1" label="$2"; shift 2
    [ "${1:-}" = "--" ] && shift
    local out; out=$(timeout 30 "$AJ" try --json "$@" 2>/dev/null)
    if printf '%s' "$out" | grep -q "\"action\":\"$want\""; then
        ok "$label -> $want"
    else
        bad "$label -> expected $want, got: $out"
    fi
}

# info_try: informational only, no hard assertion (less-certain outcome) —
# still prints the observed action so it's visible in the log.
info_try() {
    local label="$1"; shift
    [ "${1:-}" = "--" ] && shift
    local out; out=$(timeout 30 "$AJ" try --json "$@" 2>/dev/null)
    local action; action=$(printf '%s' "$out" | grep -oE '"action":"[a-z]+"' | head -1)
    echo "INFO  $label -> $action (raw: $out)"
}

mkdir -p "$PROJECT"

echo "=== file rules ==="
assert_try deny  "write ~/.ssh/authorized_keys" -- --write "$HOME/.ssh/authorized_keys"
assert_try deny  "write ~/.aws/credentials"      -- --write "$HOME/.aws/credentials"
assert_try deny  "read  ~/.ssh/id_rsa"           -- --read  "$HOME/.ssh/id_rsa"
assert_try allow "write \$PROJECT/note.txt"      -- --write "$PROJECT/note.txt"
assert_try allow "read  \$PROJECT/README.md"     -- --read  "$PROJECT/README.md"

echo "=== command rules ==="
assert_try deny  "sudo rm -rf /"                 -- sudo rm -rf /
assert_try deny  "rm -rf /"                      -- rm -rf /
assert_try deny  "chmod 777 /etc/hosts"          -- chmod 777 /etc/hosts
assert_try deny  "git push -f origin main"       -- git push -f origin main
assert_try allow "ls (benign default-allow)"     -- ls

echo "=== less-certain outcomes (informational, not hard-asserted) ==="
info_try "write \$PROJECT/.env (expected: deny/sensitive_in_project)" -- --write "$PROJECT/.env"
info_try "write /tmp/x (expected: allow/temp_allow)"                  -- --write /tmp/x
info_try "write ~/.agentjail/x (expected: deny/agentjail_self)"       -- --write "$HOME/.agentjail/x"

echo "=== try (non-JSON) still exits 0 and prints a decision line ==="
OUT=$(timeout 30 "$AJ" try --write "$HOME/.ssh/authorized_keys" 2>&1); RC=$?
echo "$OUT" | head -3
[ "$RC" = 0 ] && ok "try (non-json) exits 0 regardless of decision" || bad "try (non-json) exit $RC (expected 0)"
echo "$OUT" | grep -qE '(✗ deny|✓ allow)' && ok "try (non-json) prints a decision glyph line" || bad "try (non-json) decision line missing"

echo "=== RESULT: $PASS pass, $FAIL fail, $SKIP skip ==="
[ "$FAIL" = 0 ]
