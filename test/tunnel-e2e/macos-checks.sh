#!/usr/bin/env bash
# macOS tunnel and shield checks.
#
# The Network Extension tunnel is wired on Darwin. Its release assertion needs
# the approved golden-macos-mitm guest and the strict smoke contract; a fresh
# unapproved guest is not equivalent. See ADR 0135-tunnel-golden-image.
#
# Usage:  bash test/tunnel-e2e/macos-checks.sh
#
set -uo pipefail

PASS=0; FAIL=0; SKIP=0; INFO=0
ok()   { printf "  \033[32mPASS\033[0m  %s\n" "$1"; PASS=$((PASS+1)); }
bad()  { printf "  \033[31mFAIL\033[0m  %s\n     %s\n" "$1" "${2:-}"; FAIL=$((FAIL+1)); }
skip() { printf "  \033[33mSKIP\033[0m  %s (%s)\n" "$1" "${2:-}"; SKIP=$((SKIP+1)); }
note() { printf "  \033[36mINFO\033[0m  %s\n" "$1"; INFO=$((INFO+1)); }
group(){ printf "\n\033[1m%s\033[0m\n" "$1"; }

[ "$(uname -s)" = "Darwin" ] || { echo "This script is for macOS. On Linux run scenarios.sh instead."; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
SHIELD="$WORK/agentjail-shield"
trap 'rm -rf "$WORK"' EXIT

cd "$REPO_ROOT" || exit 1
echo "building agentjail-shield (darwin)..."
go build -o "$SHIELD" ./cmd/agentjail-shield || { echo "build failed — that is finding #1"; exit 1; }

# ============================================================ 1
group "1 — it builds and the unit suite passes on darwin"

go build ./... >/dev/null 2>&1 \
  && ok "1a  go build ./... on darwin" \
  || bad "1a  go build ./... on darwin" "run it directly for the error"

# This is the ONLY way AGE-221's darwin code gets exercised today: the bundle
# test calls systemRootsPEM(), which reads darwinRootPaths. Those paths were
# written on a Linux box and have never been observed on real hardware.
if go test ./internal/shieldapp/ -run 'TestWriteCABundle|TestTunnelCAEnv' -v 2>&1 | tee "$WORK/ca.log" | grep -q "^--- PASS: TestWriteCABundleContainsSystemRootsAndSessionCA"; then
  ok "1b  AGE-221: systemRootsPEM() finds a real macOS trust bundle and the CA bundle builds"
elif grep -q "SKIP.*no system trust store readable" "$WORK/ca.log"; then
  bad "1b  AGE-221: systemRootsPEM() finds a macOS trust bundle" \
      "SKIPPED — none of darwinRootPaths exist on this Mac. That is the finding: fix darwinRootPaths in internal/shieldapp/tunnel_ca_roots_darwin.go"
else
  bad "1b  AGE-221: CA bundle builds on darwin" "see $WORK/ca.log"
fi

go test ./internal/redact/ ./internal/netpolicy/ ./agentpolicy/config/ >/dev/null 2>&1 \
  && ok "1c  AGE-232 (redaction), AGE-227 (template validation), tunnel_mitm merge — all OS-agnostic, pass here" \
  || bad "1c  OS-agnostic unit suites" "go test ./internal/redact/ ./internal/netpolicy/ ./agentpolicy/config/"

# ============================================================ 2
group "2 — the sbpl profile (ADR 0092 D3 invariant)"

"$SHIELD" --profile-print -- /bin/echo hi > "$WORK/profile.sbpl" 2>&1
if [ -s "$WORK/profile.sbpl" ]; then
  # macOS is denylist-based: (allow default) + specific denies. The whole
  # ~/.agentjail subtree must be read-denied, and NOTHING may re-allow it
  # later — last match wins in sbpl.
  if grep -q "agentjail" "$WORK/profile.sbpl"; then
    DENY_LINE="$(grep -n "deny file-read" -A 12 "$WORK/profile.sbpl" | grep -n "\.agentjail" | head -1 | cut -d: -f1)"
    ALLOW_AFTER="$(awk '/\.agentjail/{found=NR} /allow file-read/{if(found && NR>found) print NR}' "$WORK/profile.sbpl" | head -1)"
    if [ -n "${DENY_LINE:-}" ]; then
      ok "2a  the profile read-denies ~/.agentjail (network.db is covered by the subtree deny)"
    else
      bad "2a  the profile read-denies ~/.agentjail" "no deny found — network.db would be agent-readable on macOS too"
    fi
    note "2b  eyeball $WORK/profile.sbpl: no 'allow file-read*' covering ~/.agentjail may appear AFTER the deny — last match wins"
  else
    bad "2a  the profile mentions ~/.agentjail" "grep found nothing — check sensitiveReadPaths"
  fi
else
  skip "2a  sbpl profile checks" "--profile-print produced nothing"
fi

# ============================================================ 3
group "3 — the two claims I made about macOS from Linux, which need a Mac"

# CLAIM A: the agent CANNOT read network.db on macOS (sensitiveReadPaths denies
# the whole ~/.agentjail subtree). On Linux it CAN — that is AGE-232/ADR 0092 D3.
if [ -e "$HOME/.agentjail/network.db" ]; then
  OUT="$("$SHIELD" -- /bin/bash -c 'head -c 4 ~/.agentjail/network.db >/dev/null 2>&1 && echo READABLE || echo denied' 2>&1 | tail -1)"
  if grep -q "denied" <<<"$OUT"; then
    ok "3a  CLAIM CONFIRMED: the shielded agent cannot read network.db on macOS (Linux can — that is the gap ADR 0092 D3 closes)"
  else
    bad "3a  the shielded agent cannot read network.db on macOS" \
        "it CAN ($OUT). My reading of sensitiveReadPaths was wrong, and ADR 0092's 'Linux-only exposure' claim needs correcting."
  fi
else
  skip "3a  network.db read denial" "no ~/.agentjail/network.db yet — run any agentjail session first"
fi

# CLAIM B: git works in a worktree under the shield on macOS, because macOS is
# denylist-based ((allow default)). On Linux it is broken — AGE-241.
WT="$WORK/wtprobe"
mkdir -p "$WT/main" && ( cd "$WT/main" && git init -q && git -c user.name=t -c user.email=t@t commit -q --allow-empty -m init && git worktree add -q ../wt ) 2>/dev/null
if [ -d "$WT/wt" ]; then
  OUT="$(cd "$WT/wt" && "$SHIELD" -- /bin/bash -c 'git rev-parse --is-inside-work-tree 2>&1 | head -1' 2>&1 | tail -1)"
  if grep -q "^true" <<<"$OUT"; then
    ok "3b  CLAIM CONFIRMED: git works in a worktree under the shield on macOS (AGE-241 is Linux-only)"
  else
    bad "3b  git works in a worktree on macOS" \
        "it does NOT ($OUT) — then AGE-241 is NOT Linux-only and its priority goes up"
  fi
else
  skip "3b  worktree git" "could not create a probe worktree"
fi

# ============================================================ 4
group "4 — approved extension and strict tunnel matrix"

SMOKE_RESULT="$WORK/darwin-tunnel-smoke.json"
if PATH="$WORK:$PATH" TUNNEL_SMOKE_RESULT="$SMOKE_RESULT" \
    bash "$REPO_ROOT/test/tunnel-e2e/smoke_darwin.sh" --strict; then
  ok "4a  strict Darwin tunnel smoke executed with no all-SKIP result"
else
  bad "4a  strict Darwin tunnel smoke" \
      "requires golden-macos-mitm with the extension [activated enabled]; see the strict smoke output above"
fi
[ -s "$SMOKE_RESULT" ] \
  && note "4b  structured result: $(cat "$SMOKE_RESULT")" \
  || bad "4b  strict smoke writes a structured result" "$SMOKE_RESULT missing"

group "Summary"
printf "  PASS=%d  FAIL=%d  SKIP=%d  INFO=%d\n" "$PASS" "$FAIL" "$SKIP" "$INFO"
echo
echo "  The strict smoke covers allowed HTTPS, named host/path denies, the"
echo "  port-80 raw protocol path, no-proxy bypass resistance, and evidence."
[ "$FAIL" -gt 0 ] && exit 1
exit 0
