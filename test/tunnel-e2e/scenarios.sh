#!/usr/bin/env bash
# Tunnel end-to-end scenario matrix.
#
# Exercises the tunnel the way a user meets it: a real agent, real TLS, real
# policy templates — not unit-test doubles. Runs the same list on Linux and
# macOS so the two platforms are compared on identical scenarios (ADR 0034:
# drift is a bug, and an untested platform is where drift hides).
#
# Usage:  test/tunnel-e2e/scenarios.sh [--quick]
#           --quick   skip the slow agent scenarios (A10, A12)
#
# Exit: 0 if no scenario FAILs. XFAIL (known-broken, ticketed) does not fail
# the run; it is reported so a silent fix is noticed too.

set -uo pipefail

QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
SHIELD="$WORK/agentjail-shield"
PACKS="$WORK/netpacks"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0; SKIP=0; XFAIL=0; XPASS=0

ok()    { printf "  \033[32mPASS\033[0m  %s\n" "$1"; PASS=$((PASS+1)); }
bad()   { printf "  \033[31mFAIL\033[0m  %s\n     %s\n" "$1" "${2:-}"; FAIL=$((FAIL+1)); }
skip()  { printf "  \033[33mSKIP\033[0m  %s (%s)\n" "$1" "${2:-}"; SKIP=$((SKIP+1)); }
xfail() { printf "  \033[35mXFAIL\033[0m %s (known: %s)\n" "$1" "${2:-}"; XFAIL=$((XFAIL+1)); }
xpass() { printf "  \033[36mXPASS\033[0m %s — expected to fail (%s) but PASSED; ticket may be fixed\n" "$1" "${2:-}"; XPASS=$((XPASS+1)); }
group() { printf "\n\033[1m%s\033[0m\n" "$1"; }

# run_tunnel <extra-shield-flags...> -- <script>
# Runs a shell script inside a tunneled shield session; echoes combined output.
run_tunnel() {
  local flags=() ; while [ "$1" != "--" ]; do flags+=("$1"); shift; done; shift
  AGENTJAIL_NETPACKS_DIR="$PACKS" timeout 90 "$SHIELD" "${flags[@]}" -- bash -c "$1" 2>&1
}

# ---------------------------------------------------------------- setup

echo "building agentjail-shield..."
( cd "$REPO_ROOT" && go build -o "$SHIELD" ./cmd/agentjail-shield ) || { echo "build failed"; exit 1; }

mkdir -p "$PACKS"
cat > "$PACKS/deny-host.yaml" <<'EOF'
id: e2e-deny-host
info:
  name: deny example.com outright
  severity: high
match:
  host:
    - example.com
action: deny
reason: "e2e: example.com denied by host rule"
EOF
# NOTE: path globs use filepath.Match, whose '*' does NOT cross '/'. So
# "/repos/*" does not match "/repos/torvalds/linux" — use a re: pattern to
# cover a subtree. See AGE-227.
cat > "$PACKS/deny-path.yaml" <<'EOF'
id: e2e-deny-path
info:
  name: deny a path subtree on an otherwise-allowed host
  severity: high
match:
  host:
    - api.github.com
  path:
    - "re:^/repos/"
action: deny
reason: "e2e: /repos/ subtree denied by path rule"
EOF
# The single-segment glob a user would plausibly write. Documents the semantics
# rather than asserting the footgun is fine — see AGE-227.
cat > "$PACKS/deny-glob.yaml" <<'EOF'
id: e2e-deny-glob
info:
  name: single-segment path glob
  severity: high
match:
  host:
    - api.github.com
  path:
    - "/orgs/*"
action: deny
reason: "e2e: /orgs/<one-segment> denied by glob"
EOF

# ================================================================ GROUP A
group "A — tunnel + TLS interception (the default posture, ADR 0077)"

OUT="$(run_tunnel --tunnel -- '
  curl -s -o /dev/null -w "ALLOWED:%{http_code}\n"  --max-time 15 https://www.cloudflare.com/
  curl -s -o /dev/null -w "DENIED:%{http_code}\n"   --max-time 15 https://example.com/
  curl -s -o /dev/null -w "PATHDENY:%{http_code}\n" --max-time 15 https://api.github.com/repos/torvalds/linux
  curl -s -o /dev/null -w "GLOBDENY:%{http_code}\n" --max-time 15 https://api.github.com/orgs/golang
  curl -s -o /dev/null -w "MULTI1:%{http_code}\n"   --max-time 15 https://www.cloudflare.com/
  curl -s -o /dev/null -w "MULTI2:%{http_code}\n"   --max-time 15 https://www.google.com/
  curl -s -o /dev/null -w "IPLIT:%{http_code}\n"    --max-time 15 https://1.1.1.1/
')"

grep -q "TLS interception ON" <<<"$OUT" \
  && ok "A1  banner reports interception ON" \
  || bad "A1  banner reports interception ON" "$(grep -i 'interception\|tunnel active' <<<"$OUT" | head -1)"

[ "$(grep -o 'ALLOWED:[0-9]*' <<<"$OUT")" = "ALLOWED:200" ] \
  && ok "A2  allowed host reachable (200)" \
  || bad "A2  allowed host reachable" "got $(grep -o 'ALLOWED:[0-9]*' <<<"$OUT")"

if [ "$(grep -o 'DENIED:[0-9]*' <<<"$OUT")" = "DENIED:403" ] && grep -q "template=e2e-deny-host" <<<"$OUT"; then
  ok "A3  host deny rule enforced (403 by e2e-deny-host)"
else
  bad "A3  host deny rule enforced" "got $(grep -o 'DENIED:[0-9]*' <<<"$OUT"); template fired: $(grep -c 'template=e2e-deny-host' <<<"$OUT")"
fi

# A 403 alone is not proof here: a rate-limited upstream also returns 403. The
# eval line naming our template is what distinguishes "policy denied it" from
# "the server did".
if [ "$(grep -o 'PATHDENY:[0-9]*' <<<"$OUT")" = "PATHDENY:403" ] && grep -q "template=e2e-deny-path" <<<"$OUT"; then
  ok "A4  path-subtree deny on an allowed host (403 by e2e-deny-path) — L7 depth"
else
  bad "A4  path-subtree deny on an allowed host" "got $(grep -o 'PATHDENY:[0-9]*' <<<"$OUT"); template fired: $(grep -c 'template=e2e-deny-path' <<<"$OUT")"
fi

if [ "$(grep -o 'GLOBDENY:[0-9]*' <<<"$OUT")" = "GLOBDENY:403" ] && grep -q "template=e2e-deny-glob" <<<"$OUT"; then
  ok "A4b single-segment path glob matches (403 by e2e-deny-glob)"
else
  bad "A4b single-segment path glob matches" "got $(grep -o 'GLOBDENY:[0-9]*' <<<"$OUT"); template fired: $(grep -c 'template=e2e-deny-glob' <<<"$OUT")"
fi

if [ "$(grep -o 'MULTI1:[0-9]*' <<<"$OUT")" = "MULTI1:200" ] && [ "$(grep -o 'MULTI2:[0-9]*' <<<"$OUT")" = "MULTI2:200" ]; then
  ok "A5  several distinct hosts all reachable (AGE-168 VIP/TUN collision regression)"
else
  bad "A5  several distinct hosts all reachable (AGE-168 regression)" "got $(grep -o 'MULTI[12]:[0-9]*' <<<"$OUT" | tr '\n' ' ')"
fi

# An IP literal needs an IP SAN on the leaf; any HTTP status proves the chain
# verified (1.1.1.1 answers with a redirect). AGE-220.
if grep -qE "IPLIT:[23][0-9][0-9]" <<<"$OUT"; then
  ok "A6  IP-literal https://1.1.1.1 verifies (AGE-220) — $(grep -o 'IPLIT:[0-9]*' <<<"$OUT")"
else
  bad "A6  IP-literal https://1.1.1.1 verifies" "got $(grep -o 'IPLIT:[0-9]*' <<<"$OUT") — leaf is missing an IP SAN"
fi

# --- interception actually decrypts: our CA must be the issuer
ISS="$(run_tunnel --tunnel -- 'curl -v -o /dev/null --max-time 15 https://www.cloudflare.com/ 2>&1 | grep -i "issuer:" | head -1')"
grep -qi "agentjail" <<<"$ISS" \
  && ok "A7  upstream cert is re-signed by the session CA (proves decryption)" \
  || bad "A7  upstream cert re-signed by session CA" "issuer line: ${ISS:-<none>}"

# --- runtimes that ignore the namespace trust store (AGE-113)
NODEOUT="$(run_tunnel --tunnel -- 'node -e "
  fetch(\"https://www.cloudflare.com/\").then(r=>{console.log(\"NODE:\"+r.status)}).catch(e=>{console.log(\"NODE:ERR \"+e.message)})
" 2>&1 | tail -2')"
grep -q "NODE:200" <<<"$NODEOUT" \
  && ok "A8  Node.js fetch under interception (AGE-113: NODE_EXTRA_CA_CERTS)" \
  || bad "A8  Node.js fetch under interception (AGE-113)" "$(grep NODE: <<<"$NODEOUT" | head -1)"

# What is under test is TLS verification, not the upstream's opinion of us: any
# HTTP status means the handshake and chain validation succeeded. Only an
# SSL/cert error is a real failure. (Cloudflare 403s python-urllib's UA, which
# would otherwise read as a broken tunnel.)
PYOUT="$(run_tunnel --tunnel -- 'python3 -c "
import urllib.request, urllib.error, ssl
try:
    r = urllib.request.urlopen(\"https://www.cloudflare.com/\", timeout=15)
    print(\"PY:TLSOK status=\"+str(r.status))
except urllib.error.HTTPError as e:
    print(\"PY:TLSOK status=\"+str(e.code)+\" (upstream refused, TLS fine)\")
except (ssl.SSLError, ssl.CertificateError) as e:
    print(\"PY:TLSFAIL \"+str(e))
except Exception as e:
    print(\"PY:ERR \"+type(e).__name__+\" \"+str(e))
" 2>&1 | tail -2')"
grep -q "PY:TLSOK" <<<"$PYOUT" \
  && ok "A9  Python urllib verifies the session CA under interception ($(grep -o 'status=[0-9]*' <<<"$PYOUT" | head -1))" \
  || bad "A9  Python urllib verifies the session CA under interception" "$(grep PY: <<<"$PYOUT" | head -1)"

# --- the CA is namespace-scoped: the HOST trust store must still reject it.
# ADR 0077 retains ADR 0076 condition 2 (host store never touched). Doubles as
# the mutation probe for A8/A9 — if this passed, those two would prove nothing.
HOSTCA="$WORK/host-ca.pem"
HOSTBUNDLE=""
for p in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
  [ -f "$p" ] && { HOSTBUNDLE="$p"; break; }
done
if [ -n "$HOSTBUNDLE" ]; then
  cp "$HOSTBUNDLE" "$HOSTCA"   # captured OUTSIDE the session
  if grep -qi "agentjail" "$HOSTCA" 2>/dev/null; then
    bad "A9b the session CA never enters the host trust store" "the HOST bundle $HOSTBUNDLE contains an agentjail CA — it must never be installed there"
  else
    SCOPED="$(run_tunnel --tunnel -- "python3 -c \"
import urllib.request, ssl
ctx = ssl.create_default_context(cafile='$HOSTCA')
try:
    urllib.request.urlopen('https://www.cloudflare.com/', timeout=15, context=ctx)
    print('SCOPED:TRUSTED')
except Exception:
    print('SCOPED:REJECTED')
\"")"
    grep -q "SCOPED:REJECTED" <<<"$SCOPED" \
      && ok "A9b the session CA is namespace-scoped — the host trust store still rejects it (ADR 0077)" \
      || bad "A9b the session CA is namespace-scoped" "a bundle with only public roots ACCEPTED our cert — either the host store was modified, or interception is not actually happening (which would make A8/A9 meaningless)"
  fi
else
  skip "A9b the session CA is namespace-scoped" "no system CA bundle found at a known path"
fi

GITOUT="$(run_tunnel --tunnel -- 'git ls-remote https://github.com/git/git HEAD >/dev/null 2>&1 && echo GIT:OK || echo GIT:FAIL')"
grep -q "GIT:OK" <<<"$GITOUT" \
  && ok "A10 git over HTTPS under interception" \
  || bad "A10 git over HTTPS under interception" "$(grep GIT: <<<"$GITOUT" | head -1)"

# --- request logging
DBOUT="$(run_tunnel --tunnel -- 'curl -s -o /dev/null --max-time 15 https://api.github.com/; echo done')"
if command -v sqlite3 >/dev/null 2>&1; then
  N="$(sqlite3 "$HOME/.agentjail/network.db" "select count(*) from network_requests where host='api.github.com';" 2>/dev/null || echo 0)"
  [ "${N:-0}" -gt 0 ] \
    && ok "A11 requests recorded to network.db (n=$N)" \
    || bad "A11 requests recorded to network.db" "count=$N"
else
  skip "A11 requests recorded to network.db" "sqlite3 not installed"
fi

# --- real coding agents through the tunnel
if [ "$QUICK" = "1" ]; then
  skip "A12 Claude Code session through the tunnel" "--quick"
  skip "A13 Codex CLI through the tunnel" "--quick"
else
  CC="$(run_tunnel --tunnel -- 'claude -p "reply with exactly: TUNNELOK" --max-turns 1 2>&1 | tail -3')"
  grep -q "TUNNELOK" <<<"$CC" \
    && ok "A12 Claude Code completes a real API call through the tunnel" \
    || bad "A12 Claude Code through the tunnel" "$(tail -2 <<<"$CC")"

  CX="$(run_tunnel --tunnel -- 'codex --version 2>&1 | tail -1')"
  grep -qE "[0-9]+\.[0-9]+" <<<"$CX" \
    && ok "A13 Codex CLI runs inside a tunneled session" \
    || bad "A13 Codex CLI inside a tunneled session" "$CX"
fi

# ================================================================ GROUP B
group "B — tunnel + --no-mitm (transparent-only; documented downgrade)"

BOUT="$(run_tunnel --tunnel --no-mitm -- '
  curl -s -o /dev/null -w "ALLOWED:%{http_code}\n" --max-time 15 https://www.cloudflare.com/
  curl -s -o /dev/null -w "DENIED:%{http_code}\n"  --max-time 15 https://example.com/
  curl -v -o /dev/null --max-time 15 https://www.cloudflare.com/ 2>&1 | grep -i "issuer:" | head -1
  echo "CAENV:${SSL_CERT_FILE:-unset}"
')"

grep -q "interception OFF" <<<"$BOUT" \
  && ok "B1  banner reports interception OFF" \
  || bad "B1  banner reports interception OFF" "$(grep -i 'interception' <<<"$BOUT" | head -1)"

[ "$(grep -o 'ALLOWED:[0-9]*' <<<"$BOUT")" = "ALLOWED:200" ] \
  && ok "B2  traffic still flows without interception" \
  || bad "B2  traffic still flows without interception" "got $(grep -o 'ALLOWED:[0-9]*' <<<"$BOUT")"

# ADR 0077: without MITM the DSL cannot reach HTTP(S) — 200 is CORRECT here.
[ "$(grep -o 'DENIED:[0-9]*' <<<"$BOUT")" = "DENIED:200" ] \
  && ok "B3  HTTP(S) policy is inert without interception (200) — ADR 0077's documented cost" \
  || bad "B3  HTTP(S) policy inert without interception" "expected 200 per ADR 0077, got $(grep -o 'DENIED:[0-9]*' <<<"$BOUT"); if 403, the ADR is now wrong"

if grep -qi "issuer:" <<<"$BOUT"; then
  grep -i "issuer:" <<<"$BOUT" | grep -qi "agentjail" \
    && bad "B4  upstream cert is the REAL chain, not ours" "we are still decrypting under --no-mitm" \
    || ok "B4  upstream cert is the real chain, not the session CA"
else
  skip "B4  upstream cert is the real chain" "no issuer line captured"
fi

grep -q "CAENV:unset" <<<"$BOUT" \
  && ok "B5  no CA trust env injected when not intercepting" \
  || bad "B5  no CA trust env injected when not intercepting" "$(grep CAENV: <<<"$BOUT")"

# ================================================================ GROUP C
group "C — posture resolution (flags + config tri-state, ADR 0077 D2/D3)"

POLICY="$WORK/policy-mitm-off.yaml"
cat > "$POLICY" <<'EOF'
network:
  tunnel_mitm: false
EOF

C1="$(AGENTJAIL_NETPACKS_DIR="$PACKS" timeout 60 "$SHIELD" --policy="$POLICY" --tunnel -- true 2>&1)"
grep -q "interception OFF" <<<"$C1" \
  && ok "C1  network.tunnel_mitm: false turns interception off" \
  || bad "C1  network.tunnel_mitm: false turns interception off" "$(grep -i interception <<<"$C1" | head -1)"

C2="$(AGENTJAIL_NETPACKS_DIR="$PACKS" timeout 60 "$SHIELD" --policy="$POLICY" --tunnel --mitm -- true 2>&1)"
grep -q "TLS interception ON" <<<"$C2" \
  && ok "C2  --mitm overrides a config opt-out" \
  || bad "C2  --mitm overrides a config opt-out" "$(grep -i interception <<<"$C2" | head -1)"

C3="$(AGENTJAIL_NETPACKS_DIR="$PACKS" timeout 60 "$SHIELD" --tunnel --mitm --no-mitm -- true 2>&1)"
grep -q "interception OFF" <<<"$C3" \
  && ok "C3  --no-mitm beats --mitm (off wins ties)" \
  || bad "C3  --no-mitm beats --mitm" "$(grep -i interception <<<"$C3" | head -1)"

C4="$(AGENTJAIL_NETPACKS_DIR="$PACKS" timeout 60 "$SHIELD" --tunnel -- true 2>&1)"
grep -q "TLS interception ON" <<<"$C4" \
  && ok "C4  default (no flags, no config) intercepts" \
  || bad "C4  default intercepts" "$(grep -i interception <<<"$C4" | head -1)"

# ================================================================ GROUP D
group "D — no tunnel (baseline: --tunnel must be opt-in)"

D1="$(timeout 60 "$SHIELD" -- bash -c 'curl -s -o /dev/null -w "BASE:%{http_code}\n" --max-time 15 https://www.cloudflare.com/' 2>&1)"
[ "$(grep -o 'BASE:[0-9]*' <<<"$D1")" = "BASE:200" ] \
  && ok "D1  traffic flows with no tunnel" \
  || bad "D1  traffic flows with no tunnel" "got $(grep -o 'BASE:[0-9]*' <<<"$D1")"

grep -qi "tunnel active\|interception ON" <<<"$D1" \
  && bad "D2  no tunnel/interception claimed without --tunnel" "banner claims a tunnel that was not requested" \
  || ok "D2  no tunnel or interception claimed without --tunnel"

# ================================================================ GROUP E
group "E — help / discoverability"

H="$("$SHIELD" --help 2>&1)"
MISSING=""
for f in --tunnel --mitm --no-mitm --netproxy --policy --audit-json; do
  grep -q -- "$f" <<<"$H" || MISSING="$MISSING $f"
done
[ -z "$MISSING" ] \
  && ok "E1  --help documents every shipped flag" \
  || bad "E1  --help documents every shipped flag" "missing:$MISSING"

grep -qi "decrypt" <<<"$H" \
  && ok "E2  --help states that the tunnel decrypts HTTPS by default (ADR 0077 D4)" \
  || bad "E2  --help states the decryption default" "a user cannot learn the posture from --help"

# ================================================================ GROUP F
group "F — fail-open floor (ADR 0079) + honest posture (ADR 0077 D5/D6)"

FAKEHOME="$WORK/fakehome"
mkdir -p "$FAKEHOME/.agentjail/network.db"   # a directory: unopenable as a DB
F1="$(HOME="$FAKEHOME" AGENTJAIL_NETPACKS_DIR="$PACKS" timeout 60 "$SHIELD" --tunnel -- \
      bash -c 'curl -s -o /dev/null -w "FAILOPEN:%{http_code}\n" --max-time 15 https://www.cloudflare.com/' 2>&1)"

[ "$(grep -o 'FAILOPEN:[0-9]*' <<<"$F1")" = "FAILOPEN:200" ] \
  && ok "F1  unopenable network.db still lets traffic through (fail-open floor)" \
  || bad "F1  fail-open when network.db cannot open" "got $(grep -o 'FAILOPEN:[0-9]*' <<<"$F1")"

grep -q "interception ON" <<<"$F1" \
  && bad "F2  posture reported is the one ACHIEVED (ADR 0077 D6)" "claims ON while relaying opaque — the D4 misrepresentation" \
  || ok "F2  posture reported is the one achieved, not the one requested (ADR 0077 D6)"

# ================================================================ GROUP G
group "G — chaos: a component of the stack is broken or absent"

# --- G1/G2: a template the author got wrong. The cardinal sin is a policy that
# silently does nothing while the user believes it is loaded.
BADPACKS="$WORK/packs-bad"; mkdir -p "$BADPACKS"
cat > "$BADPACKS/wrong-shape.yaml" <<'EOF'
id: chaos-wrong-shape
info:
  name: Nuclei-style shape — no top-level match/action
  severity: high
http:
  - host:
      - example.com
    action: deny
EOF
G1="$(AGENTJAIL_NETPACKS_DIR="$BADPACKS" timeout 60 "$SHIELD" --tunnel -- \
      bash -c 'curl -s -o /dev/null -w "MALFORMED:%{http_code}\n" --max-time 15 https://example.com/' 2>&1)"

if grep -qiE "refusing to launch|invalid network policy template" <<<"$G1" && ! grep -q "MALFORMED:" <<<"$G1"; then
  ok "G1  a malformed template is rejected loudly and the agent does not launch (AGE-227)"
else
  bad "G1  a malformed template is rejected loudly" "it loaded silently and the agent ran: $(grep -o 'MALFORMED:[0-9]*' <<<"$G1")"
fi

BADACT="$WORK/packs-badaction"; mkdir -p "$BADACT"
cat > "$BADACT/bad-action.yaml" <<'EOF'
id: chaos-bad-action
info:
  name: typo in the action value
  severity: high
match:
  host:
    - example.com
action: DENY_ALL
EOF
G2="$(AGENTJAIL_NETPACKS_DIR="$BADACT" timeout 60 "$SHIELD" --tunnel -- \
      bash -c 'curl -s -o /dev/null -w "BADACTION:%{http_code}\n" --max-time 15 https://example.com/' 2>&1)"
if grep -qiE "refusing to launch|expected one of allow, ask, deny" <<<"$G2" && ! grep -q "BADACTION:" <<<"$G2"; then
  ok "G2  an unknown action value is rejected loudly and the agent does not launch (AGE-227)"
else
  bad "G2  an unknown action value is rejected loudly" "it loaded silently and the agent ran: $(grep -o 'BADACTION:[0-9]*' <<<"$G2")"
fi

# --- G3: most-restrictive wins, so a weaker rule earlier in the load order
# cannot shadow a deny. This is the property that bounded AGE-227's blast
# radius; it must hold on its own, so it is guarded with two VALID templates
# (a malformed one is now rejected outright — G1).
SHADOW="$WORK/packs-shadow"; mkdir -p "$SHADOW"
cat > "$SHADOW/aa-allow.yaml" <<'EOF'
id: chaos-allow-first
info:
  name: a permissive rule loaded before the deny
  severity: info
match:
  host:
    - example.com
action: allow
EOF
cat > "$SHADOW/zz-valid-deny.yaml" <<'EOF'
id: chaos-valid-deny
info:
  name: the rule the user actually wrote
  severity: high
match:
  host:
    - example.com
action: deny
reason: "must still win next to a permissive rule"
EOF
G3="$(AGENTJAIL_NETPACKS_DIR="$SHADOW" timeout 60 "$SHIELD" --tunnel -- \
      bash -c 'curl -s -o /dev/null -w "SHADOW:%{http_code}\n" --max-time 15 https://example.com/' 2>&1)"
[ "$(grep -o 'SHADOW:[0-9]*' <<<"$G3")" = "SHADOW:403" ] \
  && ok "G3  a permissive rule does not shadow a valid deny (most-restrictive wins)" \
  || bad "G3  a permissive rule must not shadow a valid deny" "got $(grep -o 'SHADOW:[0-9]*' <<<"$G3") — an allow rule loaded first disabled the deny"

# --- G4: a malformed policy.yaml must fail CLOSED (never launch unprotected)
BADPOL="$WORK/policy-broken.yaml"
printf 'network:\n  tunnel_mitm: "not-a-bool"\n  this_field: [unclosed\n' > "$BADPOL"
G4="$(timeout 60 "$SHIELD" --policy="$BADPOL" --tunnel -- bash -c 'echo AGENT_RAN' 2>&1)"
if grep -q "AGENT_RAN" <<<"$G4"; then
  bad "G4  malformed policy.yaml refuses to launch the agent" "the agent RAN with an unparseable policy — fail-open on the policy path"
else
  grep -qi "refusing\|could not be loaded" <<<"$G4" \
    && ok "G4  malformed policy.yaml refuses to launch the agent (fails closed)" \
    || bad "G4  malformed policy.yaml refuses to launch" "agent did not run, but no clear reason given: $(head -1 <<<"$G4")"
fi

# --- G5: a configured packs dir that is not there. Refusing is deliberate:
# templates were asked for and none can load, so the session would run with no
# HTTP(S) policy while the user believed otherwise. (Before AGE-227 this failed
# deeper in and dropped the whole tunnel to netproxy without saying so.)
G5="$(AGENTJAIL_NETPACKS_DIR="$WORK/does-not-exist" timeout 60 "$SHIELD" --tunnel -- \
      bash -c 'curl -s -o /dev/null -w "NOPACKS:%{http_code}\n" --max-time 15 https://www.cloudflare.com/' 2>&1)"
if grep -q "cannot be read" <<<"$G5" && ! grep -q "NOPACKS:" <<<"$G5"; then
  ok "G5  a configured-but-absent netpacks dir refuses to launch, and says which dir"
else
  bad "G5  a configured-but-absent netpacks dir refuses to launch" "the agent ran with no policy: $(grep -o 'NOPACKS:[0-9]*' <<<"$G5")"
fi

# --- G5b: nothing configured at all is the genuine observe-only case: no
# templates asked for, so no policy expected, and traffic must flow.
NOHOME="$WORK/nohome"; mkdir -p "$NOHOME"
G5b="$(env -u AGENTJAIL_NETPACKS_DIR HOME="$NOHOME" timeout 60 "$SHIELD" --tunnel -- \
      bash -c 'curl -s -o /dev/null -w "NOCONF:%{http_code}\n" --max-time 15 https://www.cloudflare.com/' 2>&1)"
[ "$(grep -o 'NOCONF:[0-9]*' <<<"$G5b")" = "NOCONF:200" ] \
  && ok "G5b no netpacks configured at all degrades to observe-only, traffic flows" \
  || bad "G5b no netpacks configured degrades to observe-only" "got $(grep -o 'NOCONF:[0-9]*' <<<"$G5b")"

EMPTY="$WORK/packs-empty"; mkdir -p "$EMPTY"
G6="$(AGENTJAIL_NETPACKS_DIR="$EMPTY" timeout 60 "$SHIELD" --tunnel -- \
      bash -c 'curl -s -o /dev/null -w "EMPTYPACKS:%{http_code}\n" --max-time 15 https://www.cloudflare.com/' 2>&1)"
[ "$(grep -o 'EMPTYPACKS:[0-9]*' <<<"$G6")" = "EMPTYPACKS:200" ] \
  && ok "G6  an empty netpacks dir degrades to observe-only, traffic flows" \
  || bad "G6  empty netpacks dir degrades to observe-only" "got $(grep -o 'EMPTYPACKS:[0-9]*' <<<"$G6")"

# --- G7: concurrency — the symptom originally reported as AGE-168
G7="$(run_tunnel --tunnel -- '
  for i in $(seq 1 12); do
    curl -s -o /dev/null -w "C:%{http_code}\n" --max-time 20 https://www.cloudflare.com/ &
  done
  wait
')"
NOK="$(grep -c 'C:200' <<<"$G7")"
[ "${NOK:-0}" -eq 12 ] \
  && ok "G7  12 concurrent connections all succeed (AGE-168 original symptom)" \
  || bad "G7  concurrent connections all succeed" "only $NOK/12 returned 200: $(grep -o 'C:[0-9]*' <<<"$G7" | sort | uniq -c | tr '\n' ' ')"

# --- G8: a host that does not resolve must fail fast, not hang
G8="$(run_tunnel --tunnel -- '
  s=$(date +%s)
  curl -s -o /dev/null -w "NX:%{http_code}\n" --max-time 20 https://this-host-does-not-exist-agentjail-e2e.invalid/
  echo "ELAPSED:$(( $(date +%s) - s ))"
')"
EL="$(grep -o 'ELAPSED:[0-9]*' <<<"$G8" | cut -d: -f2)"
if [ "${EL:-99}" -lt 20 ]; then
  ok "G8  an unresolvable host fails fast (${EL}s), no hang"
else
  bad "G8  unresolvable host fails fast" "took ${EL}s — hit the timeout, suggesting a hang"
fi

# --- G9: the agent's exit code must survive the tunnel
timeout 60 "$SHIELD" --tunnel -- bash -c 'exit 42' >/dev/null 2>&1
RC=$?
[ "$RC" -eq 42 ] \
  && ok "G9  the agent's exit code propagates through a tunneled session" \
  || bad "G9  agent exit code propagates" "expected 42, got $RC — a CI script would misread the result"

# --- G10: no orphaned namespace holders after the session
BEFORE="$(pgrep -f "agentjail-shield" 2>/dev/null | wc -l | tr -d ' ')"
timeout 60 "$SHIELD" --tunnel -- true >/dev/null 2>&1
sleep 1
AFTER="$(pgrep -f "agentjail-shield" 2>/dev/null | wc -l | tr -d ' ')"
[ "${AFTER:-0}" -le "${BEFORE:-0}" ] \
  && ok "G10 no orphaned shield/holder process after the session (before=$BEFORE after=$AFTER)" \
  || bad "G10 no orphaned process after the session" "before=$BEFORE after=$AFTER — the namespace holder leaked"

# --- G11: the CA private key must never be on disk (ADR 0077, retains 0076 cond 3)
timeout 60 "$SHIELD" --tunnel -- true >/dev/null 2>&1
LEAK="$(find /tmp -maxdepth 3 -name '*.pem' -newermt '-2 minutes' 2>/dev/null | head -5)"
KEYLEAK=""
for f in $LEAK; do grep -ql "PRIVATE KEY" "$f" 2>/dev/null && KEYLEAK="$KEYLEAK $f"; done
[ -z "$KEYLEAK" ] \
  && ok "G11 no CA private key left on disk after the session" \
  || bad "G11 no CA private key on disk" "found:$KEYLEAK — ADR 0077 requires the key stay in memory only"

# --- G12/G13: large uploads. Two probes on purpose: the body-scan limit is the
# obvious suspect and is NOT the cause — Expect: 100-continue is (AGE-226).
G12="$(run_tunnel --tunnel -- '
  head -c 2000000 /dev/zero | tr "\0" "a" > /tmp/big.txt
  s=$(date +%s)
  curl -s -o /dev/null -w "NOEXPECT:%{http_code}\n" --max-time 25 -H "Expect:" -X POST --data-binary @/tmp/big.txt https://www.cloudflare.com/
  echo "PLAIN_ELAPSED:$(( $(date +%s) - s ))"
  s=$(date +%s)
  curl -s -o /dev/null -w "EXPECT:%{http_code}\n" --max-time 25 -X POST --data-binary @/tmp/big.txt https://www.cloudflare.com/
  echo "CONT_ELAPSED:$(( $(date +%s) - s ))"
')"

NE="$(grep -o 'PLAIN_ELAPSED:[0-9]*' <<<"$G12" | cut -d: -f2)"
if grep -qE "NOEXPECT:[1-9][0-9][0-9]" <<<"$G12" && [ "${NE:-99}" -lt 25 ]; then
  ok "G12 a 2MB body (> the 1MiB scan limit) forwards fine without Expect (${NE}s) — the limit is not the problem"
else
  bad "G12 large body forwards without Expect" "got $(grep -o 'NOEXPECT:[0-9]*' <<<"$G12"), elapsed=${NE}s — a real body-size regression"
fi

EE="$(grep -o 'CONT_ELAPSED:[0-9]*' <<<"$G12" | cut -d: -f2)"
if grep -qE "EXPECT:[1-9][0-9][0-9]" <<<"$G12" && [ "${EE:-99}" -lt 25 ]; then
  ok "G13 POST with Expect: 100-continue completes (${EE}s) — AGE-226"
else
  bad "G13 POST with Expect: 100-continue completes" "got $(grep -o 'EXPECT:[0-9]*' <<<"$G12"), elapsed=${EE}s — the client is waiting for an interim 100 that never comes"
fi

# ================================================================ summary
group "Summary"
printf "  PASS=%d  FAIL=%d  SKIP=%d  XFAIL=%d  XPASS=%d\n" "$PASS" "$FAIL" "$SKIP" "$XFAIL" "$XPASS"
[ "$XPASS" -gt 0 ] && printf "  note: an XPASS means a known-broken scenario now works — confirm and close its ticket.\n"
[ "$FAIL" -gt 0 ] && exit 1
exit 0
