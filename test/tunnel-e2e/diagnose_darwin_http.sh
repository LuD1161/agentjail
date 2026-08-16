#!/usr/bin/env bash
# Compare HTTPS and cleartext HTTP in one registered Darwin tunnel process.
set -euo pipefail

shield="${AGENTJAIL_SHIELD_BIN:?AGENTJAIL_SHIELD_BIN is required}"
work="$(mktemp -d /tmp/agentjail-http-diagnose.XXXXXX)"
case "$work" in /tmp/agentjail-http-diagnose.*) ;; *) exit 2 ;; esac
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/packs"
cat >"$work/packs/deny.yaml" <<'EOF'
id: https-host-control
info:
  name: HTTPS control
  severity: high
match:
  host: [example.com]
action: deny
reason: "bounded HTTPS control"
---
id: raw-http-control
info:
  name: raw HTTP control
  severity: high
match:
  protocol: [http]
action: deny
reason: "bounded raw HTTP control"
EOF

set +e
output="$(AGENTJAIL_NETPACKS_DIR="$work/packs" "$shield" --verbose --tunnel -- bash -c '
    curl -sS -o /dev/null -w "HTTPS_EXAMPLE:%{http_code}\n" --max-time 15 https://example.com/ || true
    curl -sS -o /dev/null -w "HTTP_EXAMPLE:%{http_code}\n" --max-time 15 http://example.com/ || true
    curl -sS -o /dev/null -w "HTTP_CLOUDFLARE:%{http_code}\n" --max-time 15 http://www.cloudflare.com/ || true
' 2>&1)"
rc=$?
set -e
printf 'child_rc=%d\n' "$rc"
printf '%s\n' "$output" | grep -E 'HTTPS_EXAMPLE:|HTTP_EXAMPLE:|HTTP_CLOUDFLARE:' || true
printf '%s\n' "$output" \
    | grep -E 'loaded policy templates|dst_port|protocol=|connection (allowed|denied)|no VIP mapping' \
    | sed 's/^/gateway: /' \
    || true
