#!/usr/bin/env bash
# Baseline: a real coding-agent task through the tunnel.
#
# Runs Claude Code inside a tunneled session on an ordinary task (build a small
# web app, commit it) and reports what the tunnel captured. This is the fixture
# the curl-based matrix cannot be: a real agent exercises cwd, git, MCP servers,
# npm, vendor telemetry and a multi-turn model loop, and every one of those has
# hidden a bug that curl could not.
#
# What it found on first run:
#   AGE-231  --tunnel dropped the agent into "/" -- Claude Code refused the task
#            outright, because there was nowhere to write. Every curl scenario
#            passed; curl does not care where it stands.
#   AGE-232  a vendor telemetry header (Dd-Api-Key) reached network.db in the
#            clear. curl never sends one.
#
# Usage:  test/tunnel-e2e/baseline-agent-task.sh [workdir]
# Needs:  claude logged in, sqlite3, git.

set -uo pipefail

WORK="${1:-$(mktemp -d)}/baseline-webapp"
DB="$HOME/.agentjail/network.db"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SHIELD="$(mktemp -d)/agentjail-shield"

command -v claude >/dev/null || { echo "SKIP: claude not installed"; exit 0; }
command -v sqlite3 >/dev/null || { echo "SKIP: sqlite3 not installed"; exit 0; }

echo "building agentjail-shield..."
( cd "$REPO_ROOT" && go build -o "$SHIELD" ./cmd/agentjail-shield ) || { echo "build failed"; exit 1; }

rm -rf "$WORK"; mkdir -p "$WORK"; cd "$WORK" || exit 1
git init -q

BEFORE="$(sqlite3 "$DB" 'select coalesce(max(id),0) from network_requests;' 2>/dev/null || echo 0)"
echo "workspace: $WORK"
echo "network.db watermark before: $BEFORE"
echo

TASK="Create a small single-page todo list web app in the current directory: index.html with inline CSS and vanilla JS (no frameworks, no CDN links), plus a short README.md. Keep it under 100 lines total. Then stage and commit them with git. Report what you created."

echo "=== running the agent through the tunnel ==="
timeout 900 "$SHIELD" --tunnel -- \
  claude -p "$TASK" \
  --allowedTools "Write" "Edit" "Bash" "Read" \
  --output-format text \
  2>&1 | grep -vE "landlock_add_rule|skip /home|denying read" | tail -6

echo
echo "=== artifact ==="
ls -1 "$WORK" 2>/dev/null | sed 's/^/  /'
git -C "$WORK" log --oneline -1 2>/dev/null | sed 's/^/  commit: /' || echo "  (no commit)"

echo
echo "=== what the tunnel captured ==="
sqlite3 -header -column "$DB" "
select host, count(*) as reqs, sum(request_size) as req_bytes, sum(response_size) as resp_bytes
from network_requests where id > $BEFORE group by host order by reqs desc;" 2>/dev/null | sed 's/^/  /'

echo
echo "  model turns (the prompt -> tool-call loop):"
sqlite3 -column "$DB" "
select '    '||method||' '||substr(path,1,24)||'  req='||request_size||'B  resp='||response_size||'B  '||elapsed_ms||'ms'
from network_requests where id > $BEFORE and path like '%messages%' order by id;" 2>/dev/null

echo
echo "=== credential hygiene: nothing secret may reach the DB in the clear ==="
# The capture is only publishable if this stays empty. AGE-232 was exactly this.
LEAKS="$(sqlite3 "$DB" "select request_headers||' '||coalesce(response_headers,'') from network_requests where id > $BEFORE;" 2>/dev/null \
  | grep -oiE '"[a-z0-9_-]*(key|token|auth|secret|cookie|session)[a-z0-9_-]*":"[^"]{0,80}"' \
  | grep -viE '"\[REDACTED\]"' | grep -viE 'session-id|session_id' | sort -u)"
if [ -z "$LEAKS" ]; then
  echo "  OK — every credential-shaped header is [REDACTED]"
else
  echo "  LEAK — these reached the DB unredacted:"
  sed 's/^/    /' <<<"$LEAKS"
  echo "  Add the key pattern to internal/redact (AGE-232) before publishing any capture."
  exit 1
fi

echo
echo "=== NOTE: what this baseline does and does not contain ==="
cat <<'EOF'
  Captured:     per-request metadata — host, method, path, status, byte counts,
                timing, redacted headers, and the policy verdict.
  NOT captured: request/response BODIES. So the model turns appear as sized
                POSTs to /v1/messages, not as prompt or tool-call text.
                Bodies are non-persisted by design — network.db holds metadata
                plus a verdict, not a transcript (ADR 0077, retaining ADR 0076).
                Capturing prompt content would be a deliberate reversal of that,
                and needs an ADR, not a flag.
EOF
