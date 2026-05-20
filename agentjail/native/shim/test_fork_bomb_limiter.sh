#!/usr/bin/env bash
# Containment fixture for the shim's inherited RLIMIT_NPROC and
# wall-clock alarm. Keeps all work local to a temp process tree and passes only
# if the shim contains the fork storm quickly.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SHIM="${SCRIPT_DIR}/../../../bin/agentjail-shim"

if [ ! -x "$SHIM" ]; then
  echo "FAIL: shim not built at $SHIM (run 'make build' first)" >&2
  exit 1
fi

WORK="$(mktemp -d -t agentjail-shim-forkbomb.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
SHIM_DIR="$WORK/shims"
mkdir -p "$SHIM_DIR"

ln -sf "$SHIM" "$SHIM_DIR/bash"

START="$(python3 - <<'PY'
import time
print(time.time())
PY
)"

set +e
AGENTJAIL_SHIM_VERIFY=0 \
AGENTJAIL_SHIM_DIR="$SHIM_DIR" \
AGENTJAIL_SHIM_RLIMIT_NPROC=32 \
AGENTJAIL_SHIM_WALLCLOCK_SECS=2 \
PATH="$SHIM_DIR:/usr/bin:/bin:/usr/sbin:/sbin" \
"$SHIM_DIR/bash" -c 'bomb(){ bomb | bomb & }; bomb' >/dev/null 2>"$WORK/stderr.log"
RC=$?
set -e

ELAPSED="$(python3 - "$START" <<'PY'
import sys, time
start = float(sys.argv[1])
print(f"{time.time() - start:.2f}")
PY
)"

if [ "$RC" -eq 0 ]; then
  echo "FAIL: fork bomb unexpectedly exited 0" >&2
  exit 1
fi

if python3 - "$ELAPSED" <<'PY'
import sys
sys.exit(0 if float(sys.argv[1]) <= 6.0 else 1)
PY
then
  :
else
  echo "FAIL: limiter did not contain fork storm quickly (elapsed ${ELAPSED}s)" >&2
  cat "$WORK/stderr.log" >&2
  exit 1
fi

if ! grep -E 'Resource temporarily unavailable|Alarm clock|setrlimit RLIMIT_NPROC' "$WORK/stderr.log" >/dev/null 2>&1; then
  echo "FAIL: fixture did not observe RLIMIT_NPROC or wall-clock containment signal" >&2
  cat "$WORK/stderr.log" >&2
  exit 1
fi

echo "PASS: fork bomb contained (rc=$RC elapsed=${ELAPSED}s)"
