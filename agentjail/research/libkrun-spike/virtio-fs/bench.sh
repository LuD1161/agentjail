#!/usr/bin/env bash
#  bench: run hello-virtfs N times, print guest uptime + host wall.
# Same shape as ../bench.sh  so numbers compare directly.
set -euo pipefail

N="${1:-10}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SPIKE="$(cd "$HERE/.." && pwd)"
HOSTBIN="$HERE/hello-virtfs"
ROOTFS="$SPIKE/rootfs"
WORKDIR="${WORKDIR:-$HERE/workdir}"

if [ ! -x "$HOSTBIN" ]; then
    echo "hello-virtfs not built — run: make -C $HERE hello-virtfs" >&2
    exit 1
fi
if [ ! -x "$ROOTFS/bin/busybox" ]; then
    echo "rootfs not prepared — run: make -C $SPIKE rootfs" >&2
    exit 1
fi
mkdir -p "$WORKDIR"
printf 'hello from host pid=%s\n' "$$" > "$WORKDIR/from-host.txt"

printf 'run  guest_uptime_s  host_wall_ms\n'

for i in $(seq 1 "$N"); do
    rm -f "$WORKDIR/from-guest.txt"
    START_NS=$(date +%s%N 2>/dev/null || python3 -c 'import time;print(int(time.time*1e9))')
    OUT=$("$HOSTBIN" "$ROOTFS" "$WORKDIR" 2>&1 || true)
    END_NS=$(date +%s%N 2>/dev/null || python3 -c 'import time;print(int(time.time*1e9))')
    WALL_MS=$(( (END_NS - START_NS) / 1000000 ))
    UPTIME=$(echo "$OUT" | grep -E '^hello uptime=' | sed -E 's/.*uptime=([0-9.]+).*/\1/' | head -1)
    [ -z "$UPTIME" ] && UPTIME="?"
    printf '%-3d  %-14s  %s\n' "$i" "$UPTIME" "$WALL_MS"
done
