#!/usr/bin/env bash
#  bench: run hello-net N times, print guest uptime + host wall +
# whether the HTTPS reach succeeded each run. Same shape as
# ../bench.sh , ../kernel/bench.sh , and
# ../virtio-fs/bench.sh  so numbers compare directly.
set -euo pipefail

N="${1:-10}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SPIKE="$(cd "$HERE/.." && pwd)"
PREFIX="$(brew --prefix)"
HOSTBIN="$HERE/hello-net"
ROOTFS="$SPIKE/rootfs"
SOCK="${SOCK:-$PREFIX/var/run/socket_vmnet}"

if [ ! -x "$HOSTBIN" ]; then
    echo "hello-net not built — run: make -C $HERE hello-net" >&2
    exit 1
fi
if [ ! -x "$ROOTFS/bin/busybox" ]; then
    echo "rootfs not prepared — run: make -C $SPIKE rootfs" >&2
    exit 1
fi
if [ ! -S "$SOCK" ]; then
    echo "socket_vmnet socket missing at $SOCK — run: make -C $HERE socket-vmnet-up" >&2
    exit 1
fi

printf 'run  guest_uptime_s  host_wall_ms  ipv4          net\n'

for i in $(seq 1 "$N"); do
    START_NS=$(date +%s%N 2>/dev/null || python3 -c 'import time;print(int(time.time*1e9))')
    OUT=$("$HOSTBIN" "$ROOTFS" "$SOCK" 2>&1 || true)
    END_NS=$(date +%s%N 2>/dev/null || python3 -c 'import time;print(int(time.time*1e9))')
    WALL_MS=$(( (END_NS - START_NS) / 1000000 ))
    UPTIME=$(echo "$OUT" | grep -E '^hello uptime=' | sed -E 's/.*uptime=([0-9.]+).*/\1/' | head -1)
    IP=$(echo "$OUT" | grep -E '^ipv4_addr=' | sed 's/^ipv4_addr=/' | head -1)
    NET=$(echo "$OUT" | grep -E '^net_exit=' | sed 's/^net_exit=/' | head -1)
    [ -z "$UPTIME" ] && UPTIME="?"
    [ -z "$IP" ] && IP="?"
    [ -z "$NET" ] && NET="?"
    printf '%-3d  %-14s  %-12s  %-13s  %s\n' "$i" "$UPTIME" "$WALL_MS" "$IP" "$NET"
done
