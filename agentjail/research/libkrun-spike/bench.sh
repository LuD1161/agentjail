#!/usr/bin/env bash
#  spike: run the libkrun hello-world N times, print per-run timings.
#
# Outputs two columns:
#   guest_uptime_s    : seconds the guest kernel had been up when /proc/uptime
#                       was read (upper bound on krun_start_enter -> first
#                       guest userspace instruction).
#   host_wall_ms      : wall clock time the host process took end-to-end.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
N="${1:-10}"

if [ ! -x "${HERE}/hello" ]; then
    echo "build first: make -C ${HERE} hello" >&2
    exit 1
fi
if [ ! -d "${HERE}/rootfs" ]; then
    echo "prepare rootfs first: ${HERE}/prepare-rootfs.sh" >&2
    exit 1
fi

now_ns {
    if command -v gdate >/dev/null; then
        gdate +%s%N
    else
        # Fallback (BSD date — millisecond precision only); use python.
        python3 -c 'import time; print(int(time.monotonic*1e9))'
    fi
}

printf 'run\tguest_uptime_s\thost_wall_ms\n'
for i in $(seq 1 "${N}"); do
    start=$(now_ns)
    out=$("${HERE}/hello" "${HERE}/rootfs" 2>/dev/null)
    end=$(now_ns)
    uptime=$(echo "${out}" | sed -n 's/^hello uptime=\(.*\)$/\1/p')
    wall_ms=$(( (end - start) / 1000000 ))
    printf '%d\t%s\t%d\n' "${i}" "${uptime}" "${wall_ms}"
done
