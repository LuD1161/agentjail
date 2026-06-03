#!/usr/bin/env bash
#  spike: run the libkrun custom-kernel boot N times, print
# per-run timings. Mirrors the parent ../bench.sh layout for direct
# comparison with the  default-kernel numbers.
#
# Usage:
#   ./bench.sh         # 10 runs
#   ./bench.sh 20      # 20 runs
#
# Columns (tab-separated):
#   guest_uptime_s    : seconds the guest kernel had been up when /proc/uptime
#                       was read (upper bound on krun_start_enter -> first
#                       guest userspace instruction).
#   host_wall_ms      : wall clock time the host process took end-to-end.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SPIKE="$(cd "${HERE}/.." && pwd)"
N="${1:-10}"

BIN="${HERE}/hello-custom-kernel"
ROOTFS="${SPIKE}/rootfs"
KERNEL="${HERE}/Image"

if [ ! -x "${BIN}" ]; then
    echo "build first: make -C ${HERE} hello-custom-kernel" >&2
    exit 1
fi
if [ ! -d "${ROOTFS}" ]; then
    echo "prepare rootfs first: make -C ${SPIKE} rootfs" >&2
    exit 1
fi
if [ ! -f "${KERNEL}" ]; then
    echo "extract kernel first: make -C ${HERE} kernel" >&2
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

printf '# mode: custom-kernel via krun_set_kernel \n'
printf 'run\tguest_uptime_s\thost_wall_ms\n'
for i in $(seq 1 "${N}"); do
    start=$(now_ns)
    out=$("${BIN}" "${ROOTFS}" "${KERNEL}" 2>/dev/null)
    end=$(now_ns)
    uptime=$(echo "${out}" | sed -n 's/^hello uptime=\(.*\)$/\1/p')
    wall_ms=$(( (end - start) / 1000000 ))
    printf '%d\t%s\t%d\n' "${i}" "${uptime}" "${wall_ms}"
done
