#!/usr/bin/env bash
#  verify: run hello-net, capture stdout, assert IPv4 connectivity
# and an outbound HTTPS reach, AND prove the egress is visible to a
# host-side tcpdump on the vmnet bridge interface.
#
# Exit: 0 on PASS, non-zero with FAIL: messages on first violation.

set -euo pipefail

HOSTBIN="${1:?missing argv1: host binary}"
ROOTFS="${2:?missing argv2: rootfs dir}"
SOCK="${3:?missing argv3: socket_vmnet socket path}"

OUT="$(mktemp -t t0014-verify.XXXXXX)"
PCAP="$(mktemp -t t0014-verify-pcap.XXXXXX)"
trap 'rm -f "$OUT" "$PCAP"' EXIT

# Discover the vmnet bridge interface socket_vmnet attached (shared
# mode creates a bridge100/bridge101/...; pick the one whose IPv4 is
# 192.168.105.1 — socket_vmnet's default gateway for --vmnet-mode=shared).
IFACE=""
for cand in $(ifconfig -l); do
    case "$cand" in
        bridge*|vmenet*|en*)
            ip="$(ifconfig "$cand" 2>/dev/null | awk '/inet 192\.168\.105\.1 / {print $2; exit}')"
            if [ "$ip" = "192.168.105.1" ]; then
                IFACE="$cand"
                break
            fi
            ;;
    esac
done

if [ -z "$IFACE" ]; then
    echo "FAIL: could not find host vmnet bridge interface with 192.168.105.1" >&2
    echo "      socket_vmnet may not be running in --vmnet-mode=shared." >&2
    exit 1
fi
echo "[verify] host vmnet bridge interface: $IFACE"

# Start a host-side tcpdump on the vmnet bridge interface, filtering for
# guest traffic by MAC (matches hello-net.c's hardcoded MAC). Background;
# we'll stop it after the VM exits.
GUEST_MAC="52:54:00:12:34:56"
echo "[verify] starting tcpdump on $IFACE for ether host $GUEST_MAC"
sudo /usr/sbin/tcpdump -i "$IFACE" -nn -w "$PCAP" -U \
    "ether host $GUEST_MAC" >/dev/null 2>&1 &
TCPDUMP_PID=$!
# Make sure tcpdump dies even if we get killed.
trap '
    sudo kill $TCPDUMP_PID 2>/dev/null || true
    wait $TCPDUMP_PID 2>/dev/null || true
    rm -f "$OUT" "$PCAP"
' EXIT

# Give tcpdump a moment to attach BPF.
sleep 0.3

# Run the spike. krun_start_enter exits with the guest workload's exit
# code on success; we just want stdout.
"$HOSTBIN" "$ROOTFS" "$SOCK" >"$OUT" 2>&1 || true

# Drain the tcpdump kernel ring.
sleep 0.5
sudo kill $TCPDUMP_PID 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true

echo "----- guest stdout -----"
cat "$OUT"
echo "------------------------"

fail {
    echo "FAIL: $*" >&2
    exit 1
}

# --- IPv4 connectivity ----------------------------------------------
ip="$(grep -E '^ipv4_addr=' "$OUT" | sed 's/^ipv4_addr=/')"
gw="$(grep -E '^default_gw=' "$OUT" | sed 's/^default_gw=/')"
[ -n "$ip" ] || fail "guest did not print ipv4_addr"
[ "$ip" != "none" ] || fail "guest did not receive a DHCP lease (ipv4_addr=none)"
case "$ip" in
    192.168.105.*) ;;
    *) fail "unexpected IPv4 [$ip]; expected 192.168.105.0/24 (socket_vmnet shared)" ;;
esac
[ "$gw" = "192.168.105.1" ] || fail "default_gw=[$gw] not 192.168.105.1"
echo "PASS: guest has IPv4 connectivity (addr=$ip gw=$gw)"

# --- HTTPS reach ----------------------------------------------------
net_exit="$(grep -E '^net_exit=' "$OUT" | sed 's/^net_exit=/')"
http_payload="$(grep -E '^http_payload=' "$OUT" | sed 's/^http_payload=/')"
[ -n "$net_exit" ] || fail "guest did not print net_exit="
[ "$net_exit" = "0" ] || fail "wget exit non-zero ($net_exit) — outbound HTTPS failed"
[ -n "$http_payload" ] || fail "http_payload empty — wget got no body"
echo "PASS: guest reached https:/example.com (body prefix=[$http_payload])"

# --- Host-side tcpdump visibility -----------------------------------
# tcpdump captured to a pcap; replay with -r to count guest packets.
pkt_count="$(sudo /usr/sbin/tcpdump -nn -r "$PCAP" 2>/dev/null | wc -l | tr -d ' ')"
[ "$pkt_count" -gt 0 ] || fail "no packets from $GUEST_MAC on $IFACE — egress not visible"
echo "PASS: host tcpdump on $IFACE saw $pkt_count packets from guest MAC $GUEST_MAC"
echo "[verify] first 5 captured packets:"
sudo /usr/sbin/tcpdump -nn -r "$PCAP" 2>/dev/null | head -5 | sed 's/^/'

echo "ALL PASS ( vmnet egress + host tcpdump visibility)"
