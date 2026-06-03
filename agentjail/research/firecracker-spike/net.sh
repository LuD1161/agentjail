#!/usr/bin/env bash
# Firecracker virtio-net + egress allowlist helper.
#
# This file is sourced by boot.sh. It sets up a TAP-backed bridge for the guest,
# two private upstream namespaces used for deterministic self-tests, and an
# iptables FORWARD chain that fail-closes to REJECT for any destination not in
# allowlist.yaml.

NET_BRIDGE="${NET_BRIDGE:-fc-br0}"
NET_TAP="${NET_TAP:-fc-tap0}"
NET_CHAIN="${NET_CHAIN:-fc-egress}"
NET_ALLOWLIST="${NET_ALLOWLIST:-${SCRIPT_DIR}/allowlist.yaml}"
NET_STATE_DIR="${NET_STATE_DIR:-${SCRIPT_DIR}/.net-state}"

NET_GUEST_CIDR="${NET_GUEST_CIDR:-172.16.0.2/24}"
NET_GUEST_IP="${NET_GUEST_IP:-172.16.0.2}"
NET_HOST_IP="${NET_HOST_IP:-172.16.0.1}"
NET_GUEST_MAC="${NET_GUEST_MAC:-02:FC:00:00:00:01}"

NET_ALLOWED_NS="${NET_ALLOWED_NS:-fc-allow}"
NET_ALLOWED_HOST_DEV="${NET_ALLOWED_HOST_DEV:-fc-allow-host}"
NET_ALLOWED_NS_DEV="${NET_ALLOWED_NS_DEV:-fc-allow-ns}"
NET_ALLOWED_HOST_IP="${NET_ALLOWED_HOST_IP:-10.200.0.1}"
NET_ALLOWED_NS_IP="${NET_ALLOWED_NS_IP:-10.200.0.2}"
NET_ALLOWED_CIDR="${NET_ALLOWED_CIDR:-10.200.0.2/32}"

NET_BLOCKED_NS="${NET_BLOCKED_NS:-fc-block}"
NET_BLOCKED_HOST_DEV="${NET_BLOCKED_HOST_DEV:-fc-block-host}"
NET_BLOCKED_NS_DEV="${NET_BLOCKED_NS_DEV:-fc-block-ns}"
NET_BLOCKED_HOST_IP="${NET_BLOCKED_HOST_IP:-10.201.0.1}"
NET_BLOCKED_NS_IP="${NET_BLOCKED_NS_IP:-10.201.0.2}"

NET_SERVICE_PORT="${NET_SERVICE_PORT:-8080}"

net_log { log "[net] $*"; }

net_require_root {
  if [ "$(id -u)" -ne 0 ]; then
    die "network subcommands require root (run via sudo on a Linux + KVM host)" 2
  fi
}

net_require_tools {
  local tool
  for tool in ip iptables python3 sysctl; do
    command -v "$tool" >/dev/null 2>&1 || die "missing host tool for networking: $tool" 2
  done
}

net_preflight {
  cmd_check
  net_require_root
  net_require_tools
  [ -f "$NET_ALLOWLIST" ] || die "allowlist file missing: $NET_ALLOWLIST" 2
  [ -f "$ROOTFS_METADATA_PATH" ] || die "network self-test requires ./boot.sh rootfs-build first" 2
  mkdir -p "$NET_STATE_DIR"
}

net_json_string {
  jq -Rn --arg v "$1" '$v'
}

net_allowlist_cidrs {
  awk '
    /^[[:space:]]*-[[:space:]]*cidr:/ {print $2}
    /^[[:space:]]*cidr:/ {print $2}
  ' "$NET_ALLOWLIST" | tr -d '"' | sed '/^[[:space:]]*$/d'
}

net_guest_command {
  cat <<EOF
ip link set lo up
ip link set eth0 up
ip addr add ${NET_GUEST_CIDR} dev eth0
ip route add default via ${NET_HOST_IP}
wget -T 5 -qO- http:/${NET_ALLOWED_NS_IP}:${NET_SERVICE_PORT}/ >/dev/null && echo NET_ALLOW_OK || echo NET_ALLOW_FAIL
wget -T 5 -qO- http:/${NET_BLOCKED_NS_IP}:${NET_SERVICE_PORT}/ >/dev/null && echo NET_BLOCK_FAIL || echo NET_BLOCK_OK
reboot -f
EOF
}

net_boot_args {
  local guest_cmd
  guest_cmd="$(net_guest_command | tr '\n' ';' | sed 's/;*$/')"
  printf "%s" "console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd init=/bin/sh -- -c '${guest_cmd}'"
}

net_setup_bridge {
  ip link show "$NET_BRIDGE" >/dev/null 2>&1 || ip link add name "$NET_BRIDGE" type bridge
  ip addr flush dev "$NET_BRIDGE" >/dev/null 2>&1 || true
  ip addr add "${NET_HOST_IP}/24" dev "$NET_BRIDGE"
  ip link set "$NET_BRIDGE" up

  ip link show "$NET_TAP" >/dev/null 2>&1 || ip tuntap add dev "$NET_TAP" mode tap
  ip link set "$NET_TAP" master "$NET_BRIDGE"
  ip link set "$NET_TAP" up

  net_log "bridge ${NET_BRIDGE} up with guest gateway ${NET_HOST_IP}; tap=${NET_TAP}"
}

net_setup_namespace {
  local ns="$1" host_dev="$2" ns_dev="$3" host_ip="$4" ns_ip="$5" body="$6"
  local www_dir pidfile

  www_dir="${NET_STATE_DIR}/${ns}-www"
  pidfile="${NET_STATE_DIR}/${ns}.pid"

  ip netns add "$ns" 2>/dev/null || true
  ip link show "$host_dev" >/dev/null 2>&1 || ip link add "$host_dev" type veth peer name "$ns_dev"
  ip link set "$ns_dev" netns "$ns"

  ip addr flush dev "$host_dev" >/dev/null 2>&1 || true
  ip addr add "${host_ip}/24" dev "$host_dev"
  ip link set "$host_dev" up

  ip netns exec "$ns" ip addr flush dev "$ns_dev" >/dev/null 2>&1 || true
  ip netns exec "$ns" ip addr add "${ns_ip}/24" dev "$ns_dev"
  ip netns exec "$ns" ip link set lo up
  ip netns exec "$ns" ip link set "$ns_dev" up
  ip netns exec "$ns" ip route replace "${NET_GUEST_IP}/32" via "$host_ip"

  mkdir -p "$www_dir"
  printf '%s\n' "$body" > "${www_dir}/index.html"
  if [ -f "$pidfile" ]; then
    kill "$(cat "$pidfile")" >/dev/null 2>&1 || true
    rm -f "$pidfile"
  fi

  ip netns exec "$ns" sh -c "cd '$www_dir' && exec python3 -m http.server ${NET_SERVICE_PORT} --bind ${ns_ip}" \
    >"${NET_STATE_DIR}/${ns}.stdout" 2>"${NET_STATE_DIR}/${ns}.stderr" &
  echo $! > "$pidfile"

  net_log "namespace ${ns} serving http:/${ns_ip}:${NET_SERVICE_PORT}/"
}

net_setup_namespaces {
  net_setup_namespace \
    "$NET_ALLOWED_NS" \
    "$NET_ALLOWED_HOST_DEV" \
    "$NET_ALLOWED_NS_DEV" \
    "$NET_ALLOWED_HOST_IP" \
    "$NET_ALLOWED_NS_IP" \
    "allowed"

  net_setup_namespace \
    "$NET_BLOCKED_NS" \
    "$NET_BLOCKED_HOST_DEV" \
    "$NET_BLOCKED_NS_DEV" \
    "$NET_BLOCKED_HOST_IP" \
    "$NET_BLOCKED_NS_IP" \
    "blocked"
}

net_setup_filter {
  local current_forward
  current_forward="$(sysctl -n net.ipv4.ip_forward)"
  printf '%s\n' "$current_forward" > "${NET_STATE_DIR}/ip_forward.before"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null

  iptables -N "$NET_CHAIN" 2>/dev/null || true
  iptables -F "$NET_CHAIN"
  iptables -C FORWARD -i "$NET_BRIDGE" -j "$NET_CHAIN" 2>/dev/null \
    || iptables -I FORWARD 1 -i "$NET_BRIDGE" -j "$NET_CHAIN"
  iptables -C FORWARD -o "$NET_BRIDGE" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
    || iptables -I FORWARD 1 -o "$NET_BRIDGE" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  while IFS= read -r cidr; do
    [ -n "$cidr" ] || continue
    iptables -A "$NET_CHAIN" -d "$cidr" -p tcp --dport "$NET_SERVICE_PORT" -j ACCEPT
  done <<EOF
$(net_allowlist_cidrs)
EOF
  iptables -A "$NET_CHAIN" -j REJECT --reject-with icmp-admin-prohibited

  net_log "iptables chain ${NET_CHAIN} installed from ${NET_ALLOWLIST}"
}

cmd_net_setup {
  net_preflight
  net_setup_bridge
  net_setup_namespaces
  net_setup_filter
}

cmd_net_teardown {
  local ns pid pidfile

  if command -v iptables >/dev/null 2>&1; then
    iptables -D FORWARD -i "$NET_BRIDGE" -j "$NET_CHAIN" 2>/dev/null || true
    iptables -D FORWARD -o "$NET_BRIDGE" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    iptables -F "$NET_CHAIN" 2>/dev/null || true
    iptables -X "$NET_CHAIN" 2>/dev/null || true
  fi

  if [ -f "${NET_STATE_DIR}/ip_forward.before" ]; then
    sysctl -w "net.ipv4.ip_forward=$(cat "${NET_STATE_DIR}/ip_forward.before")" >/dev/null 2>&1 || true
    rm -f "${NET_STATE_DIR}/ip_forward.before"
  fi

  for ns in "$NET_ALLOWED_NS" "$NET_BLOCKED_NS"; do
    pidfile="${NET_STATE_DIR}/${ns}.pid"
    if [ -f "$pidfile" ]; then
      pid="$(cat "$pidfile")"
      kill "$pid" >/dev/null 2>&1 || true
      rm -f "$pidfile"
    fi
    ip netns del "$ns" >/dev/null 2>&1 || true
  done

  ip link del "$NET_ALLOWED_HOST_DEV" >/dev/null 2>&1 || true
  ip link del "$NET_BLOCKED_HOST_DEV" >/dev/null 2>&1 || true
  ip link del "$NET_TAP" >/dev/null 2>&1 || true
  ip link del "$NET_BRIDGE" >/dev/null 2>&1 || true

  net_log "network teardown done"
}

cmd_net_refresh {
  net_preflight
  net_setup_filter
}

cmd_net_launch {
  cmd_net_setup
  trap 'cmd_net_teardown; cmd_teardown' EXIT
  cmd_fetch
  cmd_launch network
}
