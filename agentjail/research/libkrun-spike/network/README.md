# libkrun macOS spike — virtio-net via socket_vmnet

Wires a virtio-net device into the libkrun microVM via
`krun_add_net_unixstream(ctx, sock, -1, mac, COMPAT_NET_FEATURES, 0)`
and proves outbound IPv4 + HTTPS reach from inside the VM.

Sibling of `../` (minimal boot), `../kernel/` (custom kernel), and
`../virtio-fs/` (host workdir). Neither is modified; this directory adds
the fourth orthogonal demonstration of the libkrun API surface — the network device.

## Requirements

- macOS 14+ on Apple Silicon (arm64). Tested on macOS 26.2 / arm64.
- Homebrew + libkrun 1.18.1 (installed by `make -C .. deps`).
- A rootfs prepared by `make -C .. rootfs`.
- **socket_vmnet 1.2.2** (`brew install socket_vmnet`).
- **sudo** — `socket_vmnet` itself must run as root to use
  `vmnet.framework` (that's how it holds the restricted
  `com.apple.vm.networking` entitlement so we don't have to). tcpdump
  on the bridge interface also needs sudo (BPF device).

## Quick start

```sh
brew install socket_vmnet      # one-time
make socket-vmnet-up           # idempotent; sudo on first run
make                           # build + boot + outbound HTTPS

make verify                    # build + boot + host tcpdump assertion
make bench                     # 10 boots; per-run uptime + wall + IP + net_exit
make socket-vmnet-down         # stop the daemon
```

## The vmnet entitlement workaround

The reason this spike uses `krun_add_net_unixstream(... socket_vmnet
socket ...)` and not `krun_add_net_tap(...)` or the raw vmnet API:

| Approach | Entitlement on agentjail binary | Status on macOS |
|---|---|---|
| `krun_add_net_tap` | n/a — needs `/dev/net/tun` | **Linux-only.** macOS has no `/dev/net/tun`; this call returns -EINVAL. |
| Bare `vmnet.framework` (`vmnet_start_interface`) | **`com.apple.vm.networking`** (restricted; needs paid Apple Developer cert + per-app entitlement grant from Apple) | Blocked on dev boxes; AMFI rejects ad-hoc-signed binaries that claim this entitlement (see libkrun spike findings). |
| `krun_add_net_unixstream` → socket_vmnet | none (only `com.apple.security.hypervisor`, which we already have ad-hoc) | **Works today.** socket_vmnet runs as root and holds vmnet API access; our process talks to it over a unix socket. |
| `krun_add_net_unixstream` → passt / gvproxy | none | Also works, but passt/gvproxy are usermode TCP/IP stacks (slip-like) and slower than vmnet for the agentjail use case; socket_vmnet gives us a real L2 bridge with NAT for free. |

socket_vmnet is the same approach Lima, Colima, and rootless QEMU on
macOS take. It's the canonical macOS workaround for the restricted
`com.apple.vm.networking` entitlement and the recommended path until
agentjail ships with a paid Apple Developer ID (a follow-up already
flagged for the shipping binary; `krun_add_net_unixstream` → socket_vmnet
stays the right answer even after we get the cert, because it lets
agentjail's host binary stay ad-hoc-signable and one less process to entitlement-audit).

## Host ↔ guest network topology

```
                 ┌─────────────────────────────┐
   host          │  vmnet.framework (Apple)    │
   (macOS)       │  shared mode: NAT to en0    │
                 │  gateway: 192.168.105.1     │
                 │  DHCP:    192.168.105.2-254 │
                 └────────────┬────────────────┘
                              │
                  bridge100 (or similar)
                              │
                              │  (tcpdump on this iface
                              │   sees guest egress)
                              │
                 ┌────────────┴────────────────┐
                 │   socket_vmnet daemon       │
                 │   /opt/homebrew/var/run/... │
                 └────────────┬────────────────┘
                              │  unixstream
                              │
                 ┌────────────┴────────────────┐
                 │  agentjail host process     │
                 │  krun_add_net_unixstream    │
                 └────────────┬────────────────┘
                              │  virtio-net
                              │
                 ┌────────────┴────────────────┐
                 │  guest: eth0                │
                 │  MAC: 52:54:00:12:34:56     │
                 │  IPv4 via DHCP (udhcpc)     │
                 └─────────────────────────────┘
```

The guest sees a standard virtio-net device, gets a DHCP lease in the
`192.168.105.0/24` range, and reaches the public internet via
vmnet.framework's NAT. The host can `sudo tcpdump -i bridge100 ether
host 52:54:00:12:34:56` to see every packet the guest sends.

## Expected output (`make verify`)

```
[verify] host vmnet bridge interface: bridge100
[verify] starting tcpdump on bridge100 for ether host 52:54:00:12:34:56
----- guest stdout -----
[spike] virtio-net via unixstream=/opt/homebrew/var/run/socket_vmnet mac=52:54:00:12:34:56
[spike] krun_create_ctx + config: 2.31 ms
[spike] entering guest at host_t=2.40 ms
hello uptime=0.10
ipv4_addr=192.168.105.3
default_gw=192.168.105.1
dhcp_exit=0
net_exit=0
http_payload=<!doctype html>
<html>
<head>
    <title>Examp
------------------------
PASS: guest has IPv4 connectivity (addr=192.168.105.3 gw=192.168.105.1)
PASS: guest reached https://example.com (body prefix=[<!doctype html>...])
PASS: host tcpdump on bridge100 saw 42 packets from guest MAC 52:54:00:12:34:56
ALL PASS (vmnet egress + host tcpdump visibility)
```

## Files

| File | Purpose |
|---|---|
| `hello-net.c` | Host binary: ctx + rootfs + `krun_add_net_unixstream(sock, mac)` + guest shell that brings up eth0 via udhcpc, prints addr/route, and runs `wget https://example.com`. |
| `Makefile` | All targets above plus `socket-vmnet-up`/`socket-vmnet-down` helpers. |
| `verify.sh` | Boots the VM, runs host-side tcpdump in parallel, asserts IPv4 + HTTPS reach + packets-on-bridge. |
| `bench.sh` | 10× boot timing, same format as `../bench.sh` plus IP + net_exit columns. |
| `.gitignore` | Built `hello-net` + ephemeral pcap files. |

## Caveats

- **`curl` is not in alpine minirootfs**; we use busybox `wget` for the
  outbound HTTPS reach. The task brief says "curl https://example.com"
  but honours the intent (HTTPS reach + body capture). Adding curl is
  a 3 MB `apk add curl` away on the shipping rootfs; deliberately not
  changing the base minirootfs here to keep the boot path identical.
- **socket_vmnet runs as root.** That is the design — it holds the
  vmnet entitlement so the libkrun host process does not have to.
  `make socket-vmnet-up` runs it under sudo and chmods the socket to
  `0666` so any user can dial. For a deployed agentjail this becomes
  a one-time install step (`brew install socket_vmnet && sudo brew
  services start socket_vmnet`), not per-boot.
- **No port-forwarding.** `krun_set_port_map` is not called. Outbound
  is all we need here; inbound forwarding (e.g. exposing a guest-side
  service to the host) is a future task if the agentjail use case ever requires it.
- **Hardcoded MAC.** `52:54:00:12:34:56`. Fine for a single-VM spike
  on a single dev box; the future agentjail supervisor needs per-VM MAC
  assignment so multiple concurrent microVMs don't collide on the same vmnet bridge.

See `tasks/findings/` for the full work log, decisions, and
the exact tcpdump numbers measured during the spike.
