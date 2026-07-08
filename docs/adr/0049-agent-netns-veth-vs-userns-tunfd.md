# ADR 0049: Host-veth vs. unprivileged userns + TUN-fd handoff for agent network interception

**Status:** Accepted

## Context

The network-visibility work (AGE-81) routes an agent's traffic into a single
userspace gateway (gVisor netstack + `wireguard-go`) that does DNS-VIP mapping,
protocol recognition, and content-based policy (`internal/tunnel/`,
`internal/dnsvip/`, `internal/netpolicy/`). That design — `HandleLocal=false` +
`SetSpoofing(true)` to catch SYNs to any destination IP — was adopted directly
from `denoland/clawpatrol` (see AGE-58 / `GTM/research/competitive-analysis/clawpatrol-analysis.md`).

The open question is the **plumbing** that gets the agent's packets from its
isolated network namespace into that userspace gateway. Two mechanisms exist,
and they differ in exactly one property that cascades into the entire
privilege, install, and auth story:

- **Where the privileged network operation happens.** Creating or configuring a
  network device requires `CAP_NET_ADMIN` *in the netns where the device lives*.

### Mechanism A — veth pair in the host root netns (current AGE-102/103 plan)

`internal/netns/veth_linux.go` creates a veth pair: one end in the **host root
netns**, one end moved into the agent's netns, with routing between them.
Configuring the host-side end requires `CAP_NET_ADMIN` **in the host root
netns** — a capability an ordinary user cannot hold. `veth_linux.go` itself
documents the only two ways to get it:

1. `setcap cap_net_admin=ep` on the shield binary (privilege on every shield
   invocation), or
2. a **privileged daemon** that performs the veth setup on the shield's behalf
   (AGE-103: a system service installed with `AmbientCapabilities=CAP_NET_ADMIN`,
   `sudo systemctl enable` / a root LaunchDaemon, i.e. a one-time install
   password).

Option 2 is the current plan. It forces:

- a **root/system daemon** distinct from the per-user daemon that ships today
  (macOS LaunchAgent, Linux `systemctl --user`), which hold no capabilities;
- an **install-time password** (AGE-103);
- a **new privileged RPC surface** (`NamespaceService.Create/Destroy` over
  `daemon-ns.sock`) that must be authenticated — the peer-UID + per-session
  ownership gate of AGE-140 ("any caller could `Destroy` any session's netns by
  ID"). Not yet `rpc.Register`ed; today `--tunnel` silently falls back to
  netproxy.

### Mechanism B — unprivileged user namespace + TUN-fd handoff (ClawPatrol's design)

ClawPatrol takes the opposite bet, from day one: *"zero privilege requirements,
works in LXC / OpenVZ / Docker / macOS, doesn't need `NET_ADMIN`."*

On **Linux**, no host privilege is ever exercised:

1. An ordinary user calls `unshare(CLONE_NEWUSER)`. The kernel grants that
   process a full capability set — **including `CAP_NET_ADMIN`** — but scoped
   *only to namespaces owned by that new userns*. No host root.
2. Inside it, `unshare(CLONE_NEWNET)` creates the agent's netns. A **TUN device
   is created inside that netns** (`/dev/net/tun` + `TUNSETIFF`), where the
   process legitimately holds `CAP_NET_ADMIN`.
3. The open **TUN file descriptor is passed** from the namespaced process to the
   userspace gateway (running as the user, in the host netns) over a Unix socket
   via **`SCM_RIGHTS`**. The gateway `read()`/`write()`s packets on that fd and
   feeds them into the gVisor netstack.

The privileged operation happens only inside namespaces the user *created*, so
it needs neither host root, setcap, a privileged daemon, nor an install
password. On **macOS** — which has no user namespaces — ClawPatrol instead uses
a `NETransparentProxyProvider` **system extension**: a one-time, OS-mediated
**user approval** (the "password at install" memory), not a root daemon and not
per-run sudo.

## Decision (recommended)

Adopt **Mechanism B** as the primary path, matching the reference design we
already borrowed the gateway from:

- **Linux:** unprivileged user namespace + in-namespace TUN + `SCM_RIGHTS` fd
  handoff to the userspace gateway. No host `CAP_NET_ADMIN`, no privileged
  daemon, no install password.
- **macOS:** Network Extension (system extension) with one-time user approval —
  consistent with the existing `macos/` tunnel/extension work (AGE-96 chose
  `NEPacketTunnelProvider`).
- **Fallback:** where unprivileged user namespaces are disabled by host policy
  (some hardened/older distros set `kernel.unprivileged_userns_clone=0` or
  `user.max_user_namespaces=0`) or `/dev/net/tun` is unavailable, fall back to
  the existing **netproxy** mode (as `--tunnel` already does today).
- **Mechanism A (host-veth + privileged daemon) is deprecated and will not be
  built.** AGE-103 (privileged namespace RPC + `install --service`) and AGE-140
  (peer-UID + per-session auth on `daemon-ns.sock`) are **closed as obviated**.
  The privileged socket is never `rpc.Register`ed; netproxy — not a privileged
  daemon — is the sole fallback. The dormant veth/`daemon-ns.sock` code on
  `feat/network-visibility` is dead and should be removed as Mechanism B lands.

## Consequences

**Positive**

- **No host privilege on Linux, no install password.** The whole
  privileged-daemon workstream collapses: **AGE-103 (privileged namespace RPC +
  `install --service`)** and **AGE-140 (peer-UID + per-session auth on
  `daemon-ns.sock`)** are largely obviated — there is no privileged socket to
  authenticate because there is no privileged daemon. The per-user daemon
  (LaunchAgent / `systemctl --user`) stays as-is.
- **Matches the design we copied.** Removes the divergence where agentjail took
  ClawPatrol's userspace gVisor/WireGuard interception but bolted host-veth
  privilege back on.
- **Smaller attack surface.** No CAP_NET_ADMIN-behind-a-socket; the isolation
  primitives are namespaces the user already owns.
- **Portability.** Works in unprivileged containers (LXC/Docker/CI) where a
  host-veth + CAP_NET_ADMIN daemon cannot run.

**Negative / risks**

- **Depends on unprivileged userns being enabled.** This is the load-bearing
  assumption. Must be probed at runtime (`doctor`) and fail cleanly to netproxy
  when absent. Document the sysctls.
- **`/dev/net/tun` access.** Must exist and be openable inside the userns; some
  minimal images restrict it. (Pure-userspace networking à la
  slirp4netns/pasta avoids even TUN, but that is a larger change and out of
  scope here.)
- **fd-passing plumbing.** `SCM_RIGHTS` handoff + keeping the namespaced holder
  process alive for the session is new machinery in `internal/netns` /
  `internal/tunnel`, replacing the veth/daemon-RPC code paths already written.
- **macOS still needs one-time approval.** Unavoidable on that platform; it is
  install-time and OS-mediated, not per-run.
- **Degraded fallback where userns is unavailable.** When unprivileged userns is
  disabled, the agent gets netproxy (hostname-only egress control), not the
  in-namespace deep inspection. This is an accepted, documented limitation
  rather than a privileged escape hatch — `doctor` must surface it clearly.

## Related

- AGE-81 (parent), AGE-102 (netns package), AGE-103 (privileged namespace RPC —
  reconsidered here), AGE-140 (namespace RPC auth gate — obviated on the Linux
  primary path), AGE-96 (macOS `NEPacketTunnelProvider`).
- AGE-58 / `GTM/research/competitive-analysis/clawpatrol-analysis.md` — the
  zero-privilege userns + `SCM_RIGHTS` design this ADR adopts.
- [ADR 0034](./0034-platform-backend-shared-contract.md) — platform backends
  share a canonical contract; applies to any retained veth fallback.
