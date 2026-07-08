# Network-visibility branch review — security, usability, gotchas

**Date:** 2026-07-08 · **Branch:** `feat/network-visibility` · **Reviewer:** multi-agent (4 parallel subsystem reviews: netns/shield-wiring, tunnel gateway/gVisor, MITM/CA, netpolicy) + direct comparison against the ClawPatrol source (`denoland/clawpatrol`, the design inspiration — see AGE-58).

Feature under review: the **transparent tunnel + network visibility** layer (AGE-81 and children) — routing an agent session's traffic through a userspace gateway (gVisor netstack + wireguard-go) for protocol recognition, MITM TLS inspection, and content-based policy (`internal/tunnel/`, `internal/dnsvip/`, `internal/mitm/`, `internal/netpolicy/`, `internal/netns/`).

All line numbers verified against the worktree at review time.

---

## Two product constraints this feature must honor

1. **Session-scoped, not machine-wide.** Intercept only the agent session's traffic — never the whole host's.
2. **Fail-open for host availability.** If our service is down, the user's normal machine traffic must not choke. (Inside the sandbox, egress policy may still fail *closed* — the two are distinct.)

### Status against the constraints

| | Linux | macOS |
|---|---|---|
| **1. Session-scoped** | ✅ by construction (per-agent netns) — *but currently intercepts nothing; see W1* | ❌ **machine-wide** default-route + global DNS hijack (S4) — latent only because the RPC is unregistered |
| **2. Fail-open (host)** | ✅ falls back to netproxy, host routing untouched | ❌ **fails closed machine-wide** — daemon crash blackholes all host network + DNS (S4) |

The design *intent* is correct; the **Linux implementation is inert** and the **macOS implementation is the exact anti-pattern** the constraints forbid. Neither ships as-is. AGE-148 (unprivileged userns + TUN-fd handoff, per ADR 0049) is what makes Linux actually intercept per-session, and the macOS machine-wide path must be deleted in favor of the Network Extension path.

---

## A. Integration state — the stack is largely unwired

**W1 — Linux `--tunnel` intercepts nothing.** `startTunnel` builds a `tunnel.Gateway` on WireGuard UDP 51820, then **discards the namespace** (`cmd/agentjail-shield/tunnel_shield_linux.go:63`, `_ = nsResp`) and the agent is launched with a plain `exec.Command` in the **host** netns (`cmd/agentjail-shield/shield_linux.go:320`). The agent is never placed in a namespace, never handed a TUN fd, and nothing routes its traffic to the gateway. The agent-side WireGuard **private key is generated and thrown away** (`tunnel_shield_linux.go:55`), so no peer can ever complete a handshake. Addressing is also incoherent: gateway/DNS at `10.78.0.1`, namespace route at `10.77.0.1`. Net: a gateway nothing connects to.

**W2 — False-positive "secure" state (fix even before AGE-148).** When `startTunnel` returns `ready`, `runShield` sets `noNetproxy = true` (`shield_linux.go:173`) and prints "✓ WireGuard tunnel gateway started" (`shield_linux.go:176`). So if the namespace RPC ever answered, the user gets a green checkmark asserting interception while the agent runs **outside** any namespace with **direct, unfiltered egress on 80/443** (the Landlock port-only fallback) — *strictly weaker than plain `--netproxy`*. `--tunnel` must never set `noNetproxy=true` unless the agent is provably confined.

**W3 — MITM TLS is dead code.** `internal/mitm/` (~1500 LOC) has no production caller; `NewMITMHandler`/`Handle` are unreferenced. The connection handler does a **plaintext bidirectional `io.Copy`** (`internal/tunnel/handler.go:88-103`) with no TLS termination — only the cleartext ClientHello/SNI is seen; HTTPS bodies pass through opaque. The `setupTunnelCA` wrappers (`tunnel_ca_linux.go:14`, `tunnel_ca_darwin.go:34`) are never called, so the CA is never injected either.

**W4 — macOS `--tunnel` is a silent no-op.** `runShield` (`cmd/agentjail-shield/shield_darwin.go:490`) accepts `tunnelMode` but never uses it; `startTunnelDarwin`/`cleanupTunnelDarwin` have zero callers.

**W5 — Deprecated Mechanism A is still the only path the shield calls.** `startTunnel` → `requestNamespace` → `NamespaceService.Create` over `daemon-ns.sock` (`tunnel_shield_linux.go:47`, `tunnel.go:18`). `NamespaceService` is **never `rpc.Register`ed** anywhere, so the dial always fails → silent netproxy fallback. ADR 0049 (Accepted) declares this whole surface dead; it must be **removed**, not fixed.

> **Implication:** Constraints 1–3 are not violated *in effect today* (the feature is inert), but the code would violate all three the moment the RPC got registered, and W2 can already weaken the sandbox. This is scaffolding, not a shippable feature.

---

## B. Namespace & privilege (`internal/netns`, shield wiring)

**S-B1 — No capability drop / hardening after userns setup (CRITICAL for AGE-148).** ClawPatrol maps the agent to **uid-0-inside-the-userns** for mount setup, then before exec'ing the agent's command it **clears all ambient caps** (`PR_CAP_AMBIENT_CLEAR_ALL`, clawpatrol `run_linux.go:620-631`), sets **`SECBIT_NOROOT`** (`sandbox_linux.go:53`), **`PR_SET_NO_NEW_PRIVS`** (`relay_linux.go:108-116`), and **`PR_SET_DUMPABLE 0`** (`run_linux.go:646`). agentjail's `internal/netns/netns_linux.go` does **none** of these — only `GidMappingsEnableSetgroups:false` (line 85). If AGE-148 uses ambient CAP_NET_ADMIN to create the TUN (the standard rootless approach), the agent would **retain elevated capability inside its namespace** unless these are ported. **AGE-148 must port the full cap-drop + secbits lifecycle.**

**S-B2 — `nsenter --target <pid>` PID-reuse race.** Namespace entry is keyed on the holder's numeric PID (`netns_linux.go:240-255`). If the holder dies unexpectedly (OOM/external kill) and the PID is recycled, `nsenter` joins **some other process's** namespaces — possibly the host's — and runs the "isolated" command there. Fix: hold `/proc/<pid>/ns/{user,net,mnt}` fds (or a pidfd) open at `Create()` and enter via those fds, not a live PID lookup.

**S-B3 — `setns(CLONE_NEWUSER)` cannot work from multithreaded Go.** `netns_linux.go:172` — the kernel refuses `setns()` to a *user* namespace for multithreaded processes (every Go program). `bringUpLoopback` knows this and uses an `nsenter` fallback; `configureNsVeth` (`veth_linux.go:117,128`) does not, so `SetupVeth` is **dead-on-arrival**. Also, `doInNetNS` (`netns_linux.go:184-191`) `UnlockOSThread`s even after a *failed* namespace restore, returning a thread stuck in the wrong netns to the scheduler. (Moot once veth is deleted, but the `UnlockOSThread`-after-failed-restore bug is a general hazard.)

**S-B4 — CA trust-bundle temp file leaked to shared `/tmp`.** `InjectCA` (`mount_linux.go:63-108`) writes the combined bundle to `/tmp` and, by comment, **never removes it** — every session leaks a copy; lifetime isn't tied to `Namespace.Close()`. Certs are public (low confidentiality risk) but it's a hygiene/forensics smell. Fix: store the path on `Namespace` and unlink in `Close()` (unlink-after-mount keeps the inode alive).

**Smaller:** `isClonePermError` string-matches error text (`netns_linux.go:285`) — use `errors.Is(err, syscall.EPERM)`. `sleep infinity` holder assumes GNU coreutils (`netns_linux.go:71`) — BusyBox/Alpine rejects it, holder exits instantly, namespace evaporates. Test filler code in `netns_linux_test.go:44-54,188-192` asserts nothing (TestClose never verifies the holder dies). `daemonSocketPath`/`generateSessionID` duplicated across per-OS files (ADR 0034 violation).

---

## C. MITM & CA trust (`internal/mitm`, CA injection)

**S-C1 — MITM CA private key is readable by the sandboxed agent (CRITICAL).** `setupTunnelCA` (`tunnel_ca_linux.go:15-22`) writes `root.key` into `os.MkdirTemp("", …)` → host `/tmp`, `0600`. But the agent runs as the **same host uid** (`netns_linux.go:76-78`) and there is **no `pivot_root`** — the mount namespace inherits the host `/tmp`. `0600` defends against *other* uids, not the same-uid agent. The agent can read `root.key`, mint certs the injected trust store accepts, and turn the MITM into a **self-signed bypass**. Worse on macOS (no namespace at all). **Fix: never persist the ephemeral CA key** — hold it in the gateway's memory, inject only `root.crt`. `setupTunnelCA` currently discards the returned key and reloads from disk, so the design *requires* on-disk persistence today — that must change.

**S-C2 — Credential headers logged verbatim.** `mitm.go:117,223` flatten `req.Header`/`resp.Header` into `network.db`; `store_test.go:30-31,85-87` prove `Authorization: Bearer token123` round-trips to disk. Violates the project's own ADR 0032 ("never log credential values — fingerprints only"). Since `~/.agentjail` is mounted **read-only, not denied**, the agent can read back every captured secret. Bodies are *not* stored (good). Fix: redact sensitive header keys at the store boundary with the existing `RedactToolInput` key-pattern.

**S-C3 — Policy layer is default-allow.** `mitm.go:144-198` blocks only on an explicit `deny`; `nil`/unmatched forwards. With `Matcher == nil`, everything forwards uninspected. (Same architectural issue as S-D1 below — the two enforcement call sites share it.)

**Gotchas:** leaf certs carry no IP SANs (`ca.go:216-228`) → IP-literal hosts get an invalid cert (likely a contributor to AGE-113 "bad certificate"); no ALPN handling (`mitm.go:67-87`) → h2 silently downgraded, h2-only/gRPC clients hang against the HTTP/1.x-only `http.ReadRequest`; darwin `SSL_CERT_FILE` **replaces** the trust bundle rather than augmenting it (`tunnel_ca_darwin.go:40-44`) → non-proxied TLS fails to validate; 10-year validity for an ephemeral CA (`ca.go:92`).

**Done well:** host trust store genuinely untouched on Linux (bind-mount inside the mount ns only); host keychain untouched on macOS (pure env-var, no `security add-trusted-cert`); upstream identity really verified (`ServerName` set, `MinVersion TLS12`, no `InsecureSkipVerify` outside tests); leaf keys P-256, 24h, least-privilege EKU; transport-layer fails closed on unparseable TLS.

---

## D. Protocol recognition & policy (`internal/netpolicy`)

**S-D1 — The system is fail-OPEN, not fail-closed (headline).** The ClawPatrol "viral unknowns" design (truncated/unparseable → UNKNOWN → deny) is **not implemented**. `Evaluate` returns `nil` when no template matches and the documented default is **allow** (`matcher.go:132`); both callers treat `nil`/non-`deny` as allow (`handler.go:74`, `mitm.go:150-197`). Parsers return `nil` on any malformed input (`recognize_postgres.go:28,47`; `recognize_mongo.go:72,87`; `recognize_redis.go:77`), the caller synthesizes a bland `verb:"connect"` with empty fields (`handler.go:108-128`), and the shipped packs are verb-keyed **deny-lists** (`agentpolicy/packs/database.yaml`) — so anything that dodges recognition dodges enforcement. **Fix: an explicit UNKNOWN verdict + default-deny (or default-ask) for managed ports.**

**S-D2 — Only the first ~1024 peeked bytes are ever inspected.** `peekSize = 1024` (`handler.go:18`); `handleConn` evaluates once then `relay()` byte-pumps forever (`handler.go:88-103`). Agent opens a benign Postgres/Redis connection (allowed), then issues `DROP TABLE`/`FLUSHALL` on the **same socket** — never parsed, never evaluated. Defeats the entire verb-based deny surface even with perfect parsing. Also, one `c.Read` may return a partial message (TCP segmentation) → generic allow. Fix: parse per-message on the relay path, or document connect-time-only enforcement and gate DB ports on identity.

**S-D3 — Per-protocol evasions, all feeding the default-allow sink.** SQL verb extraction takes the first token uncleaned (`recognize_postgres.go:164-176`) → `/*x*/DROP`, `WITH … DELETE`, `SELECT 1; DROP …` all evade DDL/delete denies. Mongo `$db` namespace evasion by placing an unhandled BSON type before `$db` (`recognize_mongo.go:210-283`, parser aborts at first unknown type). Port-only dispatch with no protocol/port binding (`recognize.go:43-56`) → speak HTTP to 5432, or send a slightly-malformed Postgres frame, to downgrade to the generic parser and evade `protocol:`-keyed rules. Messages > 1024B silently bypass (`recognize_mongo.go:85`).

**S-D4 — Silent policy-disabling.** Invalid/misspelled `action` (e.g. `denyy`) isn't validated at load → treated as priority-0, deny becomes a no-op (`matcher.go:172-183`). Empty-`id` templates are silently dropped (`matcher.go:96-98`) → a YAML indentation slip vanishes a rule with no warning. Host globs don't normalize trailing-dot/IDN/case (`matcher.go:264-280`) → `api.github.com.` evades a `host:[api.github.com]` deny.

**S-D5 — `ask` is not enforced on the network path.** Only `deny` blocks; a shipped `action: ask` rule (`db/ask-delete`) is logged then **relayed** — `ask == allow` here (`handler.go:74-84`). Either wire `ask` to a real hold/prompt or stop shipping ask rules for network ops.

**Done well:** Redis RESP parsing is genuinely hardened (array/string lengths clamped to buffer, negatives rejected — `recognize_redis.go:135-188`); Postgres/Mongo bounds checks are careful and the chaos suite (`recognize_chaos_test.go`) proves panic-resistance on adversarial input; no unbounded allocations from attacker length fields; malformed-YAML load fails closed. **Caveat:** the chaos tests assert *no panic*, not *fail-closed semantics* — which is exactly the S-D1 gap.

---

## E. macOS machine-wide interception (`internal/daemon/namespace_darwin.go`, `internal/tunnel/utun_darwin.go`)

**S-E1 — Machine-wide hijack + fail-closed-on-crash (both constraints violated).** `Create` installs `route add 0.0.0.0/1 + 128.0.0.0/1` on a utun (`utun_darwin.go:53-58`) and repoints **system-wide Wi-Fi DNS** via `networksetup -setdnsservers Wi-Fi 10.78.0.1` (`namespace_darwin.go:214`). The file admits it: *"macOS has no per-process routing tables; the utun is system-wide"* (`namespace_darwin.go:38-41`). Every app — browser, mail, other users — is captured. On daemon crash/reboot mid-session, `Destroy`/`CleanupAll` never run → the whole machine's network + DNS blackhole into a dead utun with no auto-recovery. `restoreDNS` resets to `"Empty"` (DHCP), **destroying** any custom DNS the user had. Hardcoded `"Wi-Fi"` service silently breaks Ethernet-only Macs. **Delete this entire path**; the ADR-0049 macOS answer is `NETransparentProxyProvider` (per-flow, OS-supervised, crash-safe).

---

## F. Tunnel gateway internals (`internal/tunnel`, gVisor netstack)

**S-F1 — The transparent forwarder is not implemented; `handleConn` is dead code even if wired (CRITICAL).** `gateway.go:65-69` uses upstream `netstack.CreateNetTUN`, and `gateway.go:128-135` claims "spoofing enabled delivers all TCP SYNs to this listener regardless of destination IP/port." Verified against the module source (`golang.zx2c4.com/wireguard .../tun/netstack/tun.go`): `CreateNetTUN` sets `HandleLocal:true`, **never** calls `SetPromiscuousMode`/`SetSpoofing`, and `ListenTCP(Port:0)` binds an **ephemeral port on the gateway's own address** — not a catch-all. `SetSpoofing`/`SetPromiscuousMode` appear **nowhere** in the repo. So a SYN to VIP `10.78.1.5:443` reaches a stack whose only local address is `10.78.0.1/32` with forwarding off → **silently dropped**; `handleConn` never fires in production. The transparent-forwarder pattern requires a custom stack with `SetPromiscuousMode(1,true)` + `SetSpoofing(1,true)` + `tcp.NewForwarder` (the repo already builds a stack in `cbridge.go:101-142` to crib from). **This means AGE-104 ("WireGuard tunnel gateway", marked Done) is structurally present but non-functional — its "Done" was premature; the core interception premise is unbuilt and untested (no test pushes a packet through the stack into `handleConn`).**

**S-F2 — A parser panic kills the whole gateway (and, on macOS, the host).** `gateway.go:167` does `go g.handleConn(c)` with **no `recover()`** (zero recovers in `internal/tunnel`, `internal/dnsvip`, `internal/netpolicy`). `handleConn` feeds attacker-controlled bytes into parsers that document slice-panic hazards (`recognize_postgres.go:46`). One malformed prefix that hits a parser bug crashes every in-flight connection and — in the darwin daemon — the daemon and host networking (S-E1). Fix: `defer recover()` at the top of `handleConn` that **denies** (never allows) the connection, plus recovers in the `bridgePackets` goroutines.

**S-F3 — Gateway upstream-dial loop (AGE-113) real and unmitigated on macOS.** `handler.go:89` dials upstream via `net.Dial` on the host stack using the system resolver. On macOS the system DNS is now the DNS-VIP server (S-E1) and the `/1` routes cover everything, so the gateway's own upstream dial resolves to a **VIP**, routes back into the utun, re-enters `handleConn` → **infinite recursion**, one goroutine/fd/VIP per iteration until exhaustion. No bypass exists (no pinned resolver, no interface binding, no self-connect guard, no daemon-PID exemption). Fix: pin upstream resolution to a real DNS, hard-guard `handleConn` against dial targets inside the VIP pool, and on macOS bind upstream dials to the physical interface (`IP_BOUND_IF`).

**S-F4 — Darwin utun bridge panics on the first packet.** `gateway_utun_darwin.go:122,136` call `Read(bufs,sizes,0)`/`Write(toWrite,0)`; wireguard-go `tun_darwin.go` does `bufs[0][offset-4:]` → with offset 0 that's `bufs[0][-4:]` → **slice-bounds panic** in the bridge goroutine (no recover) → daemon dies *after* routes+DNS were installed → host blackhole. Also buffers are sized from `DefaultMTU` not `cfg.mtu()` (`:116`), truncating packets on a non-default MTU. Fix: offset 4 with 4-byte headroom; size from config MTU.

**S-F5 — Accept loop and VIP registry are single-points-of-failure.** One transient `Accept` error permanently ends `ListenAndServe` (`gateway.go:159-165`); callers only log it → silent interception death (Linux) / host blackhole (macOS). Fix: backoff-retry on temporary errors. The VIP registry never evicts and `Free` has **no production caller** (`registry.go:190`); combined with machine-wide capture the 65,534-entry pool fills over a long session → `SERVFAIL` for all new hosts (`server.go:99`). Fix: LRU eviction + wire `Free` to teardown + audit on exhaustion. Server-speaks-first protocols (SMTP/FTP/MySQL/SSH-server-banner) deadlock because `handleConn` blocks on client bytes before dialing upstream with no read deadline (`handler.go:55`).

**Done well (gateway):** the relay half-close lifecycle is correct (`handler.go:140-170`, both defers + `WaitGroup`); DNS shutdown race handled deliberately (`server.go:46-71`); config validates key sizes and is fuzzed (`config_chaos_test.go`); registry returns IP copies to prevent caller mutation (`registry.go:222`); the two-`/1`-routes trick preserves the daemon's own default route.

---

## AGE-148 acceptance gates (prioritized)

The Mechanism-B rebuild (unprivileged userns + in-namespace TUN + `SCM_RIGHTS` fd handoff) must satisfy, in order:

0. **Build the transparent forwarder** — a custom gVisor stack with `SetPromiscuousMode` + `SetSpoofing` + `tcp.NewForwarder`, so SYNs to any VIP actually reach `handleConn` (S-F1). Without this, nothing else matters — the gateway drops all traffic. Add an end-to-end test injecting a SYN for an arbitrary VIP.
1. **Actually confine the agent** — exec inside the userns+netns / hand it the TUN fd; never set `noNetproxy=true` unless confinement is proven (fixes W1, W2).
2. **Port the capability lifecycle** — ambient-cap raise for TUN setup → `PR_CAP_AMBIENT_CLEAR_ALL` + `SECBIT_NOROOT` + `NO_NEW_PRIVS` + `DUMPABLE=0` before agent exec (S-B1).
3. **Do not persist the MITM CA key** where the same-uid agent can read it (S-C1).
4. **Redact credential headers** before logging (S-C2).
5. **Fail-closed policy core** — UNKNOWN verdict + default-deny/ask on managed ports (S-D1); per-message inspection on the relay, not first-1024-bytes-only (S-D2). Wrap `handleConn` in a `recover()` that **denies** (S-F2); guard upstream dials against the VIP pool to kill the loop (S-F3).
6. **Enter namespaces by fd, not PID** (S-B2); validate `action` and non-empty `id` at pack load (S-D4).
7. **Delete Mechanism A + macOS machine-wide path** (W5, S-E1).
8. **doctor probe + clear fallback** — detect unprivileged-userns availability (`kernel.unprivileged_userns_clone`, `apparmor_restrict_unprivileged_userns`) like ClawPatrol's `usernsBlockHint`, fall back to netproxy with a legible message.

## Code to delete (per ADR 0049)

`internal/daemon/namespace*.go` (NamespaceService), `cmd/agentjail-shield/tunnel.go` + `tunnel_other.go` (RPC client), `internal/netns/veth_linux.go` (+ `SetupVeth` stub in `netns_other.go`), the machine-wide `internal/tunnel/utun_darwin.go` + `namespace_darwin.go` route/DNS code, and the uncalled `setupTunnelCA*` wrappers. **Keep** `internal/netns/netns_linux.go` + `mount_linux.go` (with the fixes above) and all of `internal/netpolicy` / `internal/dnsvip` / `internal/mitm` as the foundation.

## What's genuinely good

Session-scoped isolation primitive is correct on Linux (`CLONE_NEWUSER|NEWNET|NEWNS`); CA injection is host-untouched by construction; host-side fail-open on Linux is clean; upstream TLS identity is verified; the protocol parsers are panic-hardened with a real chaos suite; ADR 0049 is a model deprecation record. The bones are right — the integration and the fail-*closed* posture are what's missing.
