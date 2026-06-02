# agentjail — threat model

This page consolidates the adversarial-fixture evidence 
into a single matrix. It exists to make one design property unmistakable:

> **The user-space capture tracks (PATH shim, JS runtime hook, mitmproxy
> addon, substring redactor) are observability, not containment.** The
> microVM substrate is the containment boundary. An agent that wants to
> step around a user-space track usually can, in a handful of lines.

This is the same framing the eBPF LSM community uses for "NOTIFY before
AUTH" capture (cited in [`../../docs/ENGINEERING.md`](../../docs/ENGINEERING.md)
§2) and the same framing Cerbos uses when documenting where its decision
boundary actually lives: a single, well-defined trust boundary, with
everything in front of it labelled "evidence, not enforcement".

## Trust boundary diagram

```
+---------------------------------------------------------------+
|  Host (developer laptop / CI runner)                          |
|  +---------------------------------------------------------+  |
|  |  user-space wrap (observability)                        |  |
|  |  - PATH shim   (exec evidence; PATH lookups only)       |  |
|  |  - JS hook     (Node/Bun in-process patches)            |  |
|  |  - mitmproxy   (opt-in HTTPS_PROXY interception)        |  |
|  |  - redactor    (best-effort cred substring scrub)       |  |
|  +---------------------------------------------------------+  |
|                              |                                |
|                  >>> trust boundary <<<                       |
|                              |                                |
|  +---------------------------------------------------------+  |
|  |  agentjail microVM (containment)                        |  |
|  |  - virtio-fs scoped mount                               |  |
|  |  - TAP egress + raw-TCP block + DNS allowlist           |  |
|  |  - transparent egress proxy with in-guest CA            |  |
|  +---------------------------------------------------------+  |
+---------------------------------------------------------------+
```

Everything **above** the trust boundary is best-effort evidence the agent
can route around. Everything **below** is enforced by the substrate; an
escape requires breaking the hypervisor itself.

## The matrix — one row per fixture

Columns:

- **User-space catches** — does any of the four user-space tracks observe
  the attack as it happens? "Partial" means the shim sees a related event
  (e.g. the parent shell exec) but the load-bearing action is invisible.
- **microVM catches** — does the containment substrate stop or observe
  the attack? The microVM driver is still landing in the M-series (see
  [`../../ARCHITECTURE.md`](../../ARCHITECTURE.md) Layer 1); the column
  records the *design intent*, not a today-status.
- **Both** — does the user-space evidence + microVM enforcement combine
  to give full observation + containment?

| # | Attack class | Fixture | Findings | User-space catches | microVM catches | Both |
|---|---|---|---|---|---|---|
| 1 | Compiled native binary issues HTTPS direct from a child process | [`../test/adversarial/runtime-hook/`](../test/adversarial/runtime-hook/) |  | No (shim sees `go build`; no track sees the resulting binary's egress) | Yes (TAP-only egress; binary cannot reach the host network) | Yes (shim provides exec evidence; TAP blocks the egress) |
| 2 | Absolute-path `/bin/sh` skips PATH lookup | [`../test/adversarial/shim/`](../test/adversarial/shim/) |  | Partial (shim catches an in-shell PATH-resolved `curl`; misses the shell itself and absolute-path children) | Yes (microVM has no notion of "PATH"; egress is gated regardless) | Yes |
| 3 | Direct `posix_spawn(3)` from a C helper (plus `dlopen` + `dlsym` variant) | [`../test/adversarial/runtime-hook/posix_spawn/`](../test/adversarial/runtime-hook/posix_spawn/) |  | No (`posix_spawn` is libc, not PATH; runtime hook lives in the Node process, not in the C child) | Yes (the child cannot egress; substrate enforces independent of libc interposition) | Yes |
| 4 | Bash `/dev/tcp/HOST/PORT` redirection — raw TCP from a shell builtin | [`../test/adversarial/net/devtcp/`](../test/adversarial/net/devtcp/) |  | No for the network call (mitmproxy is bypassed by construction — no HTTP client in the chain honours `HTTPS_PROXY`); shim records only the bash exec | Yes (raw-TCP block at the TAP; only the egress proxy may open 443) | Yes |
| 5 | `dlopen` libc + raw `write(2)` / `connect(2)` — bypass libc-interposition-style hooks at the data-shaped surface (distinct from the exec-shaped `posix_spawn` surface) | [`../test/adversarial/runtime-hook/dlopen-libc/`](../test/adversarial/runtime-hook/dlopen-libc/) |  | No — runtime hook patches JS surfaces (`process.stdout.write`, `net.Socket.connect`); libc write/connect from a C child never enters Node. The dlopen arm additionally sidesteps any hypothetical `DYLD_INTERPOSE` on these symbols | Yes (substrate does not rely on libc interposition; TAP-only egress + raw-TCP block enforce below the C library) | Yes |
| 6 | TLS pinning rejects mitmproxy's MITM cert | [`../test/adversarial/net/tls-pinning/`](../test/adversarial/net/tls-pinning/) |  | Partial (mitmproxy sees SNI / CONNECT; body is opaque. Insecure-bypass mode — adversary disables verification — is fully visible to mitmproxy, but a real adversary will not pick that mode) | Yes for the *transport* (raw-TCP block forces all egress through the in-guest proxy; pinned clients still reject, but they reject *inside* the microVM with the attempted SNI logged) | Partial — the substrate does not break pinning, but it removes the agent's ability to silently exfiltrate: every attempt is observed at the TAP |
| 7 | Agent `unset`s `HTTPS_PROXY` and dials direct | [`../test/adversarial/env/proxy-unset/`](../test/adversarial/env/proxy-unset/) |  | Partial (shim records the `curl --noproxy '*'` exec with full argv as forensic evidence; mitmproxy never sees the bytes) | Yes (TAP-only egress is independent of in-guest env vars; clearing `HTTPS_PROXY` in the guest does nothing) | Yes |
| 8 | Cred substring encoded to defeat the redactor (hex, gzip, `\uNNNN`, sharded) | [`../test/adversarial/redactor/`](../test/adversarial/redactor/) |  | Partial (redactor catches 3 of 7 encodings: plain, base64, URL-encoded. Misses hex, gzip, JSON `\uNNNN` per-byte escape, sharded-across-bodies) | Out of scope for the substrate — redaction is a content-layer concern, not a containment concern | The load-bearing control is the cred's downstream scope (lease TTL + revoke-on-session-end); see [ADR 0004 — credentials, not tools](../../docs/adr/0004-credential-broker-tier1.md). Redaction is defence-in-depth |
| 9 | Timing side-channel exfiltration via DNS | [`../test/adversarial/net/`](../test/adversarial/net/) *(fixture pending)* |  | No (mitmproxy does not see DNS; the shim sees no exec if the agent uses an in-process resolver) | Partial (DNS allowlist at the TAP bounds destinations and rate; timing-channel signal cannot be eliminated, but bandwidth can be capped) | Partial — fundamental limitation: any allowed channel can be timed. Mitigation is rate + destination scope, not elimination |

<!-- TODO: fixture pending — (timing-side-channel exfil via DNS) -->

## What the matrix tells you

1. **No user-space track is a containment boundary.** Every row has at
   least one user-space surface that an adversary defeats in under 30
   lines of code. The shim is exec-time only, the runtime hook lives
   inside the runtime being patched, mitmproxy is opt-in for the child,
   the redactor is best-effort string scanning.
2. **The microVM is the line.** Every row's "fixed" answer routes
   through the substrate — TAP egress, raw-TCP block, DNS allowlist,
   in-guest CA. The two `Partial` rows in the microVM column (TLS
   pinning, DNS timing) are fundamental limitations of *any* containment,
   not gaps specific to this design.
3. **User-space evidence still matters.** Rows 2, 6, 7, 9 show the shim
   or mitmproxy contributing forensic evidence even when they cannot
   stop the attack. That evidence is what the audit context (see the
   audit aggregate in `../../ARCHITECTURE.md`) consumes. Observability
   without enforcement is not nothing — it labels every attempted
   bypass with the agent that made it.

## How to use this page

- **When triaging a report.** Find the closest attack class above. If
  the row says "user-space catches: No / Partial", do not patch the
  shim or the hook; the substrate is the answer.
- **When proposing a new user-space patch.** Read [ADR 0004 —
  credentials, not tools](../../docs/adr/0004-credential-broker-tier1.md)
  and the per-row "Findings" links. A patch that narrows a row's
  miss without narrowing the *family* of misses is rarely worth the
  scan budget; substrate-level fixes are durable.
- **When adding a new fixture.** Add it under
  `agentjail/test/adversarial/<area>/`, write the findings file, add
  a row here, and update the relevant per-fixture cross-reference
  list.

## Out of scope for this page

- **Host compromise.** If the host is owned, the microVM is owned too.
  Outside agentjail's mandate.
- **Hypervisor escape.** Tracked separately; depends on the substrate
  driver (libkrun / Firecracker) and is upstream's problem first.
- **Supply-chain attacks** against the agent runtime itself
  (poisoned Node modules, malicious Python wheels). Not a containment
  question — addressed by package-manager hygiene + the substrate's
  read-only rootfs guarantee.

## Source documents

- Per-fixture findings: see adversarial test fixtures in the test directory
- Per-fixture READMEs: linked from each fixture directory in the matrix
- Layer architecture: [`../../ARCHITECTURE.md`](../../ARCHITECTURE.md)
- Cred-path design rationale: [`../../docs/adr/0004-credential-broker-tier1.md`](../../docs/adr/0004-credential-broker-tier1.md)
- Engineering principles (KISS, inspirations, no shortcuts):
  [`../../docs/ENGINEERING.md`](../../docs/ENGINEERING.md)
