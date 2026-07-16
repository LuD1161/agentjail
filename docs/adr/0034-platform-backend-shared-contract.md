# ADR 0034: Platform backends share a canonical contract behind an interface

**Status:** Accepted

## Context

Several agentjail binaries carry per-OS implementations selected by build tags
(`_linux.go`, `_darwin.go`, ...). [ADR 0025](./0025-layered-self-protection.md)
and the shield work established this split for `agentjail-shield`, where the
Linux backend uses Landlock (an allowlist model) and the macOS backend uses
Apple Seatbelt / `sandbox-exec` (a denylist model).

[AGENTS.md](../../AGENTS.md) already required "define the interface or shared
logic in a plain `.go` file; put each OS implementation in `_linux.go` /
`_darwin.go`". In practice we followed only half of it: the *implementations*
were split by build tag, but the *data they operate on* was duplicated inline in
each backend instead of living in a shared contract.

Concretely, `cmd/agentjail-shield/shield_linux.go` and `shield_darwin.go` each
hardcoded their own copy of "the paths Claude Code legitimately needs" (home
directories like `~/.claude`, `~/.cache`, `~/.local`; runtime binary dirs; MCP
server dirs). The two copies drifted:

- Linux (`applyLandlock`) granted `~/.claude` **read-write**, so Claude Code ran
  correctly sandboxed on Linux.
- macOS (`sensitiveWritePaths`) left `~/.claude` in the **write-deny** list, so a
  sandboxed Claude Code hit `EPERM` creating `~/.claude/session-env/<uuid>` and
  could not start. macOS was also missing `AGENTJAIL_SHIELDED=1` in the agent
  env, which the Linux backend sets.

Because the "what the agent needs" list lived in two places, a fix or addition
on one OS silently did not reach the other. This is a maintenance hazard that
grows with every new path, runtime, or platform.

## Decision

**Per-OS backends must consume a single, OS-agnostic contract. The contract is
the source of truth; the `_os.go` files are thin adapters that translate it into
the platform's enforcement primitive.**

Rules:

1. **One canonical definition.** Data that is conceptually shared across
   platforms (path allowlists, capability sets, feature toggles) lives in an
   unconstrained `.go` file (no `//go:build`), exposed as a typed value or
   interface -- e.g. `shield_agentpaths.go` returning an `AgentPaths` struct.
2. **Backends adapt, they do not redefine.** `_linux.go` maps the contract onto
   Landlock allow-rules; `_darwin.go` maps it onto sbpl allow/deny carve-outs.
   Neither re-lists the shared data.
3. **Divergence is explicit and named.** Where a platform must genuinely differ
   (e.g. macOS keeps `~/.agentjail` write-denied even though the shared list
   grants it), encode the exception as a named override in that backend
   (`darwinWriteDenyOverrides`) with a comment saying why -- never by silently
   omitting an entry.
4. **Drift is a bug.** A change to the shared contract must take effect on every
   platform by construction; if it only helps one OS, the contract was bypassed.
5. **Each binary compiles only its OS files.** The build tag selection means a
   binary never links another platform's enforcement code; shared contracts stay
   tag-free so every platform sees them.

This is the interface + implementor pattern already preferred elsewhere in the
codebase (registries and abstractions over `switch`-per-call): the contract is
the interface, the `_os.go` files are the implementors.

### Worked example: the tunnel address plan (AGE-224)

The rule is not only about per-OS files. Any value re-declared away from its
owner can drift, and the drift is silent by construction.

`internal/dnsvip` owns the tunnel address plan: the VIP pool is `10.78.0.0/16`,
allocated from `.1` upward. `internal/netns` separately hardcoded the agent's
TUN address as `10.78.0.2/16`, and `internal/tunnel` documented the gateway as
`10.78.0.1`. Three packages, one address plan, no shared constant — so the pool
handed `.2` to the second hostname of every session. That host dialed its own
interface and its traffic never left the box, while every other host worked.

Two properties made it expensive to find:

- **It looked like flakiness.** Exactly one host per session failed, and which
  one depended on resolution order, so it never reproduced in isolation.
- **The tests asserted the collision.** They pinned `10.78.0.1` and
  `10.78.0.2` as the expected first two VIPs. A literal in a test is a claim
  about the address plan; these claims were wrong and green.

The fix is the contract, not the constant: `dnsvip` reserves the datapath
offsets and exports `GatewayV4()`/`AgentV4()`; `netns` derives `TUNAddrCIDR`
from `dnsvip.AgentV4()`. The address now exists in one place, so the pool and
the TUN cannot disagree. Tests assert properties (in-pool, not-a-datapath-
address, sticky) rather than literals.

Generalizing: when two packages must agree on a value, one of them owns it and
the other derives it. If a test has to name the literal to check the agreement,
the agreement is not encoded in the code.

## Consequences

- Adding a path/runtime/capability is a one-line change to the shared contract
  and lands on all platforms at once.
- Backends stay small and auditable -- each is "translate the contract into my
  primitive" plus a short, documented list of platform exceptions.
- Reviewers can diff the contract against each backend to spot missing
  translations; a security-relevant carve-out can't hide in one OS file.
- Applies to any multi-OS binary, not just the shield (e.g. `procwalk_*.go`).
  New platform code (a future BSD/Windows backend, or the macOS app's system
  hooks) implements the existing contract rather than forking a new copy.
- Existing violations are migrated opportunistically; `agentjail-shield` is the
  first to adopt `shield_agentpaths.go` as the reference implementation.
