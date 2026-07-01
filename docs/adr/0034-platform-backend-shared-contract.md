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
