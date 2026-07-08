# ADR 0055: Escape hatch for self-sandboxing subprocess tools (e.g. Codex)

**Status:** Proposed

## Context

Some agent tools run their own sandbox internally. Codex CLI is the
concrete example: it launches its own Apple Seatbelt profile around its
app-server subprocess, independent of and nested inside whatever sandbox
launched Codex itself.

When Codex runs inside agentjail-shield's macOS Seatbelt profile, its
app-server cold-init intermittently fails with `failed to initialize
in-process app-server client: Operation not permitted`. Investigation
during this branch's work found two contributing factors:

1. **AF_UNIX bind for its IPC app-server.** This part is now fixed by
   [ADR 0054](./0054-macos-shield-tempdir-afunix-parity.md), which allows
   `network-bind` on `/tmp`, `/private/tmp`, and the per-user temp dir.
2. **Credential-shaped file reads/writes during init.** Codex's app-server
   appears to touch paths under `~/.codex` and similar credential-shaped
   locations as part of its startup sequence, which the shield's deny
   rules for sensitive paths and patterns block. This part remains
   unresolved and the failure was observed intermittently, which made
   root-causing it precisely difficult -- nested sandboxes compound in
   ways that are hard to distinguish from timing or ordering issues.

The general problem is broader than Codex: any tool that sandboxes itself
and is then run inside agentjail's shield is a **nested sandbox**. The
inner sandbox's own carve-outs (its own idea of what it needs to read or
write) are invisible to the outer shield, so the outer shield either (a)
denies something the inner tool needs, breaking it in ways that look like
generic EPERMs with little diagnostic signal, or (b) agentjail has to
guess and punch matching holes in its own deny rules -- which, if those
holes are credential-shaped, erodes the security property the shield
exists to provide.

## Decision (proposed, no implementation in this batch)

The proposed direction is: **designate specific, trusted self-sandboxing
tools to run OUTSIDE agentjail's shield**, rather than widening the
shield's credential-file denies to accommodate their internal init
behavior. Since these tools already sandbox themselves, running them
unwrapped does not remove sandboxing from the subprocess -- it just avoids
stacking a second, blind sandbox layer on top of one that already exists
and is better informed about what the tool actually needs.

Sketch of the shape such a mechanism could take (not committed to any of
these specifics):

- A small, explicit allowlist of trusted tool identities (e.g. resolved
  binary path plus a version or signature check) that the shield or the
  hook recognizes at launch time.
- For a recognized identity, the shield either skips wrapping that
  specific subprocess in `sandbox-exec` / Landlock, or execs it through a
  pass-through path that defers entirely to the tool's own sandboxing.
- The hook layer (`agentjail-hook`) continues to observe and enforce its
  own policy on the tool's outward-facing actions regardless of whether
  the OS-level shield wraps it, so Tier 1 enforcement is not lost even
  when Tier 1.5 steps back for that one subprocess.

**Explicit non-goal:** this ADR does NOT propose punching credential-file
read/write holes in agentjail's shield to make Codex's (or any other
tool's) internal init succeed. That path was considered and rejected --
it would widen the shield's most security-sensitive deny rules
(`SensitiveFilePatterns`, `SensitiveMCPCommandDirs`) for the benefit of
one nested tool's convenience, which is the wrong trade-off.

**No implementation lands in this batch.** This document records the
decision direction only; the allowlist mechanism, identity verification
approach, and wiring into `agentjail-shield` / `agentjail-hook` are future
work.

## Consequences

- If implemented as sketched, agentjail would be trusting the inner
  tool's own sandbox to do its job correctly -- a chain-of-trust decision
  that needs its own scrutiny per tool before being added to any
  allowlist.
- Identity verification (how the shield reliably recognizes "this is the
  real Codex binary" rather than something spoofing it, e.g. a
  same-named binary earlier in `PATH`) is an open question that must be
  resolved before implementation; a naive path-based check is not
  sufficient on its own.
- Keeps agentjail's own credential denies intact and uniform for every
  tool that does NOT get an escape-hatch entry -- the shield's baseline
  security posture does not erode as a side effect of accommodating one
  nested-sandbox tool.
- Diagnosing nested-sandbox failures (like the intermittent Codex
  app-server EPERM) remains harder than diagnosing a flat deny, since two
  sandbox layers can fail in combinations that look identical from the
  outside. This ADR does not solve that diagnostic problem; it only
  proposes removing the double-wrapping for tools we choose to trust.
- Tracked as future work; no Linear ticket number is asserted here.
