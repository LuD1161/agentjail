# ADR 0127: The opt-in PATH shim defaults to the transparent tunnel

**Status:** Accepted

## Context

The PATH shim is an explicit, durable user choice: `agentjail install
--with-path-shim` records consent in the shell profile and updates ordinary
`claude`, `codex`, and Cursor `agent` commands to enter AgentJail's canonical
launcher. The shared shim currently calls `agentjail run -- <agent>`, which
activates the OS sandbox but leaves the transparent tunnel off. Users therefore
opt into automatic protection while silently missing the network visibility the
UI, MITM policy, and request recording depend on.

An earlier implementation on `rescue/burp-ui-2026-07-05` added `--tunnel`
directly to `agentjail-shield`. That behavior was stranded during the history
rewrite, and restoring it literally would now bypass launch responsibilities
owned by `agentjail run`, including daemon checks, real-agent resolution, and
SSH capability setup.

ADR 0078-lazy-tunnel-consent kept direct tunnelling opt-in and anticipated a
later default-on decision. Its privilege constraints still apply: installation
does not provision the tunnel, and any platform setup happens at first use.

## Decision

The opt-in PATH shim invokes `agentjail run --tunnel -- <agent>`. It preserves
the current command boundary and forwards every child argument unchanged. If
the launcher binary is unavailable but the shield exists, the documented
fallback invokes `agentjail-shield --tunnel -- <agent>`.

Direct `agentjail run -- <agent>` and direct `agentjail-shield -- <agent>`
remain non-tunnel launches. Installing the PATH shim is the standing choice that
makes tunnelling automatic for ordinary agent commands.

The old branch's `--packs-dir` argument is not restored; current netpack
resolution is centralized in `internal/shieldapp`. Its `NODE_OPTIONS` IPv4
override is also not restored: it would replace user Node options and predates
the explicit IPv6 tunnel control in ADR 0110-network-flag-consolidation.

## Consequences

- PATH-shim launches capture and enforce network traffic by default without
  bypassing the canonical launcher or changing child arguments.
- Hosts requiring first-use tunnel setup encounter it on their next shim launch,
  consistent with ADR 0078-lazy-tunnel-consent.
- Scripts that require the non-tunnel posture can use the explicit canonical
  form `agentjail run -- <agent>` instead of the PATH shim.
- The PATH shim remains opt-in, sticky, and fail-open when AgentJail itself is
  missing under ADR 0062-path-shim-consent-is-the-rc-block and
  ADR 0063-shim-fails-open-uninstall-is-total.
