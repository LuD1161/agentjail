# ADR 0141 — Runtime grants

- **Status:** Accepted
- **Date:** 2026-08-19
- **Deciders:** agentjail-core
- **Related:** [ADR 0001-os-sandbox-enforcement-layer](0001-os-sandbox-enforcement-layer.md), [ADR 0003-mcp-reverse-proxy](0003-mcp-reverse-proxy.md), [ADR 0035-domain-driven-interface-first-typesafe](0035-domain-driven-interface-first-typesafe.md), [ADR 0047-runtime-grant-daemon](0047-runtime-grant-daemon.md), [ADR 0115-agent-decision-adapters](0115-agent-decision-adapters.md), [ADR 0119-general-shell-approval](0119-general-shell-approval.md), [ADR 0132-grant-cli-surface](0132-grant-cli-surface.md), [ADR 0134-host-proxy-mvp](0134-host-proxy-mvp.md)

## Context

AgentJail has several narrowly scoped authority mechanisms with different
vocabularies and lifecycles:

- `grantctl` holds pending project-host network requests;
- `approvalexec` binds one-use Codex prompts to exact shell operations;
- the credential domain tracks issued credential grants; and
- the MCP proxy enforces configured server/tool policy without a shared runtime
  grant abstraction.

Adding a new grant type for every resource would duplicate approval, expiry,
revocation, audit, and session-binding logic. It would also obscure a separate
problem exposed by host-local browser connectors: permission to use
`127.0.0.1:9225` does not make that address reachable when Chrome and the agent
run in different network namespaces. An approval prompt cannot change routing
or widen an immutable Landlock or Seatbelt profile.

The canonical policy decision and the agent-specific rendered response must
remain distinct. A successful retry, rewritten command, connected socket, or
visible prompt is not approval evidence by itself.

## Decision

### One typed authorization domain

`internal/grant` owns the common runtime-grant vocabulary. A request binds a
named principal and session to one action, one canonical resource, one explicit
scope, the current policy epoch, and timestamps. Scope is a closed union:
one-use, current-session, or bounded TTL. Lifecycle state is also closed:
requested, approved, active, denied, consumed, expired, revoked, or activation
failed.

The initial actions align with the existing permission vocabulary where one
exists: `exec`, `read`, `write`, `fetch`, `mcp_call`, and `cred_use`.
`connect` covers non-HTTP network connections. Resource kinds are subprocess,
file, network, MCP tool, and credential.

Resource-specific adapters own canonicalization, equivalence, matching, and
whether the action needs activation. The grant domain validates adapter output:
the kind cannot change and canonicalization must be equivalent to the requested
resource. Matching may narrow a grant but cannot make a different resource
equivalent. The first slice defines this seam and conformance behavior; it does
not add an empty registry before multiple runtime adapters exist.

Explicit and locked denies retain precedence. A runtime grant can satisfy an
eligible `ask`; it cannot override a deny or change the immutable canonical
policy decision.

### Authorization is separate from activation

Approval moves a request to approved, not automatically to active. A resource
that needs only logical proxy enforcement may activate immediately after the
durable approval record succeeds. A resource that depends on host reachability
must remain inactive until its adapter has installed and verified the bridge.
Bind, dial, identity, or readiness failure produces activation failure and no
usable authority.

The isolated agent never selects an arbitrary host destination. Host-local
connectors are preconfigured typed resources. A host-side adapter owns the
actual dial and exposes only the approved connector through the isolation
transport. Guest loopback is never interpreted as host loopback.

Running Landlock and Seatbelt profiles remain immutable. If a requested
resource cannot be reached through an existing proxy/control boundary, the
request is unsupported for that session and fails closed.

### Agent-native approval is an adapter concern

The grant request is agent-neutral; prompt rendering and approval evidence are
agent-specific. Each approval adapter must bind evidence to the exact request,
agent, session, turn/tool-use identity where available, resource, action, and
scope. Unsupported scopes, missing adapters, timeout, cancellation, malformed
evidence, and agent exit leave the request unauthorized.

Codex's existing approval-exec challenge remains the verified one-use shell
transport until a compatibility-tested adapter can carry other resource
requests through a native prompt. This ADR does not infer approval from a hook
retry and does not claim that agent hooks dynamically add MCP configuration.

### Lifecycle durability and migration

Approval and activation audit records are written before authority becomes
usable; failure is fail-closed. Expiry and one-use consumption are checked
atomically at authorization time. Reapers and connector cleanup are hygiene,
not the permission boundary. Session termination revokes all session grants.

Migration is incremental:

1. introduce the typed domain and adapter seam without changing enforcement;
2. move pending/active lifecycle ownership behind a shared authority;
3. adapt `approvalexec` and `grantctl` at their existing verified boundaries;
4. enforce grants at the MCP proxy and add preconfigured host-local connectors;
5. adapt credential issuance only after its backend revocation semantics fit
   the shared lifecycle.

The existing wire protocols and persisted records do not change in the first
slice. Serialization boundaries decode into the new domain through explicit
adapters rather than type aliases or untyped maps.

Dynamic registration of an arbitrary MCP server that was unknown at session
startup, arbitrary raw TCP forwarding, and unconfined host command execution
are not part of the first release.

## Consequences

- File, command, network, MCP, and credential authority share one scope and
  lifecycle vocabulary without sharing unsafe resource matching logic.
- Native allow-once approval can authorize a preconfigured connector, but the
  grant remains unusable until the namespace bridge is verified.
- The design adds an activation phase and adapter conformance tests to every
  resource integration.
- Existing grant implementations coexist during migration, so temporary
  duplication is explicit and bounded rather than hidden behind aliases.
- Preconfiguration is required for the first MCP/connector release; users
  cannot grant arbitrary host ports discovered by an agent mid-session.
- No new dependency is introduced.
