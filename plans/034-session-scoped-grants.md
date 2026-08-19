# Session-scoped capability grants

Status: IN PROGRESS  
Owner: unassigned  
Started: 2026-08-19  
Linear migration: parent draft is currently represented by AGE-93; lifecycle
work was drafted in AGE-57. Treat this file as the source of truth until the
remaining issues can be created in Linear.

## Objective

Let an agent request narrowly scoped authority during a live session and route
that request through the agent's native approval surface. The same domain model
must cover shell execution, file access, network access, MCP calls, and
credential use without defining a new approval mechanism for each capability.

Authorization and reachability are separate. A grant may authorize access to a
host-local service, but it does not make that service reachable across a
container or microVM network namespace. A resource adapter must activate and
attest any required bridge before the grant becomes usable.

## Invariants

- Explicit and locked policy denies retain precedence over runtime grants.
- A grant is bound to the requesting principal and session; it is not a bearer
  token transferable between agents or sessions.
- Scope is explicit: one use, the current session, or a bounded TTL.
- Approval is not activation. A grant is usable only after the resource adapter
  confirms that enforcement and, where necessary, connectivity are active.
- Expiry and one-use consumption are checked atomically with authorization.
- Durable approval/audit failure denies activation.
- Existing Landlock and Seatbelt profiles are immutable for a running process;
  no grant claims to widen them in place.
- Host execution remains allowlisted and typed. A network grant is not a raw
  command or arbitrary TCP proxy escape hatch.

## Work breakdown

| Track | Work item | Depends on | Status |
|------:|-----------|------------|--------|
| 1 | Define the generic typed grant domain and adapter contract | — | IN PROGRESS |
| 2 | Implement the generic runtime grant lifecycle | 1 | TODO |
| 3 | Bridge generic grant requests to native agent approval prompts | 1, 2 | TODO |
| 4 | Enforce session-scoped MCP grants | 1, 2, 3 | TODO |
| 5 | Bridge approved host-local MCP connectors across isolation boundaries | 1; integration after 4 | IN PROGRESS — same-host route and Linux bind-mounted AF_UNIX transport; microVM launch primitive unavailable |
| 6 | Add release-gate coverage, diagnostics, and user documentation | 2–5 | TODO |

## 1. Define the generic typed grant domain and adapter contract

Create the domain vocabulary shared by request, approval, activation,
enforcement, audit, and UI layers. Existing host grants, approval-exec
challenges, and credential grants migrate through adapters rather than through
a flag day.

Acceptance criteria:

- Named types represent grant ID, principal, session, action, resource kind,
  resource identity, scope, lifecycle state, and approval reference.
- Supported actions cover command execution, file read/write, network access,
  MCP tool calls, and credential use without capability-specific grant structs.
- Scope constructors make invalid one-use/session/TTL combinations
  unrepresentable; TTL scope requires a valid expiry.
- The model distinguishes authorization from activation/readiness.
- Resource-specific canonicalization and matching are owned by typed adapters;
  adapters cannot silently widen the requested resource.
- Explicit/locked deny precedence is part of the evaluator contract.
- Existing `grantctl`, `approvalexec`, and credential grant types have a
  documented incremental migration path.
- Unit tests cover construction, validation, scope semantics, and rejection of
  invalid or widened resources.
- The architectural choice is recorded in an ADR with no new dependency.

## 2. Implement the generic runtime grant lifecycle

Add the concurrent, in-memory authority that moves a request through approval,
activation, use, expiry, revocation, or denial while preserving audit
durability requirements.

Acceptance criteria:

- The lifecycle covers requested, approved, active, denied, consumed, expired,
  revoked, and activation-failed terminal behavior.
- Requests and grants are bound to principal, session, resource, action, scope,
  policy epoch, and timestamps.
- One-use authorization is claimed and consumed atomically; failed execution
  can roll back only under an explicit adapter contract.
- TTL and session expiry are checked synchronously on lookup/use; cleanup is
  hygiene rather than the permission boundary.
- Session termination revokes all grants belonging to that session.
- Approval and activation records are written before authority is exposed;
  audit failure fails closed.
- Duplicate approval, replay, cross-session use, stale policy epoch, and expired
  grants are rejected deterministically.
- A clock is injected for deterministic tests.
- Race-enabled tests cover concurrent claim/use/revoke/expiry paths.

## 3. Bridge generic requests to native agent approval prompts

Teach each supported agent adapter to translate a generic request into the
agent's native allow-once/session approval experience and bind the response to
the exact pending request.

Acceptance criteria:

- The domain approval request is agent-neutral; prompt transport and response
  evidence are adapter-specific.
- Codex requests use a native approval boundary that can carry typed resource
  intent, rather than treating a successful retry as approval evidence.
- Claude Code and other supported adapters preserve their native prompt
  semantics through the same domain contract.
- Approval evidence binds agent/session/turn/tool-use/request/resource/action
  and cannot authorize a sibling or later request.
- Allow-once, bounded session/TTL approval, and deny map to explicit domain
  outcomes; unsupported scopes fail closed.
- Prompt text shows the concrete action, canonical resource, scope, and
  isolation consequence before approval.
- Cancellation, timeout, malformed evidence, adapter absence, and agent crash
  all leave the request unauthorized.
- Compatibility tests pin the installed agent versions and current official
  hook/approval contracts used by each adapter.

## 4. Enforce session-scoped MCP grants

Apply active grants at the MCP proxy boundary for MCP servers configured before
session startup. Dynamic hot registration of previously unknown MCP servers is
not required for the first release.

Acceptance criteria:

- MCP resources are identified canonically by server and tool, with strict
  typed argument matching where the policy requires it.
- Protocol metadata such as `_meta` is normalized without making strict
  argument policies unusable.
- The MCP proxy checks explicit deny precedence and an active grant before
  forwarding a call.
- One-use MCP grants are consumed atomically with forwarding authorization;
  session/TTL grants stop working immediately after revocation or expiry.
- A grant for one server/tool/argument set cannot authorize another.
- Unknown or newly registered servers remain unavailable until the supported
  configuration lifecycle makes them known to the proxy.
- Every request, approval, activation, use, denial, expiry, and revocation is
  represented in the decision/audit model without credential values.
- Integration tests cover allow once, session allow, deny, expiry, replay,
  cross-session isolation, strict arguments, and unavailable upstreams.

## 5. Bridge approved host-local MCP connectors across isolation boundaries

Provide a typed host-side connector so an isolated workspace can reach an
approved service such as a browser CDP endpoint without exposing arbitrary host
network access.

Acceptance criteria:

- The connector binds to the isolation boundary and dials the configured host
  resource from the host side; guest loopback is never assumed to be host
  loopback.
- The resource is configured by typed identity (for example, a named browser
  connector), not by an agent-supplied arbitrary destination.
- Authorization alone does not mark the grant active; activation requires a
  successful reachability and identity/readiness probe.
- The connector is scoped to the approved principal/session/resource/action
  and shuts down or rejects traffic immediately on revoke/expiry/session end.
- No generic raw TCP forwarder or unconfined host command execution is exposed
  to the agent.
- Failure to bind, dial, verify, or clean up produces activation failure and no
  usable grant.
- Linux container/microVM and macOS isolation implementations consume one
  shared contract, with platform-specific transport kept behind interfaces.
- Tests prove namespace separation before activation, successful approved
  bridging, destination confinement, and cleanup after expiry/revocation.

## 6. Add release-gate coverage, diagnostics, and documentation

Make the complete flow observable and prevent a green unit suite from hiding a
broken native prompt, namespace bridge, or expired permission.

Acceptance criteria:

- An end-to-end fixture requests an initially unavailable, preconfigured MCP
  resource; displays native approval; activates the bridge; performs one
  allowed call; and denies reuse after the selected scope ends.
- The release gate exercises both authorization and reachability from inside
  the real isolation tier, not only from the host or a mocked transport.
- Negative fixtures cover denial, prompt timeout, missing approval evidence,
  failed activation, wrong destination, session mismatch, expiry, replay, and
  locked-policy denial.
- `agentjail doctor` distinguishes policy denial, approval unavailable,
  approval pending/denied, grant inactive/expired, and resource unreachable.
- Audit output presents the canonical decision separately from runtime grant
  handling and records lifecycle transitions without secrets.
- User documentation explains preconfiguration, scope choices, namespace
  boundaries, unsupported dynamic MCP registration, and recovery steps.
- The tested agent versions, official contract sources, and verification date
  are recorded beside the integration coverage.
- `make e2e-release` fails when the native prompt or connector path is a silent
  no-op.

## Non-goals for the first release

- Hot-registering an arbitrary MCP server that was unknown at session startup.
- Treating a permission grant as a mechanism for widening an already-applied
  Landlock or Seatbelt profile.
- Exposing arbitrary guest-selected host ports or raw TCP forwarding.
- Replacing the credential grant manager in the first domain-model slice.
- Treating a retry, rewritten command, or successful connection as proof that
  the user approved the request.

## Verification cadence

Each track owns focused unit and integration tests. Before merge, run the full
repository gates required by `AGENTS.md`, including `go build ./...`,
`go vet ./...`, `go test ./...`, `make smoke`, and `make adr-check` when the ADR
is introduced or renumbered.
