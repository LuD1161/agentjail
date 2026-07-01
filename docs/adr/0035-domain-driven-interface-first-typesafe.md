# ADR 0035: Domain-driven, interface-first, type-safe architecture

**Status:** Accepted

## Context

agentjail has grown into several distinct areas of responsibility -- policy
evaluation, the credential broker, the MCP reverse proxy, the OS shield, agent
hook wiring, the event store, and telemetry. Some already have clean seams
(`policy.HookEngine`, `store.EventStore`, `agents.Registry`, the typed
`config.PolicyConfig`, sqlc-generated store types). Others grew as concrete code
with cross-cutting reach and stringly-typed data.

Two prior decisions point the same direction and should be generalized into one
standard:

- [ADR 0034](./0034-platform-backend-shared-contract.md): per-OS backends
  implement a shared, tag-free contract (interface + implementors).
- The [type-safe database access rule](../../AGENTS.md) (sqlc): domain rows are
  typed structs, never `any`.

We want every part of the codebase to follow the same shape so behavior is
swappable, testable, and checked by the compiler rather than at runtime.

## Decision

Adopt a **domain-driven, interface-first, type-safe** architecture.

### 1. Organize by domain (bounded context)

Each area of responsibility is a package that owns its domain: `policy`,
`credentials`/secret broker, `mcpproxy`, `shield`, `agents`, `store`,
`telemetry`, `netproxy`. A domain owns its types and exposes a small public
surface; internals stay unexported. Names follow the ubiquitous language of the
domain (`Decision`, `Grant`, `Shield`, `Hook`, `Verdict`) -- the same words in
code, docs, and UI.

### 2. Interface-first at the seams

Cross-domain dependencies go through an **interface**, and the interface is
defined by the **consumer** (Go idiom: "accept interfaces, return structs"). The
daemon depends on a `HookEngine` interface, not a concrete engine; the store is
consumed as `EventStore`/`ReadOnlyStore`, not `*sqliteStore`. Design the
boundary contract before the implementation.

Implementors are concrete types satisfying the interface. When more than one
implementor exists (per-OS shields, per-agent installers), select them via a
**registry** or build-tag file split (ADR 0034) -- never a `switch` on a string
scattered across call sites.

**Guardrail (so this stays idiomatic, not Java-in-Go):** an interface belongs at
a *seam* -- a boundary you test across, swap, or vary by platform. Do not add an
interface (or a one-method wrapper) for a single-implementor internal helper
that has no seam; that is indirection without benefit. "Interface-first" means
*design the contract first*, not *one interface per struct*.

### 3. Type-safe throughout

- Domain data is modeled with **named types, structs, and enums** -- never
  `interface{}`/`any`, and never a bare `string`/`int` where a domain concept
  exists (use `Action`, `Verdict`, `Tier`, etc.).
- `any`/`map[string]any` is permitted **only** at true serialization boundaries
  (JSON hook I/O, wire protocols) and must decode into a typed struct
  immediately -- domain logic never operates on untyped bags.
- SQL goes through sqlc; dynamic queries still scan into typed structs (existing
  rule).
- Prefer compile-time errors to runtime ones: exhaustive enums, constructor
  functions that validate, and interfaces that make illegal states
  unrepresentable.

### 4. Per-OS variation is a special case

The interface + implementor split by build tag (ADR 0034) is this pattern
applied to the OS axis. Any new multi-OS binary implements a shared contract;
each binary compiles only the files for its target.

## Consequences

- **Testability:** seams take fakes/mocks, so domains are unit-testable without
  the daemon, filesystem, or network (already true for `policy`, `store`).
- **Swappability:** new implementors (a Tier-2 microVM shield, an alternate
  store, a new agent) drop in behind the existing interface with no call-site
  churn.
- **Safety:** the compiler catches wrong types and missing enum cases; fewer
  `any`-shaped runtime surprises, which matters most on the fail-closed
  credential and policy paths.
- **Cost:** more upfront boundary design, and the discipline to *not* over-
  abstract. Migration is opportunistic -- touch a domain, bring it up to the
  standard; do not rewrite working code wholesale for its own sake.
- New code and reviews are held to this shape; deviations need a reason in the
  PR (or a superseding ADR).
