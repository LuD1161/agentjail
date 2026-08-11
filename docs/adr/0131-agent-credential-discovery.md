# ADR 0131 — Agent credential discovery

- **Status:** Accepted
- **Date:** 2026-08-10
- **Deciders:** agentjail-core
- **Linear:** AGE-275, AGE-276, AGE-277, AGE-278, AGE-279
- **Related:** [ADR 0004-credential-broker-tier1](0004-credential-broker-tier1.md), [ADR 0032-phantom-credentials](0032-phantom-credentials.md), [ADR 0129-credentialed-cli-bootstrap](0129-credentialed-cli-bootstrap.md)

## Context

ADR 0129 initially required a trusted launcher to select one broker identity
before starting the coding agent. That proves CLI compatibility but does not
serve a task where the user names one of several AWS accounts or Kubernetes
contexts after the session starts. AgentJail cannot infer which identity the
user intended, and silently selecting the first broker entry would repeat the
multi-identity failure recorded in GOTCHAS 53.

The user wants the coding agent to interpret the task. AgentJail should expose
available non-secret identities, receive a request for one exact identity with
a reason, and apply policy to that request. The initial OSS milestone has no
credential-policy language or human approval workflow yet. Every typed local
broker credential is therefore approved, but wildcard authorization must not
be confused with identity selection.

Returning a static credential directly exposes it to the agent and its MCP
transcript. That is an accepted bootstrap limitation. AWS STS/JIT issuance is
the next phase; phantom values replaced or re-signed by the tunnel are later.

## Decision

### Discover, then request exactly

AgentJail exposes two MCP tools:

1. `list_credentials` returns typed non-secret descriptors, optionally filtered
   by tool. A descriptor contains stable ID, tool, kind, label, account/context,
   and current approval posture.
2. `request_credential` requires one exact ID and a bounded non-empty reason.
   It returns that record's standard environment/file presentation directly.

AgentJail never selects an identity. Agent-native session instructions require
the coding agent to list first, select from the user's stated target, and ask
the user when multiple descriptors remain plausible.

### Typed encrypted records

New `agentjail credential set` imports wrap material and non-secret discovery
metadata in one versioned record before the existing encrypted store persists
it. Legacy entries are discoverable only for the known `aws/`, `kube/`,
`kubernetes/`, `github/`, and `gh/` namespaces and only after their material
passes the strict adapter decoder. Arbitrary raw secrets never become visible
to the agent by inference.

### Session capability, not host control authority

The shield registers a random session capability with the broker before
Landlock or Seatbelt is applied. The capability authorizes only typed inventory
discovery and exact credential requests for its session. It cannot set, delete,
or enumerate arbitrary raw secrets. The global control token remains outside
the sandbox.

The current authorizer is a named bootstrap implementation equivalent to:

```yaml
credential_access:
  discover: ["*"]
  auto_approve: ["*"]
```

This notation documents behavior; it does not add the later policy schema.
Specific rules will precede wildcard fallback when AGE-29 implements policy.

### Fail-closed request audit

Discovery is audited without values. Before decrypting or returning material,
the broker durably emits `credential.access_requested`; an unavailable or
failing audit store denies issuance. Approval, issuance, and denial events carry
session/project/agent, exact credential ID, non-secret target, bounded reason,
bootstrap policy result, and a fingerprint only. Values never enter audit or
structured logs.

## Consequences

Multiple AWS accounts and Kubernetes contexts are supported without an
AgentJail default. The agent, not the broker, resolves user intent. Later human
approval, JIT issuers, and phantom tunnel transformation replace policy or
issuance components without changing discovery or exact request semantics.

Static material is present in the MCP result and can be retained by the coding
agent's local transcript. Operators must use credentials whose native IAM/RBAC
authority is acceptable until JIT and phantom phases land. AgentJail documents
this exposure and does not claim secret non-disclosure for the bootstrap.
