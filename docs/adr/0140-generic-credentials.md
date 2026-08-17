# ADR 0140 — Generic credentials

- **Status:** Accepted
- **Date:** 2026-08-16
- **Deciders:** agentjail-core
- **Supersedes:** [ADR 0129-credentialed-cli-bootstrap](0129-credentialed-cli-bootstrap.md), [ADR 0131-agent-credential-discovery](0131-agent-credential-discovery.md)
- **Related:** [ADR 0004-credential-broker-tier1](0004-credential-broker-tier1.md), [ADR 0032-phantom-credentials](0032-phantom-credentials.md), [ADR 0137-credential-residue](0137-credential-residue.md)

## Context

The unreleased credential bootstrap modeled AWS CLI, kubectl, and GitHub CLI as
credential identities. A stored record carried a mandatory tool, provider kind,
account, and context. Launch then required `--credential=TOOL=NAME`, filtered
discovery by tool, and pinned one executable for each selected credential.

That model combined three independent concepts: the user-chosen credential
identity, how bytes enter a session, and which application consumes them. It
made a Slack token or an unfamiliar internal client impossible without a new
AgentJail adapter. Names such as `aws-read-only-prod` also looked authoritative
even though only provider IAM/RBAC determines whether a credential is read-only.

Direct bootstrap delivery already makes static material readable to the
sandboxed agent. Binding it to one executable did not stop that agent from
passing the value to another process. The tool field therefore added vocabulary
and drift without providing the authority boundary it appeared to provide.

## Decision

### Credential identity is opaque

A credential has one arbitrary, exact user-chosen ID plus optional non-secret
label and tags. AgentJail does not parse those fields to infer a provider,
account, environment, permission level, or intended command. Tags are discovery
metadata, never policy authority. Ambiguous intent remains a user/agent decision;
the broker selects nothing implicitly.

The public launch syntax is `agentjail run --credential ID -- <command>`. The
agent-facing MCP inventory has no tool filter. `request_credential` requires an
exact listed ID; its non-secret audit reason is optional.

### Delivery is generic and explicit

The encrypted record stores a provider-neutral delivery bundle:

- environment variables captured by name from the trusted launch shell;
- file content copied into a mode-0600 private session file and exposed through
  an environment variable; and
- private mode-0700 session directories for future import helpers.

The CLI never accepts a secret value in argv. `--from-env NAME` is repeatable,
`--from-file ENV=PATH` is repeatable, and `--from-stdin ENV` reads one value.
Optional future provider importers may validate or translate source material,
but their output is this generic record. They do not become credential identity
or authorization fields.

Bindings that can replace the executable search path, dynamic loader, sandbox
control plane, proxy/TLS trust, shell startup, Python module path, or SSH agent
are rejected. Duplicate output names and unsafe session filenames also fail
before encrypted storage.

### Preserve the security machinery

Encrypted storage, exact selection, random session capabilities, durable
fail-closed request/issuance audit, value redaction, fingerprints, private file
modes, expiry, revocation, and cleanup remain unchanged. Raw broker values and
the earlier unreleased version-1 typed records are not inferred as agent-visible
credentials; users re-import them into the generic format.

Credential set/list/remove operations use typed broker actions. Listing hides
raw and obsolete entries, while set/remove refuse to overwrite or delete a
non-credential entry that happens to use the same name.

Static material is available to the selected sandbox session, not confined to a
single executable. Provider IAM/RBAC remains the effective authority boundary.
JIT and phantom delivery can later reduce that exposure without changing exact
credential identity.

## Consequences

- Any credential shape can use the broker without an AgentJail code change.
- Names and tags stay honest: they describe user intent but do not claim verified
  permissions.
- The CLI and MCP contracts are smaller and do not privilege three vendors.
- Users must explicitly describe environment/file delivery when importing a
  credential.
- The shield no longer resolves or pins AWS, kubectl, or GitHub executables for
  credential bootstrap. Other sandbox and policy controls still apply to every
  process in the session.
- Existing unreleased version-1 records are hidden rather than ambiguously
  converted; re-import is required before the next release.
