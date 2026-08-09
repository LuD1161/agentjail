# ADR 0129 — Credentialed CLI bootstrap

- **Status:** Accepted
- **Date:** 2026-08-09
- **Deciders:** agentjail-core
- **Linear:** AGE-275, AGE-276, AGE-277, AGE-278, AGE-279
- **Related:** [ADR 0004-credential-broker-tier1](0004-credential-broker-tier1.md), [ADR 0023-secret-server](0023-secret-server.md), [ADR 0034-platform-backend-shared-contract](0034-platform-backend-shared-contract.md), [ADR 0067-control-plane-token-auth](0067-control-plane-token-auth.md)

## Context

The shield strips ambient credentials and denies the agent direct access to
host stores such as `~/.aws`, `~/.kube`, and `~/.config/gh`. The encrypted
AgentJail broker can already hold secrets and can issue some scoped credentials,
but ordinary CLIs still cannot consume a selected broker entry seamlessly.

This milestone is deliberately earlier than credential policy and general JIT
issuance. An OSS user may put static or root credentials in the local encrypted
broker and explicitly select one before launching a shielded session. Existing
AWS STS issuance remains usable where a broker entry already contains its
configuration, but the bootstrap must not require it.

Putting issuance and CLI presentation in one backend would make every future
issuer—JIT, Vault, OpenBao, or a SaaS source—reimplement AWS environment names,
kubeconfig delivery, and GitHub CLI behavior. Conversely, making the shield
parse every provider's stored secret would turn the sandbox launcher into a
credential backend.

The supported external contracts were verified against primary documentation
on 2026-08-09:

- AWS CLI uses `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, optional
  `AWS_SESSION_TOKEN`, and region environment variables; environment credentials
  override shared credential files. Source: [AWS CLI environment variables](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html).
- `kubectl` uses the file named by `KUBECONFIG`; when it names one file, that
  file supplies the effective configuration instead of the default
  `$HOME/.kube/config`. The v1 format also permits executable authentication
  plugins and credential file references. Sources: [Kubernetes kubeconfig organization](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/),
  [Kubernetes kubeconfig v1 API](https://kubernetes.io/docs/reference/config-api/kubeconfig.v1/).
- GitHub CLI uses `GH_TOKEN` for `github.com`, and `GH_CONFIG_DIR` selects its
  configuration directory. Source: [GitHub CLI environment](https://cli.github.com/manual/gh_help_environment).

The local compatibility baseline was AWS CLI 2.9.19, kubectl 1.36.3, and GitHub
CLI 2.67.0. The clean Linux gate additionally recorded AWS CLI 2.36.19,
kubectl 1.36.3, and GitHub CLI 2.45.0.

## Decision

### Separate issuance from presentation

An issuer returns typed, canonical credential material. A tool adapter consumes
that material and returns only the environment variables and session files the
CLI needs. The shared contract lives in `internal/credentialtools`.

The initial issuer is the local encrypted broker:

1. An unsandboxed launch explicitly selects `tool=credential-name`.
2. The shield authenticates to the broker before applying Landlock or Seatbelt.
3. The broker retrieves or issues the credential and returns canonical material.
4. The registered adapter presents it for the selected CLI.
5. The shield injects the result into only that session.

The child receives `AGENTJAIL_CREDENTIAL_TOOLS` containing only the ready tool
IDs, in addition to the non-secret startup notices. Credential names and values
are not encoded in that discovery variable.

A future issuer can return the same material without changing an adapter. A new
CLI needs one adapter and does not change broker transport or sandbox launch
logic.

### Initial adapters

| Tool | Binary | Delivery |
|---|---|---|
| AWS CLI | `aws` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, optional `AWS_SESSION_TOKEN` and `AWS_DEFAULT_REGION`; force `AWS_EC2_METADATA_DISABLED=true` |
| Kubernetes | `kubectl` | one strictly validated, self-contained, mode-0600 session kubeconfig and `KUBECONFIG=<that exact file>` |
| GitHub CLI | `gh` | `GH_TOKEN`, `GH_PROMPT_DISABLED=1`, and an empty private `GH_CONFIG_DIR` |

The GitHub adapter is the third conformance case: it proves that the shared path
is not an AWS/Kubernetes conditional hidden in the shield.

### Static credentials now, JIT later

The direct static path is not described as least privilege. The credential may
be a root or broadly privileged credential, and its value is visible to the
sandboxed agent through its environment or generated file. Provider IAM/RBAC
is the effective scope. Status, logs, audit events, argv, and readiness notices
must contain only tool names, broker entry names, and fingerprints—never values.

Credential policy, access-mode declarations, company policy distribution, and
general JIT issuance remain separate later milestones. The adapter contract is
the compatibility seam for those features, not an early implementation of
them.

### Pre-launch binary and file lifecycle

Every selected adapter resolves its exact executable before sandbox activation.
A missing, non-regular, changed, working-tree, or temporary-directory executable
refuses launch; the shield never injects a credential into an agent-writable CLI
lookalike or guesses a replacement after entering the sandbox. Per-OS backends
translate the same resolved-tool contract into their filesystem primitive.

Generated files live in a private mode-0700 session directory, use mode 0600,
and are removed by the supervising shield after normal exit. Startup also
removes abandoned credential session directories from terminated sessions so a
crash does not leave credentials indefinitely. The credential source file and
host credential stores are never mounted.

## Consequences

The immediate OSS path works with credentials already held locally and does not
depend on SaaS or a policy service. AWS, Kubernetes, and GitHub share the launch,
audit, cleanup, and binary-resolution path while retaining their standard CLI
interfaces.

The agent can read credentials delivered to its own session. Static root
credentials therefore carry their original blast radius until scoped/JIT
issuance is implemented. Static kubeconfig import rejects executable/auth
plugins and path-backed CA, token, certificate, and key material; only inline
credentials cross the broker boundary.

Keeping the local static decoder alongside the adapter contract adds a small
compatibility surface for existing broker entries. It is intentionally not the
issuer interface: Vault/OpenBao/JIT integrations should produce canonical
material directly rather than emulating encrypted-store serialization.
