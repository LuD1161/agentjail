# ADR 0143 — Retire sensitive-path shell heuristic

## Status

Accepted. Supersedes the decision in ADR 0111-shield-attested-downgrade
to retain `command_policy/no-bash-touch-sensitive-path`, and the corresponding
shell-text guard in ADR 0001-os-sandbox-enforcement-layer.

## Context

The old rule inferred filesystem access from sensitive-looking strings anywhere
in a Bash command. Harmless repository searches, documentation, and certificate
inspection received hard denials. Tests asserted the matcher rather than whether
the command attempted the prohibited effect. Special-casing Git commit messages
did not solve the underlying problem.

The sandbox already handles configured filesystem restrictions at the actual
file operation, including operations performed by subprocesses. Hook policy
evaluation remains useful for native file tools, command policies, MCP policies,
approvals, and audit records.

## Decision

Retire `command_policy/no-bash-touch-sensitive-path` from both active policy
bundles and the active CLI rule registry. Remove its matching helpers and its
`any_dangerous_pattern` clause so benign commands do not merely fall back to
`ask`. Preserve the old source as [legacy documentation](../legacy/sensitive-path-rule.md),
outside all loaded and installed policy directories. Historical audit aliases
and display handling remain supported.

Do not introduce an environment-based exemption or suppress other candidates.
The remaining OPA policies decide the tool call normally. Policy allow means
permission to attempt the operation, not proof that filesystem access succeeded;
execution outcomes remain separate (ADR 0112-final-action-outcome).

Retirement applies to the shipped rule in every launch mode. Hook-only launches
lose this best-effort shell-text check; `--no-sandbox` does not provide a
replacement filesystem boundary. Existing installations receive the change
when their installed core policy bundle is updated.

## Consequences

- Searches and inert text no longer trigger a secret-path denial or approval
  solely because they mention a protected path.
- OS sandbox restrictions, native Read/Write/Edit policies, other command
  policies, self-protection, MCP evaluation, and approvals remain unchanged.
- Sandbox protection is the configured platform contract, not every pattern
  the old heuristic matched. Linux Landlock has no basename-pattern deny
  primitive; macOS secret-form `.env` patterns deny writes, not reads. Files
  inside an allowed workspace are not necessarily blocked because their names
  look secret. Native file-tool rules do not mediate Bash I/O. This is an
  explicit policy reduction, not a claim of identical coverage.
- Old decisions retain their original rule ID and rendering. The archive is
  reference material, not an optional installable policy pack.

Validation covers harmless mentions, shell I/O policy delegation, retained
native file and command denials, source/embedded parity, and existing sandbox
smoke checks. Tests do not use host credential contents.
