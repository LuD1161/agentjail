# ADR 0020 — Environment audit at launch

- **Status:** Accepted
- **Date:** 2026-06-19
- **Deciders:** agentjail-core
- **Related:** [ADR 0001](0001-os-sandbox-enforcement-layer.md) (OS sandbox), [ADR 0024](0024-env-stripping-at-launch.md) (env stripping)

## Context

Even with Landlock/Seatbelt filesystem restrictions, netproxy network
filtering, and env stripping, the agent's effectiveness depends on the
host environment being reasonably configured. On an over-permissive EC2
instance (AdministratorAccess role, IMDSv1, open security groups, running
as root), the shield's containment is less effective — not because the
shield fails, but because the blast radius of a foot-gun is larger.

The design note (§9.5, §13) identifies this scenario explicitly: "the
shield is the boundary, not the EC2 instance." The shield mitigates the
risk, but the user should be warned about the environment so they can
fix it (e.g. switch to IMDSv2, use a scoped IAM role, run as non-root).

## Decision

Add a best-effort environment audit that runs **before** shield setup
(before Landlock/Seatbelt, before netproxy, before env stripping).  The
audit is non-blocking by default: warnings are printed to stderr and the
agent is still launched.  `--audit-strict` makes critical findings abort
the launch.

### Checks

| Check | Severity | Method | What it detects |
|---|---|---|---|
| Root | Critical | `os.Getuid() == 0` | Running as root (the shield doesn't need root) |
| Ambient cred files | Warning | `os.ReadFile("~/.aws/credentials")` | Credential files exist and are readable on the host |
| Ambient env vars | Warning | `os.Getenv("AWS_SECRET_ACCESS_KEY")` | Credential env vars are set (before stripping) |
| IMDS version | Critical | HTTP to `169.254.169.254` | IMDSv1 is enabled (IMDSv2 token request fails, IMDSv1 responds) |
| IAM role | Critical/Info | IMDS `/iam/security-credentials/` | Instance role name contains "admin" (heuristic for AdministratorAccess) |

### IMDS probing

The audit probes the EC2 Instance Metadata Service (IMDS) at
`169.254.169.254` with a 2-second timeout:
1. **IMDSv2**: `PUT /latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds: 300`.
   If successful, IMDSv2 is available and the token is used for subsequent
   requests.
2. **IMDSv1**: If IMDSv2 fails, try `GET /latest/meta-data/` without a
   token.  If this succeeds, IMDSv1 is enabled — a critical finding.
3. **Role name**: `GET /latest/meta-data/iam/security-credentials/` returns
   the instance role name.  If it contains "admin" or "administrator", a
   critical finding is emitted (heuristic — a proper check would call
   `iam:list-attached-role-policies`, but that requires AWS credentials
   and SigV4 signing, which is out of scope for the best-effort audit).

On non-EC2 hosts, all IMDS connections timeout within 2 seconds and the
checks are skipped silently.

### CLI flags

| Flag | Description |
|---|---|
| `--audit-json=PATH` | Write findings as JSON to PATH (use `-` for stdout) |
| `--audit-strict` | Refuse to launch if critical findings are detected |

### Security group egress

The task mentions checking for `0.0.0.0/0` egress rules.  This requires
calling the AWS EC2 API (`describe-security-groups`), which needs AWS
credentials and SigV4 signing.  This check is **not implemented** in the
initial audit — it's a future enhancement that would require either the
AWS SDK or extending the SigV4 signer (from `cmd/agentjail-secrets/sigv4.go`)
to handle EC2 API calls.

## Consequences

**Positive:**
- Users are warned about over-permissive environments before the agent
  launches, giving them a chance to fix the configuration (switch to
  IMDSv2, use a scoped role, run as non-root).
- `--audit-strict` provides a fail-closed mode for high-security
  deployments where critical findings should block the launch.
- `--audit-json` enables machine-readable audit output for CI/CD
  integration and compliance reporting.
- The audit runs before shield setup, so it's fast and doesn't interfere
  with sandbox restrictions.

**Negative:**
- The IAM role check is a heuristic (role name contains "admin") — it
  can't detect `AdministratorAccess` attached via a policy ARN that
  doesn't contain "admin" in the role name.  A proper check requires
  AWS API calls.
- Security group egress check is not implemented (needs AWS API).
- IMDS probing adds ~2 seconds to the launch on non-EC2 hosts (connection
  timeout).  On EC2, it's sub-second.
- `--audit-strict` may block legitimate launches in environments where
  running as root is intentional (e.g. containerized deployments).  Users
  can omit the flag in those cases.

**Implementation notes:**
- `cmd/agentjail-shield/audit.go` — audit checks and output formatting
- `cmd/agentjail-shield/main.go` — `--audit-json` and `--audit-strict` flags
- Tests: root detection, ambient cred file detection, ambient env var
  detection, critical finding detection, JSON output, warning output,
  IMDS unreachable handling (skip on non-EC2).
