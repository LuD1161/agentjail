# 0017 — AWS policy pack: Tier 1 intent rules + per-account posture

Status: Accepted

Covers Phase 1 items P1.1 (AWS intent Rego rules), P1.2 (per-account posture
config), and P1.3 (`samples/configs/policy-aws.yaml`).

## Context

Today agentjail's AWS coverage at Tier 1 is limited to a file deny on
`~/.aws/` (in `file_policy/sensitive_credential`) and a Bash sensitive-path
deny that catches `cat ~/.aws/credentials`. There are no rules for the AWS
CLI itself: an agent can run `aws s3 rb --force prod-logs`, `aws rds
delete-db-instance`, or `aws iam delete-role` and the hook returns
`command_policy/default-allow`.

The product's threat model is **foot-gun, not adversary** (research note §1):
a helpful agent that deletes the wrong bucket because the prompt was
ambiguous. The verdict matrix that follows is: reads (non-secret) → allow,
create/update → ask, delete/destructive → deny.

Two structural facts shape where these rules live:

1. **Tier 1 sees the declared command string, not bytes.** An AWS CLI call
   (`aws s3 rb --force`) is visible; an SDK call
   (`boto3.client('s3').delete_bucket(...)` in a script) is not — the hook
   only saw `python script.py`. The research note §6.1 cautions that
   byte-pattern rules for cloud verbs are fragile and "belong at Tier 2."
2. **Not every AWS account is the same.** A user wants to declare *this*
   account is a sandbox where CUD is fine and *that* one is prod where
   delete is locked. This is a config overlay, not new Rego logic per
   account (research note §3).

## Decision

### Tier 1 AWS intent rules (P1.1)

Ship AWS CLI intent rules at Tier 1 as an opt-in library rule
(`agentpolicy/policies/library/no_aws_destructive.rego`):

- **Deny** destructive verbs: `aws s3 rb`, `aws s3api delete-*`,
  `aws <svc> delete-*`, `aws ec2 terminate-*`, `aws ec2 release-address`.
- **Ask** on mutating verbs: `aws <svc> create-*`, `aws ec2 run-instances`,
  `aws s3 cp`.
- **Allow** reads (no candidate; `command_policy/default-allow` fires for
  `aws s3 ls`, `aws ec2 describe-instances`, etc.).

The rules use `regex.match` over `input.tool_input.command`, the same
pattern as the existing `command_policy` deny rules. They are generalized by
verb family (`aws <svc> delete-*`) so new AWS services with the same verb
shape are covered without a rule edit.

### Posture deferral (the deny > ask > ask resolver constraint)

The resolver is deny > ask > allow. A deny candidate always beats an ask, so
a posture rule cannot *downgrade* a deny to an ask for a sandbox account by
emitting a competing candidate. The design therefore centralizes the verdict:
exactly one emitter fires per AWS command.

`no_aws_destructive.rego` emits the **fail-safe default** (PROD: destructive
→ deny, create → ask) **only when no AWS posture config exists**
(`not data.agentjail.config.aws`). When an AWS posture config is present
(P1.2), the rule defers and `aws_policy/*` computes the posture-aware
verdict (sandbox → delete asks, locked → create denies, prod → delete
denies). This keeps P1.1 self-contained and lets P1.2 add posture without
modifying the P1.1 rule.

### Per-account posture config (P1.2)

Add an `aws` section to `policy.yaml`:

```yaml
aws:
  default_posture: prod          # fail-safe: unknown account treated as prod
  accounts:
    "123456789012":
      posture: sandbox           # sandbox | prod | locked | custom
    "987654321098":
      posture: prod
  resources:
    "arn:aws:s3:::prod-*": { posture: locked }   # resource-level override
```

Posture → verdict matrix (research note §3.2):

| Posture | Read | Create | Update | Delete |
|---|---|---|---|---|
| `sandbox` | allow | allow | allow | ask |
| `prod` | allow | ask | ask | **deny** |
| `locked` | allow | deny | deny | deny |
| `custom` | per-account `allow_cud` / `deny_delete` / `read_only` flags |

`default_posture: prod` is the fail-safe — an account the user did not
explicitly bless is treated as prod (delete locked). The daemon extracts the
account from `--profile` (resolving `~/.aws/config`) and injects it as
`input.aws_account` before Rego eval; `aws_policy/*` reads
`data.agentjail.config.aws.accounts[acct].posture`.

### Sample config (P1.3)

`samples/configs/policy-aws.yaml` demonstrates the pack: AWS MCP
`allowed`/`blocked`, per-server `allowed_tools` (allow `List*`/`Get*`/
`Describe*`, deny `Delete*`/`Terminate*`), account postures, and a network
allowlist for typical AWS endpoints.

## Consequences

+ Catches the CLI foot-gun (`aws s3 rb --force`, `delete-db-instance`) at the
  hook before it runs — the product's actual job.
+ One fail-safe default (`prod`) means an unknown account can't be
  accidentally treated as a sandbox.
+ Per-account posture is config, not per-account Rego — users add accounts
  without writing rules.
+ The posture-deferral guard keeps the Tier 1 rule and the posture rule from
  both firing (which the deny > ask > ask resolver would resolve wrongly).
- **Tier 1 limit (acknowledged):** SDK-driven calls
  (`boto3.delete_bucket()` in a script) bypass these rules — the hook only
  saw `python script.py`. The structural fix is the Tier 2 wire gateway
  (ADR 0016, Rego over `input.aws.action`); the operational backstop today
  is IAM-scoped credentials (an inline session policy that denies
  `Delete*`/`Terminate*` on prod accounts). This rule does not claim to
  catch the SDK case.
- Regex over the command string is bypassable by obfuscation (`eval $(...)`,
  variable expansion). The shield (Tier 1.5, Landlock/Seatbelt) is the
  backstop for obfuscated commands; the AWS CLI is a cooperative-agent
  surface, not an adversarial one.
- Posture extraction from `--profile` depends on `~/.aws/config`, which the
  agent cannot read (`file_policy/sensitive_credential` denies `~/.aws`).
  The daemon (not the agent) reads it; ambiguous/missing profile →
  `default_posture`.
