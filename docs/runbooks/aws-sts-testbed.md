# AWS STS testbed runbook

Use this workflow when a macOS credential release assertion must prove real AWS
behavior through AgentJail and a real Codex session. It creates only temporary,
private AWS resources and a disposable Tart clone. It is not part of the
ordinary offline `credentialed-cli` fixture.

## Trust boundary

The source AWS profile stays in the operator's normal host terminal. Neither
its access keys nor its profile files enter Tart, the coding-agent session, the
repository, or the evidence package. The harness accepts only a one-hour,
least-privilege role session imported into the guest's AgentJail broker over the
existing encrypted SSH connection.

Do not paste AWS values into Codex, write them to a handoff file, copy
`~/.aws`, enable shell tracing, or use a root credential inside the guest. The
operator command creates and removes a disposable bootstrap IAM user solely to
avoid root-session `AssumeRole` restrictions. That user's trust is constrained
by its exact principal ARN, and it is deleted before the test starts.

## Run

From the repository root, start the orchestrator:

```sh
bash test/testbed/run-aws-sts-live.sh
```

It clones `golden-macos-mitm`, provisions the real install path, installs a
guest-only import helper, and stops at `ACTION REQUIRED`. Run the one printed
command in a separate normal terminal. For example:

```sh
AWS_PROFILE=smo \
AWS_E2E_AWS_BIN="$HOME/.pyenv/versions/3.11.6/bin/aws" \
bash test/testbed/aws-sts-provision.sh --guest aws-sts-live
```

`AWS_PROFILE` is case-sensitive. Set `AWS_E2E_AWS_BIN` when the default AWS CLI
is broken or belongs to an incompatible Python installation. A profile can
exist only in `~/.aws/credentials`; a matching config section is not required
unless it needs region, output, SSO, role, or other configuration. This harness
passes its region explicitly.

To print different defaults in the operator instruction:

```sh
AWS_E2E_PROFILE_HINT=my-profile \
AWS_E2E_AWS_BIN_HINT=/absolute/path/to/aws \
bash test/testbed/run-aws-sts-live.sh
```

Leave the operator terminal open. It waits for the harness finish signal, then
removes the exact marker, inline policies, role, bootstrap identity, and two
buckets. It also cleans automatically after 45 minutes or interruption. A
cleanup failure is a test failure and reports the unique run ID for bounded
manual inspection.

Before creating the VM or asking for AWS credentials, the runner verifies the
Codex cache, printed AWS binary, golden image, every helper, and a writable,
gitignored report root. Post-handoff evidence directories are therefore not a
late runtime dependency.

## Required proof

The orchestrator fails unless all of these execute with zero SKIPs:

- the guest has no ambient AWS profile and cannot identify itself outside a
  broker session;
- a direct brokered AWS CLI resolves to the expected assumed role;
- only the named target bucket can be listed and it contains an unpredictable
  marker;
- the decoy bucket and target-bucket write are both denied, with no denied
  object created;
- the identified Codex binary discovers and requests the exact broker record,
  then stops without copying static credential values into a shell command;
- a separate direct broker session resolves the session-only AWS symlink and
  executes the positive and negative AWS operations. This deliberately follows
  the user-facing contract: Codex proves discovery and exact request; the direct
  session proves the issued credential works and is least-privilege;
- SQLite proves ordered discovery, request, approval, issuance, and revocation
  for the same credential session;
- bounded command outputs and the raw Codex stream contain no exact STS value;
- temporary credential-session directories, guest auth, AWS resources, and the
  disposable VM are removed.

The direct guest session proves its write receives `AccessDenied`. After the
scenarios finish and before deleting either bucket, the external provisioner
uses the source profile to perform an authoritative `HeadObject` absence check
for that exact denied key. The absence boolean and resource cleanup have
separate fields in the structured cleanup result; both must pass.

Structured SQLite records and JSON results are the assertion sources. Terminal
output is diagnostic only. Reports are written beneath the gitignored
`test/testbed/reports/aws-sts-<run-id>/` directory with a neutral independent
review prompt and checksums. Never move raw casts, databases, agent transcripts,
or unfiltered command output into a committed evidence directory.

## Failure guide

| Failure | Likely cause | Bounded action |
|---|---|---|
| AWS CLI fails loading `pyexpat` | Homebrew/Python ABI mismatch | Point `AWS_E2E_AWS_BIN` at a known-working AWS CLI; do not reinstall blindly during evidence capture. |
| `Invalid principal in policy` | IAM propagation or a deleted principal was embedded directly | Use this harness's account-root trust plus exact `aws:PrincipalArn`; do not replace it with a newly-created principal ARN. |
| Role cannot be assumed immediately | IAM propagation | The provisioner retries the exact `AssumeRole` call for one minute. Preserve the final stderr only as local diagnostics. |
| Codex prose says it requested a credential but ordered SQLite evidence is absent | Agent did not use the intended broker path | Fail. Do not accept its prose as a substitute. |
| AWS calls pass but SQLite lifecycle is absent | Broker/audit path was bypassed or logging is defective | Fail and trace the structured database path; do not grep terminal output. |
| Cleanup status is missing or failed | Operator command exited or AWS cleanup was incomplete | Inspect only resources containing the reported run ID, remove them, and retain the run as FAIL. |
| Any required assertion is SKIP | The live path did not execute | Fail. Offline fixture success is not live AWS evidence. |

S3 bucket names derive from a separate lowercase form of the run ID. Keep the
mixed-case run ID for evidence correlation; never use it directly as a bucket
name. The provisioner records a bucket as cleanup-owned immediately after the
create call, before applying public-access and encryption controls, so a later
hardening failure cannot orphan it.

## Scope

This workflow proves Codex credential discovery and exact request, direct
session-only delivery, AWS identity, least-privilege enforcement, negative
outcomes, audit ordering, leakage checks, and bounded cleanup. ADR
0140-generic-credentials explicitly accepts that static session material is
visible to the coding agent; this harness prevents an unnecessary second copy in
a shell transcript. It does not prove the Darwin tunnel or MITM path; run the
strict tunnel scenario separately, serially, because macOS has one global
Network Extension configuration.
