# Package agentjail — library rule: no-aws-destructive
#
# WHAT IT BLOCKS
# --------------
# AWS CLI commands that are destructive (delete/terminate) or mutating
# (create/provision/transfer). This is an intent rule: it pattern-matches the
# declared `aws` CLI command string at the hook layer, before the command runs.
#
#   DENY (destructive, irreversible):
#     aws s3 rb [--force] <bucket>            remove bucket
#     aws s3api delete-bucket|delete-objects  S3 delete family
#     aws <svc> delete-*                      IAM/RDS/CloudFormation/Lambda/… delete family
#     aws ec2 terminate-*                     terminate instances
#     aws ec2 release-address|release-elastic-ip   release EIP
#
#   ASK (mutating, side effects / cost):
#     aws <svc> create-*                      IAM/RDS/… create family
#     aws ec2 run-instances                   provision instances
#     aws s3 cp                               object transfer (upload overwrite / download)
#
#   ALLOW (read, non-secret): no candidate here — falls through to
#     command_policy/default-allow (aws s3 ls, aws ec2 describe-instances, …).
#
# THREAT MODEL
# ------------
# Foot-gun, not adversary. A helpful agent that runs `aws s3 rb --force` on the
# wrong bucket, or `aws rds delete-db-instance` thinking it was staging. The
# verdict matrix is: reads allowed (non-secret), create/update → ask,
# delete/destructive → deny.
#
# POSTURE AWARENESS
# -----------------
# When a per-account AWS posture is configured in policy.yaml
# (`data.agentjail.config.aws`), these default candidates DEFER to the posture
# rule (aws_policy/*, added in P1.2) so a sandbox account can ask on delete
# instead of deny, and a locked account can deny create. When no AWS posture
# config exists, the fail-safe default is PROD: destructive → deny,
# create → ask. The guard is `not data.agentjail.config.aws`.
#
# TIER 1 LIMIT (acknowledged)
# ---------------------------
# This rule pattern-matches the CLI command string. SDK-driven calls
# (`boto3.client('s3').delete_bucket(...)` in a script) are invisible to the
# hook — the hook only saw `python script.py`. The structural fix for the SDK
# case is the Tier 2 wire gateway (Rego over `input.aws.action`, ADR 0016); the
# operational backstop today is IAM-scoped credentials (an inline session
# policy that denies `Delete*`/`Terminate*` on prod accounts). This rule
# catches the CLI foot-gun, which is the product's actual job.
#
# HOW TO ENABLE
# -------------
#   agentjail policy enable no_aws_destructive
#   kill -HUP $(pgrep -f agentjail-daemon)

package agentjail

import future.keywords.if
import future.keywords.contains

# AWS CLI command classification (_aws_cmd, _aws_is_bash, _aws_destructive,
# _aws_create) is defined in the core aws_posture.rego rule (same package) and
# reused here. aws_posture.rego is always loaded (core), so these helpers are
# always available when this library file is enabled.

# ---------------------------------------------------------------------------
# Default-posture candidates.
#
# Fire ONLY when no AWS posture config exists (`not data.agentjail.config.aws`).
# When an AWS posture config is present, aws_policy/posture (aws_posture.rego)
# computes the posture-aware verdict so a sandbox account can ask on delete
# and a locked account can deny create. The fail-safe default here is PROD:
# destructive -> deny, create -> ask.
# ---------------------------------------------------------------------------

candidate contains r if {
	_aws_is_bash
	c := _aws_cmd
	_aws_destructive(c)
	not data.agentjail.config.aws
	r := {
		"action":  "deny",
		"rule_id": "library/no-aws-destructive",
		"reason":  "destructive AWS CLI command (delete/terminate) denied — irreversible operation; confirm with a human or run against a sandbox account",
		"impact":  "would run a destructive AWS CLI command",
	}
}

candidate contains r if {
	_aws_is_bash
	c := _aws_cmd
	_aws_create(c)
	not data.agentjail.config.aws
	r := {
		"action":  "ask",
		"rule_id": "library/no-aws-destructive",
		"reason":  "mutating AWS CLI command (create/provision/transfer) — confirm intent before proceeding",
		"impact":  "would run a mutating AWS CLI command",
	}
}
