# Package agentjail — AWS per-account posture policy (ADR 0017, P1.2).
#
# This is a CORE (always-on) rule. It owns the shared AWS CLI command
# classification helpers (_aws_cmd, _aws_is_bash, _aws_destructive,
# _aws_create) so the opt-in library/no-aws-destructive rule can reference
# them without a load-order dependency on the library file being enabled.
#
# Fires when an AWS posture config exists (data.agentjail.config.aws). When it
# does, library/no-aws-destructive DEFERS (its candidates are guarded by
# `not data.agentjail.config.aws`), so this rule is the SOLE emitter for AWS
# CLI commands — exactly one candidate, with the action derived from the
# effective posture. The resolver is deny > ask > allow, so a deny cannot be
# downgraded to an ask by a competing candidate; centralising the verdict here
# is what lets a sandbox account ask on delete while a prod account denies.
#
# Effective posture = resource-level override (S3 ARN glob, most-specific
# wins) else account posture else default_posture else "prod" (fail-safe).
#
# Posture -> verdict matrix (research note §3.2):
#   sandbox: Read allow, Create/Update allow, Delete ask
#   prod:    Read allow, Create/Update ask,  Delete deny
#   locked:  Read allow, Create/Update deny, Delete deny
#   custom:  per-account allow_cud / deny_delete / read_only flags
#
# Reads (aws s3 ls, describe-instances) contribute no candidate here and fall
# through to command_policy/default-allow. The daemon resolves the AWS account
# from --profile (via ~/.aws/config) and injects it as input.aws_account
# before Rego eval; an unresolvable/missing account -> default_posture.

package agentjail

import future.keywords.if
import future.keywords.contains
import future.keywords.in

# ---------------------------------------------------------------------------
# Shared AWS CLI command classification (reused by library/no-aws-destructive).
# ---------------------------------------------------------------------------

# _aws_cmd is the raw shell command string from the Bash tool_input.
_aws_cmd := input.tool_input.command

# _aws_is_bash is true for a Bash PreToolUse event.
_aws_is_bash if {
	input.hook_event == "PreToolUse"
	input.tool_name == "Bash"
}

# _aws_destructive matches irreversible AWS CLI delete/terminate/release
# operations. Generalized by verb family so new AWS services with the same
# verb shape are covered without a rule edit.
_aws_destructive(c) if regex.match(`\baws\s+\S+\s+delete-\S+\b`, c)

_aws_destructive(c) if regex.match(`\baws\s+ec2\s+terminate-\S+\b`, c)

_aws_destructive(c) if regex.match(`\baws\s+s3\s+rb\b`, c)

_aws_destructive(c) if regex.match(`\baws\s+s3api\s+delete-\S+\b`, c)

_aws_destructive(c) if regex.match(`\baws\s+ec2\s+release-(address|elastic-ip)\b`, c)

# _aws_create matches mutating AWS CLI create/provision/transfer operations.
_aws_create(c) if regex.match(`\baws\s+\S+\s+create-\S+\b`, c)

_aws_create(c) if regex.match(`\baws\s+ec2\s+run-instances\b`, c)

_aws_create(c) if regex.match(`\baws\s+s3\s+cp\b`, c)

# ---------------------------------------------------------------------------
# Account posture (fail-safe: default_posture, then "prod").
# ---------------------------------------------------------------------------

aws_account_posture := posture if {
	acct := input.aws_account
	acct != ""
	p := data.agentjail.config.aws.accounts[acct].posture
	p != ""
	posture := p
} else := posture if {
	dp := data.agentjail.config.aws.default_posture
	dp != ""
	posture := dp
} else := "prod"

# ---------------------------------------------------------------------------
# Resource-level override (S3 bucket ARN glob -> posture). Most-specific
# matching glob wins: longest glob, ties broken lexicographically largest.
# Only S3 buckets are extracted at Tier 1; non-S3 commands use account posture.
# ---------------------------------------------------------------------------

# _aws_s3_bucket extracts the bucket name from an S3 CLI command. Two forms:
#   s3://<bucket>/...           (cp, ls, sync, mv, rb s3://...)
#   --bucket <name> | =<name>   (s3api)
# The positional `aws s3 rb <name>` form is intentionally NOT handled here:
# reliably distinguishing the bucket from flag values (`--force`, `--profile
# prod`) at Tier 1 is brittle, so resource overrides apply only when the
# bucket is unambiguous (s3:// or --bucket). Account posture still applies.
# regex.find_n returns the full match (no capture groups in RE2), so the
# known prefix is stripped with regex.replace.
_aws_s3_bucket(c) := bucket if {
	m := regex.find_n(`s3://[a-zA-Z0-9][a-zA-Z0-9.\-]*`, c, 1)
	count(m) > 0
	bucket := regex.replace(m[0], `^s3://`, "")
}

_aws_s3_bucket(c) := bucket if {
	not regex.match(`s3://`, c)
	m := regex.find_n(`--bucket[ =][a-zA-Z0-9][a-zA-Z0-9.\-]*`, c, 1)
	count(m) > 0
	bucket := regex.replace(m[0], `^--bucket[ =]`, "")
}

_aws_matching_globs(arn) := {p |
	some p in object.keys(data.agentjail.config.aws.resources)
	glob.match(p, ["/"], arn)
}

# _aws_better_glob is true when some other matching glob is preferable to g:
# longer, or equal-length and lexicographically larger.
_aws_better_glob(g, arn) if {
	globs := _aws_matching_globs(arn)
	some other in globs
	other != g
	count(other) > count(g)
}

_aws_better_glob(g, arn) if {
	globs := _aws_matching_globs(arn)
	some other in globs
	other != g
	count(other) == count(g)
	other > g
}

_aws_resource_posture(arn) := posture if {
	globs := _aws_matching_globs(arn)
	count(globs) > 0
	some win in globs
	not _aws_better_glob(win, arn)
	posture := data.agentjail.config.aws.resources[win].posture
}

# ---------------------------------------------------------------------------
# Effective posture: resource override (S3) else account posture.
# ---------------------------------------------------------------------------

aws_effective_posture := posture if {
	c := _aws_cmd
	bucket := _aws_s3_bucket(c)
	arn := sprintf("arn:aws:s3:::%s", [bucket])
	rp := _aws_resource_posture(arn)
	rp != ""
	posture := rp
} else := aws_account_posture

# ---------------------------------------------------------------------------
# Verdict matrix: (action-class, posture) -> action.
# ---------------------------------------------------------------------------

_aws_verdict(class, posture) := "ask" if {
	class == "delete"
	posture == "sandbox"
} else := "deny" if {
	class == "delete"
	posture in {"prod", "locked"}
} else := "deny" if {
	class == "delete"
	posture == "custom"
	data.agentjail.config.aws.accounts[input.aws_account].deny_delete
} else := "ask" if {
	class == "delete"
	posture == "custom"
} else := "allow" if {
	class == "create"
	posture == "sandbox"
} else := "ask" if {
	class == "create"
	posture == "prod"
} else := "deny" if {
	class == "create"
	posture == "locked"
} else := "deny" if {
	class == "create"
	posture == "custom"
	data.agentjail.config.aws.accounts[input.aws_account].read_only
} else := "allow" if {
	class == "create"
	posture == "custom"
	data.agentjail.config.aws.accounts[input.aws_account].allow_cud
} else := "ask" if {
	class == "create"
	posture == "custom"
}

# ---------------------------------------------------------------------------
# Candidates — sole emitter for AWS CLI commands when posture config exists.
# ---------------------------------------------------------------------------

candidate contains r if {
	_aws_is_bash
	c := _aws_cmd
	_aws_destructive(c)
	data.agentjail.config.aws
	posture := aws_effective_posture
	action := _aws_verdict("delete", posture)
	r := {
		"action":  action,
		"rule_id": "aws_policy/posture",
		"reason":  sprintf("destructive AWS CLI command on %s-posture account %q -> %s", [posture, object.get(input, "aws_account", ""), action]),
		"impact":  "would run a destructive AWS CLI command",
	}
}

candidate contains r if {
	_aws_is_bash
	c := _aws_cmd
	_aws_create(c)
	data.agentjail.config.aws
	posture := aws_effective_posture
	action := _aws_verdict("create", posture)
	r := {
		"action":  action,
		"rule_id": "aws_policy/posture",
		"reason":  sprintf("mutating AWS CLI command on %s-posture account %q -> %s", [posture, object.get(input, "aws_account", ""), action]),
		"impact":  "would run a mutating AWS CLI command",
	}
}
