# Tests for agentpolicy/policies/aws_posture.rego (P1.2 — per-account posture).
package agentjail_test

import future.keywords.if
import data.agentjail

posture_rule_id := "aws_policy/posture"

# bash_with_account builds a Bash PreToolUse input with the daemon-resolved
# aws_account already injected (the daemon resolves --profile -> account from
# ~/.aws/config before Rego eval; tests inject it directly).
bash_with_account(cmd, acct) := {
	"hook_event":  "PreToolUse",
	"tool_name":   "Bash",
	"tool_input":  {"command": cmd},
	"session_id":  "s1",
	"cwd":         "/Users/dev/project",
	"aws_account": acct,
}

# aws_cfg wraps an aws section in a minimal data.agentjail.config shape.
aws_cfg(aws) := {
	"aws":             aws,
	"disabled_rules":  [],
}

destructive := "aws s3 rb --force my-bucket --profile prod"
create_cmd := "aws iam create-user --user-name test --profile prod"

# ---------------------------------------------------------------------------
# PROD posture: destructive -> deny, create -> ask
# ---------------------------------------------------------------------------

test_posture_prod_delete_deny if {
	agentjail.decision.action == "deny" with input as bash_with_account(destructive, "123") with data.agentjail.config as aws_cfg({
		"default_posture": "prod",
		"accounts": {"123": {"posture": "prod", "allow_cud": false, "deny_delete": false, "read_only": false}},
		"resources": {},
	})
	agentjail.decision.rule_id == posture_rule_id with input as bash_with_account(destructive, "123") with data.agentjail.config as aws_cfg({
		"default_posture": "prod",
		"accounts": {"123": {"posture": "prod", "allow_cud": false, "deny_delete": false, "read_only": false}},
		"resources": {},
	})
}

test_posture_prod_create_ask if {
	agentjail.decision.action == "ask" with input as bash_with_account(create_cmd, "123") with data.agentjail.config as aws_cfg({
		"default_posture": "prod",
		"accounts": {"123": {"posture": "prod", "allow_cud": false, "deny_delete": false, "read_only": false}},
		"resources": {},
	})
}

# ---------------------------------------------------------------------------
# SANDBOX posture: destructive -> ask, create -> allow
# ---------------------------------------------------------------------------

test_posture_sandbox_delete_ask if {
	agentjail.decision.action == "ask" with input as bash_with_account(destructive, "123") with data.agentjail.config as aws_cfg({
		"default_posture": "prod",
		"accounts": {"123": {"posture": "sandbox", "allow_cud": true, "deny_delete": false, "read_only": false}},
		"resources": {},
	})
}

test_posture_sandbox_create_allow if {
	agentjail.decision.action == "allow" with input as bash_with_account(create_cmd, "123") with data.agentjail.config as aws_cfg({
		"default_posture": "prod",
		"accounts": {"123": {"posture": "sandbox", "allow_cud": true, "deny_delete": false, "read_only": false}},
		"resources": {},
	})
}

# ---------------------------------------------------------------------------
# LOCKED posture: destructive -> deny, create -> deny
# ---------------------------------------------------------------------------

test_posture_locked_delete_deny if {
	agentjail.decision.action == "deny" with input as bash_with_account(destructive, "123") with data.agentjail.config as aws_cfg({
		"default_posture": "prod",
		"accounts": {"123": {"posture": "locked", "allow_cud": false, "deny_delete": true, "read_only": true}},
		"resources": {},
	})
}

test_posture_locked_create_deny if {
	agentjail.decision.action == "deny" with input as bash_with_account(create_cmd, "123") with data.agentjail.config as aws_cfg({
		"default_posture": "prod",
		"accounts": {"123": {"posture": "locked", "allow_cud": false, "deny_delete": true, "read_only": true}},
		"resources": {},
	})
}

# ---------------------------------------------------------------------------
# Default posture fail-safe: unknown account -> default_posture
# ---------------------------------------------------------------------------

test_posture_unknown_account_default_prod_deny if {
	agentjail.decision.action == "deny" with input as bash_with_account(destructive, "999999999999") with data.agentjail.config as aws_cfg({
		"default_posture": "prod",
		"accounts": {"123": {"posture": "sandbox", "allow_cud": true, "deny_delete": false, "read_only": false}},
		"resources": {},
	})
}

test_posture_unknown_account_default_sandbox_ask if {
	agentjail.decision.action == "ask" with input as bash_with_account(destructive, "999999999999") with data.agentjail.config as aws_cfg({
		"default_posture": "sandbox",
		"accounts": {"123": {"posture": "prod", "allow_cud": false, "deny_delete": false, "read_only": false}},
		"resources": {},
	})
}

# ---------------------------------------------------------------------------
# Empty/missing default_posture -> fail-safe "prod" (destructive deny)
# ---------------------------------------------------------------------------

test_posture_missing_default_posture_failsafe_prod if {
	agentjail.decision.action == "deny" with input as bash_with_account(destructive, "999999999999") with data.agentjail.config as aws_cfg({
		"accounts": {},
		"resources": {},
	})
}

# ---------------------------------------------------------------------------
# CUSTOM posture: per-account flags
# ---------------------------------------------------------------------------

test_posture_custom_deny_delete_flag if {
	agentjail.decision.action == "deny" with input as bash_with_account(destructive, "123") with data.agentjail.config as aws_cfg({
		"default_posture": "prod",
		"accounts": {"123": {"posture": "custom", "allow_cud": true, "deny_delete": true, "read_only": false}},
		"resources": {},
	})
}

test_posture_custom_no_deny_delete_ask if {
	agentjail.decision.action == "ask" with input as bash_with_account(destructive, "123") with data.agentjail.config as aws_cfg({
		"default_posture": "prod",
		"accounts": {"123": {"posture": "custom", "allow_cud": true, "deny_delete": false, "read_only": false}},
		"resources": {},
	})
}

test_posture_custom_read_only_create_deny if {
	agentjail.decision.action == "deny" with input as bash_with_account(create_cmd, "123") with data.agentjail.config as aws_cfg({
		"default_posture": "prod",
		"accounts": {"123": {"posture": "custom", "allow_cud": false, "deny_delete": false, "read_only": true}},
		"resources": {},
	})
}

test_posture_custom_allow_cud_create_allow if {
	agentjail.decision.action == "allow" with input as bash_with_account(create_cmd, "123") with data.agentjail.config as aws_cfg({
		"default_posture": "prod",
		"accounts": {"123": {"posture": "custom", "allow_cud": true, "deny_delete": false, "read_only": false}},
		"resources": {},
	})
}

# ---------------------------------------------------------------------------
# Resource-level override: S3 bucket ARN glob overrides account posture.
# Account is sandbox (delete ask) but the bucket matches a locked resource.
# Uses the --bucket form (s3api delete-bucket) so the bucket is unambiguous.
# ---------------------------------------------------------------------------

test_posture_resource_override_locked_over_sandbox if {
	agentjail.decision.action == "deny" with input as bash_with_account("aws s3api delete-bucket --bucket prod-logs", "123") with data.agentjail.config as aws_cfg({
		"default_posture": "prod",
		"accounts": {"123": {"posture": "sandbox", "allow_cud": true, "deny_delete": false, "read_only": false}},
		"resources": {"arn:aws:s3:::prod-*": {"posture": "locked", "deny_delete": true}},
	})
}

# Resource glob does NOT match a non-matching bucket -> account posture applies.
test_posture_resource_no_match_uses_account if {
	agentjail.decision.action == "ask" with input as bash_with_account("aws s3api delete-bucket --bucket dev-bucket", "123") with data.agentjail.config as aws_cfg({
		"default_posture": "prod",
		"accounts": {"123": {"posture": "sandbox", "allow_cud": true, "deny_delete": false, "read_only": false}},
		"resources": {"arn:aws:s3:::prod-*": {"posture": "locked", "deny_delete": true}},
	})
}

# Most-specific (longest) matching glob wins. The s3:// form is used.
test_posture_resource_most_specific_wins if {
	# s3://prod-logs/x matches both "arn:aws:s3:::prod-*" (sandbox) and the
	# longer "arn:aws:s3:::prod-logs" (locked). The longer (locked) wins -> deny.
	agentjail.decision.action == "deny" with input as bash_with_account("aws s3 cp s3://prod-logs/key ./k", "123") with data.agentjail.config as aws_cfg({
		"default_posture": "prod",
		"accounts": {"123": {"posture": "sandbox", "allow_cud": true, "deny_delete": false, "read_only": false}},
		"resources": {
			"arn:aws:s3:::prod-*":    {"posture": "sandbox", "deny_delete": false},
			"arn:aws:s3:::prod-logs": {"posture": "locked", "deny_delete": true},
		},
	})
}

# ---------------------------------------------------------------------------
# Deferral: with aws config, library/no-aws-destructive does NOT fire
# (rule_id is aws_policy/posture, not library/no-aws-destructive).
# ---------------------------------------------------------------------------

test_posture_defers_library_rule if {
	agentjail.decision.rule_id == posture_rule_id with input as bash_with_account(destructive, "123") with data.agentjail.config as aws_cfg({
		"default_posture": "prod",
		"accounts": {"123": {"posture": "prod", "allow_cud": false, "deny_delete": false, "read_only": false}},
		"resources": {},
	})
}

# ---------------------------------------------------------------------------
# Reads: no aws_policy candidate -> command_policy/default-allow -> allow.
# ---------------------------------------------------------------------------

test_posture_read_still_allow if {
	agentjail.decision.action == "allow" with input as bash_with_account("aws s3 ls", "123") with data.agentjail.config as aws_cfg({
		"default_posture": "prod",
		"accounts": {"123": {"posture": "prod", "allow_cud": false, "deny_delete": false, "read_only": false}},
		"resources": {},
	})
}

# ---------------------------------------------------------------------------
# No aws_account injected (daemon could not resolve --profile) but aws config
# present -> default_posture applies.
# ---------------------------------------------------------------------------

test_posture_no_account_injected_uses_default if {
	agentjail.decision.action == "deny" with input as {
		"hook_event": "PreToolUse",
		"tool_name":  "Bash",
		"tool_input": {"command": destructive},
		"session_id": "s1",
		"cwd":        "/Users/dev/project",
	} with data.agentjail.config as aws_cfg({
		"default_posture": "prod",
		"accounts": {},
		"resources": {},
	})
}
