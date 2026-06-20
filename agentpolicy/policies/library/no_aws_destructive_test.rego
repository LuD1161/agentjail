# Tests for agentpolicy/policies/library/no_aws_destructive.rego
package agentjail_test

import future.keywords.if
import data.agentjail

aws_rule_id := "library/no-aws-destructive"

bash(cmd) := {
	"hook_event": "PreToolUse",
	"tool_name":  "Bash",
	"tool_input": {"command": cmd},
	"session_id": "s1",
	"cwd":        "/Users/dev/project",
}

# ---------------------------------------------------------------------------
# DENY: destructive AWS CLI commands
# ---------------------------------------------------------------------------

test_aws_deny_s3_rb_force if {
	agentjail.decision.action == "deny" with input as bash("aws s3 rb --force my-bucket")
	agentjail.decision.rule_id == aws_rule_id with input as bash("aws s3 rb --force my-bucket")
}

test_aws_deny_s3_rb_plain if {
	agentjail.decision.action == "deny" with input as bash("aws s3 rb my-bucket")
	agentjail.decision.rule_id == aws_rule_id with input as bash("aws s3 rb my-bucket")
}

test_aws_deny_s3api_delete_bucket if {
	agentjail.decision.action == "deny" with input as bash("aws s3api delete-bucket --bucket my-bucket")
	agentjail.decision.rule_id == aws_rule_id with input as bash("aws s3api delete-bucket --bucket my-bucket")
}

test_aws_deny_ec2_terminate_instances if {
	agentjail.decision.action == "deny" with input as bash("aws ec2 terminate-instances --instance-ids i-1234567890abcdef0")
	agentjail.decision.rule_id == aws_rule_id with input as bash("aws ec2 terminate-instances --instance-ids i-1234567890abcdef0")
}

test_aws_deny_rds_delete_db_instance if {
	agentjail.decision.action == "deny" with input as bash("aws rds delete-db-instance --db-instance-identifier prod-db --skip-final-snapshot")
	agentjail.decision.rule_id == aws_rule_id with input as bash("aws rds delete-db-instance --db-instance-identifier prod-db --skip-final-snapshot")
}

test_aws_deny_iam_delete_role if {
	agentjail.decision.action == "deny" with input as bash("aws iam delete-role --role-name my-role")
	agentjail.decision.rule_id == aws_rule_id with input as bash("aws iam delete-role --role-name my-role")
}

test_aws_deny_cloudformation_delete_stack if {
	agentjail.decision.action == "deny" with input as bash("aws cloudformation delete-stack --stack-name prod-stack")
	agentjail.decision.rule_id == aws_rule_id with input as bash("aws cloudformation delete-stack --stack-name prod-stack")
}

test_aws_deny_lambda_delete_function if {
	agentjail.decision.action == "deny" with input as bash("aws lambda delete-function --function-name my-fn")
	agentjail.decision.rule_id == aws_rule_id with input as bash("aws lambda delete-function --function-name my-fn")
}

test_aws_deny_ec2_release_address if {
	agentjail.decision.action == "deny" with input as bash("aws ec2 release-address --allocation-id eipalloc-123")
	agentjail.decision.rule_id == aws_rule_id with input as bash("aws ec2 release-address --allocation-id eipalloc-123")
}

# ---------------------------------------------------------------------------
# ASK: mutating AWS CLI commands (create / provision / transfer)
# ---------------------------------------------------------------------------

test_aws_ask_iam_create_user if {
	agentjail.decision.action == "ask" with input as bash("aws iam create-user --user-name test")
	agentjail.decision.rule_id == aws_rule_id with input as bash("aws iam create-user --user-name test")
}

test_aws_ask_iam_create_role if {
	agentjail.decision.action == "ask" with input as bash("aws iam create-role --role-name test --assume-role-policy-document file://trust.json")
	agentjail.decision.rule_id == aws_rule_id with input as bash("aws iam create-role --role-name test --assume-role-policy-document file://trust.json")
}

test_aws_ask_ec2_run_instances if {
	agentjail.decision.action == "ask" with input as bash("aws ec2 run-instances --image-id ami-12345678 --count 1")
	agentjail.decision.rule_id == aws_rule_id with input as bash("aws ec2 run-instances --image-id ami-12345678 --count 1")
}

test_aws_ask_s3_cp_upload if {
	agentjail.decision.action == "ask" with input as bash("aws s3 cp ./file s3://my-bucket/key")
	agentjail.decision.rule_id == aws_rule_id with input as bash("aws s3 cp ./file s3://my-bucket/key")
}

test_aws_ask_s3_cp_download if {
	agentjail.decision.action == "ask" with input as bash("aws s3 cp s3://my-bucket/key ./file")
	agentjail.decision.rule_id == aws_rule_id with input as bash("aws s3 cp s3://my-bucket/key ./file")
}

test_aws_ask_s3api_create_bucket if {
	agentjail.decision.action == "ask" with input as bash("aws s3api create-bucket --bucket new-bucket --region us-east-1")
	agentjail.decision.rule_id == aws_rule_id with input as bash("aws s3api create-bucket --bucket new-bucket --region us-east-1")
}

# ---------------------------------------------------------------------------
# ALLOW: read AWS CLI commands (no AWS candidate; command_policy/default-allow)
# ---------------------------------------------------------------------------

test_aws_allow_s3_ls if {
	agentjail.decision.action == "allow" with input as bash("aws s3 ls")
}

test_aws_allow_s3_ls_bucket if {
	agentjail.decision.action == "allow" with input as bash("aws s3 ls s3://my-bucket/")
}

test_aws_allow_ec2_describe if {
	agentjail.decision.action == "allow" with input as bash("aws ec2 describe-instances")
}

test_aws_allow_iam_list_users if {
	agentjail.decision.action == "allow" with input as bash("aws iam list-users")
}

test_aws_allow_sts_caller_identity if {
	agentjail.decision.action == "allow" with input as bash("aws sts get-caller-identity")
}

# ---------------------------------------------------------------------------
# Non-regression: non-AWS commands are unaffected by this rule
# ---------------------------------------------------------------------------

test_aws_nonaws_git_status_not_denied_by_aws if {
	not agentjail.decision.action == "deny" with input as bash("git status")
}

test_aws_nonaws_ls_not_asked_by_aws if {
	not agentjail.decision.action == "ask" with input as bash("ls -la")
}

# ---------------------------------------------------------------------------
# Posture deferral: when data.agentjail.config.aws exists, this rule defers
# (emits no candidate) so aws_policy/* can compute the posture-aware verdict.
# A configured prod posture must still deny destructive — verified here by
# confirming this rule does NOT double-fire when aws config is present.
# ---------------------------------------------------------------------------

test_aws_defers_when_posture_configured if {
	# With an aws config present, the default-posture candidate must not fire
	# (the destructive command is handled by aws_policy/*). This asserts the
	# guard works: the library/no-aws-destructive rule_id is absent.
	agentjail.decision.rule_id != aws_rule_id with input as bash("aws s3 rb --force my-bucket") with data.agentjail.config as {
		"aws": {
			"default_posture": "prod",
			"accounts": {},
		},
		"mcp": {"allowed": [], "blocked": [], "servers": {}},
		"file": {"extra_deny": [], "extra_allow": [], "temp_roots": []},
		"commands": {"extra_block": []},
		"network": {"allowed_hosts": []},
		"web": {"blocked": []},
		"disabled_rules": [],
	}
}
