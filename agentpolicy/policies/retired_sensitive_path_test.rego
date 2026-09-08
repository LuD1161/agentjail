package agentjail_command_test

import data.agentjail
import future.keywords.every
import future.keywords.if

# Inert path mentions must not deny or fall through to ask.
# See ADR 0143-retire-path-heuristic.
test_sensitive_path_mentions_allow if {
	every command in [
		`rg -n '/etc/|id_rsa|\.env|\.pem' docs`,
		`echo 'document ~/.ssh and ~/.aws/credentials'`,
		`git commit -m "document /etc/resolv.conf"`,
		`tool -m "document ~/.ssh handling"`,
		`openssl x509 -in /tmp/cert.pem -text`,
	] {
		d := agentjail.decision with input as bash_input(command)
		d.action == "allow"
		d.rule_id == "command_policy/default-allow"
	}
}

# Policy inputs only; the sandbox decides whether actual I/O succeeds.
# See ADR 0143-retire-path-heuristic.
test_shell_file_access_delegates_to_sandbox if {
	every command in [
		"cat /Users/dev/.ssh/id_rsa",
		"cat /home/dev/.aws/credentials",
		"cat /root/.npmrc",
		"cat ~/.kube/config",
		"cat .env",
		"printf x > .env.local",
		"cat /etc/passwd",
	] {
		d := agentjail.decision with input as bash_input(command)
		d.action == "allow"
		d.rule_id == "command_policy/default-allow"
	}
}

# Retirement must not suppress the remaining candidates.
test_sensitive_path_retirement_preserves_other_policies if {
	d := agentjail.decision with input as bash_input("sudo cat /etc/passwd")
	d.action == "deny"
	d.rule_id == "command_policy/no-sudo"

	f := agentjail.decision with input as {
		"hook_event": "PreToolUse",
		"tool_name": "Read",
		"tool_input": {"file_path": "/Users/dev/.ssh/id_rsa"},
		"cwd": "/Users/dev/project",
	}
	f.action == "deny"
	f.rule_id == "file_policy/sensitive_credential"
}
