package main

// Command examples are kept together so the complete user-facing tree can be
// audited as one help contract. See ADR 0027-cobra-cli-framework.
func init() {
	rootCmd.Example = `  agentjail run -- codex
  agentjail stats --since 7d
  agentjail doctor`

	allowCmd.Example = `  # Ask a human to add this host to the project policy.
  agentjail allow host api.example.com

  # Explain why future project sessions need the host.
  agentjail allow host api.example.com --reason "Needed for deployment checks"`
	allowHostCmd.Example = allowCmd.Example

	costCmd.Example = `  agentjail cost --period 7d
  agentjail cost --period 24h --project "$PWD"
  agentjail cost --period 30d --json`

	credentialCmd.Example = `  agentjail credential list

  # Import the AWS variables already exported in this terminal and store them
  # under the user-chosen name "aws/development".
  agentjail credential set aws/development --tool aws --from-current-env --label "Development account"

  agentjail credential remove aws/development`
	credentialSetCmd.Example = `  # Requires AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in the environment.
  # "aws/development" is a user-chosen name, not an AWS profile or filesystem path.
  agentjail credential set aws/development --tool aws --from-current-env --label "Development account"

  # Import a kubeconfig file under the user-chosen name "kube/development".
  agentjail credential set kube/development --tool kubectl --from-file ./dev.kubeconfig

  # Import the value of GH_TOKEN under the user-chosen name "github/work".
  printf '%s' "$GH_TOKEN" | agentjail credential set github/work --tool gh --from-stdin`
	credentialListCmd.Example = `  # Print stored identifiers, for example: aws/development
  agentjail credential list

  # Start Codex with that AWS credential selected before the sandbox starts.
  agentjail run --credential=aws=aws/development -- codex`
	credentialRemoveCmd.Example = `  agentjail credential remove aws/development`

	doctorCmd.Example = `  agentjail doctor
  agentjail doctor --fix`
	feedbackCmd.Example = `  agentjail feedback "The deny reason could be clearer"`

	grantCmd.Example = `  agentjail grant list
  agentjail grant history
  agentjail grant approve 01JABC123
  agentjail grant deny 01JABC123`
	grantApproveCmd.Example = `  # First list pending requests and copy the GRANT_ID to approve.
  agentjail grant list

  # Then approve that request from this trusted terminal.
  agentjail grant approve 01JABC123`
	grantDenyCmd.Example = `  # First list pending requests and copy the GRANT_ID to deny.
  agentjail grant list

  # Then deny that request from this trusted terminal.
  agentjail grant deny 01JABC123`
	helpTopicCmd.Example = `  agentjail help getting-started
  agentjail help mcp tool
  agentjail stats --help`

	installCmd.Example = `  agentjail install --all
  agentjail install --for codex
  agentjail install --with-path-shim`
	logsCmd.Example = `  agentjail logs --since 2h --action deny
  agentjail logs --latest 100 --json
  agentjail logs --session 625d86f1`

	mcpCmd.Example = `  agentjail mcp list
  agentjail mcp scan
  agentjail mcp tool list context7`
	mcpAllowCmd.Example = `  agentjail mcp allow context7`
	mcpBlockCmd.Example = `  agentjail mcp block stripe`
	mcpScanCmd.Example = `  agentjail mcp scan
  agentjail mcp scan --json`
	mcpWhereCmd.Example = `  agentjail mcp where context7
  agentjail mcp where context7 --json`
	mcpToolListCmd.Example = `  agentjail mcp tool list
  agentjail mcp tool list context7 --json`
	mcpToolCmd.Example = `  agentjail mcp tool list context7
  agentjail mcp tool allow context7 resolve-library-id
  agentjail mcp tool ask github create_pull_request --project "$PWD"`
	mcpToolAllowCmd.Example = `  agentjail mcp tool allow context7 resolve-library-id`
	mcpToolBlockCmd.Example = `  agentjail mcp tool block github delete_repository --project "$PWD"`
	mcpToolAskCmd.Example = `  agentjail mcp tool ask github create_pull_request --project "$PWD"`
	mcpToolClearCmd.Example = `  agentjail mcp tool clear github create_pull_request --project "$PWD"`

	monitorCmd.Example = `  agentjail monitor --since 24h
  agentjail monitor --since 7d --json`

	policyCmd.Example = `  agentjail policy list
  agentjail policy enable no_shell_init_write

  # Core rules marked "locked" cannot be disabled; other core rules require
  # --force and interactive human confirmation.
  agentjail policy disable command_policy/no-sudo --force`
	policyEnableCmd.Example = `  agentjail policy enable no_shell_init_write
  agentjail policy enable command_policy/no-sudo`
	policyDisableCmd.Example = `  # Disable an optional library rule by its file name.
  agentjail policy disable no_history_read

  # Disable a user-tunable core rule from a trusted interactive terminal.
  agentjail policy disable command_policy/no-sudo --force`
	policyAddCmd.Example = `  agentjail policy add ./my-rule.rego`
	policyRemoveCmd.Example = `  agentjail policy remove my-rule`

	replayCmd.Example = `  agentjail sessions --since 24h
  agentjail replay --session 625d86f1
  agentjail replay --session 625d86f1 --follow --verbose`
	runCmd.Example = `  agentjail run -- claude
  agentjail run --verbose -- codex
  agentjail run --git-ssh -- codex
  agentjail run --credential=aws=aws/dev -- claude`
	claudeCmd.Example = `  agentjail claude
  agentjail claude --verbose
  agentjail claude --git-ssh`

	sessionsCmd.Example = `  agentjail sessions --active
  agentjail sessions --since 7d --json`

	skillCmd.Example = `  agentjail skill list
  agentjail skill ask --project "$PWD" deploy-production`
	skillListCmd.Example = `  agentjail skill list --json`
	skillAllowCmd.Example = `  agentjail skill allow code-review
  agentjail skill allow --project "$PWD" code-review`
	skillBlockCmd.Example = `  agentjail skill block --project "$PWD" deploy-production`
	skillAskCmd.Example = `  agentjail skill ask --project "$PWD" deploy-production`
	skillClearCmd.Example = `  agentjail skill clear --project "$PWD" deploy-production`

	statsCmd.Long = `Summarize recorded final outcomes, policy denies, latency, and recording
coverage from the local SQLite event store.

The default report includes all recorded history. Use --since to select a
recent window and --top to control the number of rows in each breakdown.`
	statsCmd.Example = `  agentjail stats
  agentjail stats --since 24h
  agentjail stats --since 7d --top 20
  agentjail stats --since 30d --json`

	telemetryCmd.Example = `  agentjail telemetry status
  agentjail telemetry view
  agentjail telemetry disable`
	trustCmd.Example = `  agentjail trust add ./services/api
  agentjail trust list`
	trustAddCmd.Example = `  agentjail trust add ./services/api`
	trustRemoveCmd.Example = `  agentjail trust remove ./services/api`
	tryCmd.Example = `  agentjail try "git push origin main"
  agentjail try --read ~/.aws/credentials
  agentjail try --write /etc/hosts
  agentjail try
  agentjail try --json "rm -rf /"`
	uiCmd.Example = `  agentjail ui
  agentjail ui --addr 127.0.0.1:9200`

	uninstallCmd.Example = `  agentjail uninstall --for cursor
  agentjail uninstall --for vscode
  agentjail uninstall --path-shim-only
  agentjail uninstall --keep-credentials`
	updateCmd.Example = `  agentjail update
  agentjail update --force`
}
