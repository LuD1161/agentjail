package main

// Command examples are kept together so the complete user-facing tree can be
// audited as one help contract. See ADR 0027-cobra-cli-framework.
func init() {
	rootCmd.Example = `  agentjail run -- codex
  agentjail stats --since 7d
  agentjail doctor`

	allowCmd.Example = `  agentjail allow host api.example.com --ttl 30m --reason "Needed for the current task"`
	allowHostCmd.Example = allowCmd.Example

	costCmd.Example = `  agentjail cost --period 7d
  agentjail cost --period 24h --project "$PWD"
  agentjail cost --period 30d --json`

	credentialCmd.Example = `  agentjail credential list
  agentjail credential set aws/dev --tool aws --from-current-env --label "Development"
  agentjail credential remove aws/dev`
	credentialSetCmd.Example = `  agentjail credential set aws/dev --tool aws --from-current-env --label "Development"
  agentjail credential set kube/dev --tool kubectl --from-file ./dev.kubeconfig
  printf '%s' "$GH_TOKEN" | agentjail credential set github/dev --tool gh --from-stdin`
	credentialListCmd.Example = `  agentjail credential list`
	credentialRemoveCmd.Example = `  agentjail credential remove aws/dev`

	doctorCmd.Example = `  agentjail doctor
  agentjail doctor --fix`
	feedbackCmd.Example = `  agentjail feedback "The deny reason could be clearer"`

	grantCmd.Example = `  agentjail grant approve 01JABC123
  agentjail grant deny 01JABC123`
	grantApproveCmd.Example = `  agentjail grants
  agentjail grant approve 01JABC123`
	grantDenyCmd.Example = `  agentjail grants
  agentjail grant deny 01JABC123`
	grantsCmd.Example = `  agentjail grants
  agentjail grants --log`

	helpTopicCmd.Example = `  agentjail help getting-started
  agentjail help mcp-tools
  agentjail stats --help`

	installCmd.Example = `  agentjail install --all
  agentjail install --for codex
  agentjail install --with-path-shim`
	logsCmd.Example = `  agentjail logs --since 2h --action deny
  agentjail logs --latest 100 --json
  agentjail logs --session 625d86f1`

	mcpCmd.Example = `  agentjail mcp list
  agentjail mcp scan
  agentjail mcp tools context7`
	mcpAllowCmd.Example = `  agentjail mcp allow context7`
	mcpBlockCmd.Example = `  agentjail mcp block stripe`
	mcpListCmd.Example = `  agentjail mcp list`
	mcpScanCmd.Example = `  agentjail mcp scan
  agentjail mcp scan --json`
	mcpWhereCmd.Example = `  agentjail mcp where context7
  agentjail mcp where context7 --json`
	mcpToolsCmd.Example = `  agentjail mcp tools
  agentjail mcp tools context7 --json`
	mcpToolCmd.Example = `  agentjail mcp tool allow context7 resolve-library-id
  agentjail mcp tool ask github create_pull_request --project "$PWD"`
	mcpToolAllowCmd.Example = `  agentjail mcp tool allow context7 resolve-library-id`
	mcpToolBlockCmd.Example = `  agentjail mcp tool block github delete_repository --project "$PWD"`
	mcpToolAskCmd.Example = `  agentjail mcp tool ask github create_pull_request --project "$PWD"`
	mcpToolClearCmd.Example = `  agentjail mcp tool clear github create_pull_request --project "$PWD"`

	monitorCmd.Example = `  agentjail monitor --since 24h
  agentjail monitor --since 7d --json`

	policyCmd.Example = `  agentjail policy list
  agentjail policy enable no_shell_init_write
  agentjail policy disable custom/example/rule`
	policyListCmd.Example = `  agentjail policy list`
	policyEnableCmd.Example = `  agentjail policy enable no_shell_init_write
  agentjail policy enable command_policy/no-sudo`
	policyDisableCmd.Example = `  agentjail policy disable custom/example/rule
  agentjail policy disable command_policy/no-sudo --force`
	policyAddCmd.Example = `  agentjail policy add ./my-rule.rego`
	policyRemoveCmd.Example = `  agentjail policy remove my-rule`

	replayCmd.Example = `  agentjail replay --list
  agentjail replay --session 625d86f1
  agentjail replay --session 625d86f1 --follow --verbose`
	runCmd.Example = `  agentjail run -- claude
  agentjail run --verbose -- codex
  agentjail run --git-ssh -- codex
  agentjail run --credential=aws=aws/dev -- claude`
	claudeCmd.Example = `  agentjail claude
  agentjail claude --verbose
  agentjail claude --git-ssh`

	secretCmd.Example = `  agentjail secret list
  agentjail secret set github --from-env GITHUB_TOKEN --hosts api.github.com
  agentjail secret remove github`
	secretSetCmd.Example = `  agentjail secret set github --from-env GITHUB_TOKEN --hosts api.github.com
  agentjail secret set deploy --from-env DEPLOY_TOKEN --hosts api.example.com --methods GET,POST --ttl 8h`
	secretListCmd.Example = `  agentjail secret list`
	secretRemoveCmd.Example = `  agentjail secret remove github`

	sessionsCmd.Example = `  agentjail sessions list
  agentjail sessions list --active
  agentjail sessions list --since 7d --json`

	skillCmd.Example = `  agentjail skill list
  agentjail skill ask --project "$PWD" deploy-production`
	skillListCmd.Example = `  agentjail skill list
  agentjail skill list --json`
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

	statusCmd.Example = `  agentjail status`
	telemetryCmd.Example = `  agentjail telemetry status
  agentjail telemetry view
  agentjail telemetry disable`

	trustCmd.Example = `  agentjail trust
  agentjail trust ./services/api
  agentjail trust list`
	trustListCmd.Example = `  agentjail trust list`
	tryCmd.Example = `  agentjail try "git push origin main"
  agentjail try --read ~/.aws/credentials
  agentjail try --write /etc/hosts
  agentjail try --json "rm -rf /"`
	uiCmd.Example = `  agentjail ui
  agentjail ui --addr 127.0.0.1:9200`

	uninstallCmd.Example = `  agentjail uninstall --for cursor
  agentjail uninstall --path-shim-only
  agentjail uninstall --keep-secrets`
	untrustCmd.Example = `  agentjail untrust
  agentjail untrust ./services/api`
	updateCmd.Example = `  agentjail update
  agentjail update --force`
	versionCmd.Example = `  agentjail version`
}
