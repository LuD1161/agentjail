package main

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// Legacy command implementations still parse their own argv. Mirror that
// surface into Cobra until each parser is migrated. See ADR 0027-cobra-cli-framework.
func init() {
	home, _ := os.UserHomeDir()
	dbPath := filepath.Join(home, ".agentjail", "agentjail.db")
	logPath := filepath.Join(home, ".agentjail", "daemon.log")
	policyPath := filepath.Join(home, ".agentjail", "policy.yaml")

	documentStringFlag(costCmd, "period", "7d", "time period (e.g. 7d, 30d, 24h)")
	documentStringFlag(costCmd, "project", "", "filter to a specific project directory")
	documentBoolFlag(costCmd, "json", "output as JSON")

	documentStringFlag(logsCmd, "log", logPath, "path to daemon log")
	documentStringFlag(logsCmd, "db", dbPath, "path to SQLite event store")
	documentBoolFlag(logsCmd, "no-follow", "print existing lines and exit (no tail)")
	documentStringFlag(logsCmd, "action", "", "filter by action(s): allow, ask, deny")
	documentStringFlag(logsCmd, "tool", "", "filter by exact tool name")
	documentStringFlag(logsCmd, "since", "", "only decisions newer than a duration (e.g. 10m, 2h)")
	documentBoolFlag(logsCmd, "json", "pass through raw daemon log lines")
	documentBoolFlag(logsCmd, "all", "include non-decision INFO lines")
	documentBoolFlag(logsCmd, "no-color", "disable ANSI color output")
	documentBoolFlag(logsCmd, "v", "show input summary, reason, and session ID")
	documentStringFlag(logsCmd, "session", "", "filter by session ID substring")
	documentBoolFlag(logsCmd, "basic", "disable rich terminal mode")
	documentIntFlag(logsCmd, "latest", 0, "print the newest N matching decisions and exit")

	documentStringFlag(monitorCmd, "db", dbPath, "path to SQLite event store")
	documentStringFlag(monitorCmd, "policy", policyPath, "path to policy.yaml")
	documentBoolFlag(monitorCmd, "json", "output as JSON")
	documentStringFlag(monitorCmd, "since", "24h", "time range; 0 means all time")

	documentStringFlag(replayCmd, "db", dbPath, "path to SQLite event store")
	documentStringFlag(replayCmd, "session", "", "session ID to replay")
	documentBoolFlag(replayCmd, "verbose", "include redacted tool input")
	documentBoolFlag(replayCmd, "follow", "follow new decisions for the session")
	documentBoolFlag(replayCmd, "list", "list sessions")
	documentBoolFlag(replayCmd, "no-color", "disable ANSI colors")
	documentBoolFlag(replayCmd, "basic", "force plain text output")

	sessionsCmd.Use = "sessions list [flags]"
	documentStringFlag(sessionsCmd, "db", dbPath, "path to SQLite event store")
	documentBoolFlag(sessionsCmd, "active", "show only active sessions")
	documentBoolFlag(sessionsCmd, "json", "output as JSON")
	documentStringFlag(sessionsCmd, "since", "24h", "time range; 0 means all time")

	documentStringFlag(statsCmd, "db", dbPath, "path to SQLite event store")
	documentBoolFlag(statsCmd, "json", "output as JSON")
	documentStringFlag(statsCmd, "since", "0", "time range; 0 means all time")
	documentIntFlag(statsCmd, "top", 10, "rows to show per breakdown table")

	tryCmd.Use = "try [flags] [command...]"
	documentStringFlag(tryCmd, "read", "", "evaluate a Read event on this path")
	documentStringFlag(tryCmd, "write", "", "evaluate a Write event on this path")
	documentBoolFlag(tryCmd, "json", "emit JSON (JSONL in interactive mode)")

	documentStringFlag(uiCmd, "addr", "127.0.0.1:9101", "listen address")
	documentStringFlag(uiCmd, "db", dbPath, "path to SQLite event store")
	documentStringFlag(uiCmd, "log", logPath, "path to daemon log")
	documentBoolFlag(uiCmd, "edit-policy", "allow policy enable/disable controls")
	documentBoolFlag(uiCmd, "insecure-bind", "allow a non-loopback bind without auth or TLS")
	uiCmd.Flags().StringSlice("trusted-host", nil, "trusted Host/Origin allowed through the rebinding guard (repeatable)")

	installCmd.Use = "install [flags]"
	documentStringFlag(installCmd, "for", "", "install one target: claude-code, codex, cursor, vscode, or cursor-ide")
	documentBoolFlag(installCmd, "all", "install all detected agents non-interactively")
	installCmd.Flags().BoolP("yes", "y", false, "assume yes for non-interactive setup")
	documentBoolFlag(installCmd, "with-path-shim", "install agent launch shims in ~/.agentjail/bin")
	documentBoolFlag(installCmd, "with-apparmor", "install the Linux AppArmor user-namespace profile")
	documentBoolFlag(installCmd, "chain", "chain an existing IDE wrapper")
	documentBoolFlag(installCmd, "replace", "replace an existing IDE wrapper")
	documentBoolFlag(installCmd, "allow-unsupported", "deprecated compatibility flag")

	uninstallCmd.Use = "uninstall [flags]"
	documentStringFlag(uninstallCmd, "for", "", "uninstall one agent hook: claude-code, codex, or cursor")
	documentBoolFlag(uninstallCmd, "path-shim-only", "remove only agent launch shims")
	documentBoolFlag(uninstallCmd, "keep-secrets", "preserve the local credential vault")
	documentBoolFlag(uninstallCmd, "force", "continue teardown past recoverable failures")

	updateCmd.Use = "update [flags]"
	documentBoolFlag(updateCmd, "force", "reinstall the current version")

	runCmd.Flags().Bool("tunnel", false, "route egress through the L7 policy tunnel")
	runCmd.Flags().Bool("no-sandbox", false, "use hook-only policy without the OS sandbox")
	runCmd.Flags().Bool("git-ssh", false, "enable Git over SSH by delegating all loaded SSH-agent identities")
	runCmd.Flags().Bool("no-git-ssh", false, "disable policy-default Git over SSH for this launch")
	claudeCmd.Flags().Bool("tunnel", false, "route egress through the L7 policy tunnel")
	claudeCmd.Flags().Bool("no-sandbox", false, "use hook-only policy without the OS sandbox")
	claudeCmd.Flags().Bool("git-ssh", false, "enable Git over SSH by delegating all loaded SSH-agent identities")
	claudeCmd.Flags().Bool("no-git-ssh", false, "disable policy-default Git over SSH for this launch")

	feedbackCmd.Use = "feedback [message...]"
	feedbackCmd.Long = "Send feedback plus the AgentJail version and OS. If no message is supplied, prompt interactively."
	telemetryCmd.Use = "telemetry [status|enable|disable|view|reset]"

	documentBoolFlag(mcpScanCmd, "json", "output as JSON")
	documentBoolFlag(mcpWhereCmd, "json", "output as JSON")
	documentBoolFlag(mcpToolsCmd, "json", "output as JSON")
	documentBoolFlag(skillListCmd, "json", "output as JSON")
	for _, cmd := range []*cobra.Command{skillAllowCmd, skillBlockCmd, skillAskCmd, skillClearCmd} {
		documentStringFlag(cmd, "project", "", "project directory for project-scoped policy")
	}
}

func documentStringFlag(cmd *cobra.Command, name, value, usage string) {
	cmd.Flags().String(name, value, usage)
}

func documentBoolFlag(cmd *cobra.Command, name, usage string) {
	cmd.Flags().Bool(name, false, usage)
}

func documentIntFlag(cmd *cobra.Command, name string, value int, usage string) {
	cmd.Flags().Int(name, value, usage)
}
