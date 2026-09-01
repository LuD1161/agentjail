package main

import (
	"os"
	"path/filepath"

	"github.com/LuD1161/agentjail/internal/localui"
	"github.com/spf13/cobra"
)

// Legacy command implementations still parse their own argv. Mirror that
// surface into Cobra until each parser is migrated. See ADR 0027-cobra-cli-framework.
func init() {
	home, _ := os.UserHomeDir()
	dbPath := filepath.Join(home, ".agentjail", "agentjail.db")
	logPath := filepath.Join(home, ".agentjail", "daemon.log")
	policyPath := filepath.Join(home, ".agentjail", "policy.yaml")

	documentStringFlag(costCmd, "period", "7d", "positive report duration up to 90d (for example: 12h, 7d, 30d)")
	documentStringFlag(costCmd, "project", "", "include only sessions for project directory PATH")
	documentBoolFlag(costCmd, "json", "write machine-readable JSON instead of the terminal dashboard")

	documentStringFlag(logsCmd, "log", logPath, "read legacy JSONL from PATH instead of SQLite (disables --latest)")
	documentStringFlag(logsCmd, "db", dbPath, "read decisions from SQLite database at PATH")
	documentBoolFlag(logsCmd, "no-follow", "print existing lines and exit (no tail)")
	documentStringFlag(logsCmd, "action", "", "include actions LIST (comma-separated: allow,ask,deny)")
	documentStringFlag(logsCmd, "tool", "", "filter by exact tool name")
	documentStringFlag(logsCmd, "since", "", "include decisions from the last DURATION (for example: 10m, 2h, 24h)")
	documentBoolFlag(logsCmd, "json", "write normalized JSON from SQLite; with --log, pass through raw daemon lines")
	documentBoolFlag(logsCmd, "all", "with --log, include non-decision INFO lines")
	documentBoolFlag(logsCmd, "no-color", "disable ANSI color output")
	documentBoolFlag(logsCmd, "v", "show input summary, reason, and session ID")
	documentStringFlag(logsCmd, "session", "", "filter by session ID substring")
	documentBoolFlag(logsCmd, "basic", "disable rich terminal mode")
	documentIntFlag(logsCmd, "latest", 0, "print the newest N matching decisions and exit (1-10000)")

	documentStringFlag(monitorCmd, "db", dbPath, "read decisions from SQLite database at PATH")
	documentStringFlag(monitorCmd, "policy", policyPath, "read enforcement mode from policy file PATH")
	documentBoolFlag(monitorCmd, "json", "write machine-readable JSON instead of the table")
	documentStringFlag(monitorCmd, "since", "24h", "report window DURATION (for example: 30m, 24h, 7d); use 0 for all time")

	documentStringFlag(replayCmd, "db", dbPath, "read sessions from SQLite database at PATH")
	documentStringFlag(replayCmd, "session", "", "session ID or unique ID prefix to replay")
	documentBoolFlag(replayCmd, "verbose", "include redacted tool input")
	documentBoolFlag(replayCmd, "follow", "follow new decisions for the session")
	documentBoolFlag(replayCmd, "list", "deprecated compatibility flag; use 'agentjail sessions'")
	documentBoolFlag(replayCmd, "no-color", "disable ANSI colors")
	documentBoolFlag(replayCmd, "basic", "force plain text output")

	sessionsCmd.Use = "sessions"
	documentStringFlag(sessionsCmd, "db", dbPath, "read sessions from SQLite database at PATH")
	documentBoolFlag(sessionsCmd, "active", "show only active sessions")
	documentBoolFlag(sessionsCmd, "json", "output as JSON")
	documentStringFlag(sessionsCmd, "since", "24h", "include sessions from last DURATION (for example: 30m, 24h, 7d); use 0 for all time")

	documentStringFlag(statsCmd, "db", dbPath, "read events from SQLite database at PATH")
	documentBoolFlag(statsCmd, "json", "write machine-readable JSON instead of the terminal report")
	documentStringFlag(statsCmd, "since", "0", "report window DURATION (for example: 30m, 24h, 7d); use 0 for all time")
	documentIntFlag(statsCmd, "top", 10, "maximum rows in each ranked breakdown (must be at least 1)")

	tryCmd.Use = "try [flags] [command...]"
	documentStringFlag(tryCmd, "read", "", "evaluate a Read event on this path")
	documentStringFlag(tryCmd, "write", "", "evaluate a Write event on this path")
	documentBoolFlag(tryCmd, "json", "emit JSON (JSONL in interactive mode)")

	documentStringFlag(uiCmd, "addr", localui.DefaultAddr, "listen on HOST:PORT (loopback only unless --insecure-bind)")
	documentStringFlag(uiCmd, "db", dbPath, "path to SQLite event store")
	documentStringFlag(uiCmd, "log", logPath, "path to daemon log")
	documentBoolFlag(uiCmd, "edit-policy", "allow policy enable/disable controls")
	documentBoolFlag(uiCmd, "insecure-bind", "allow a non-loopback bind without auth or TLS")
	uiCmd.Flags().StringSlice("trusted-host", nil, "allow HOST through the rebinding guard (repeatable)")

	installCmd.Use = "install [flags]"
	documentStringFlag(installCmd, "for", "", "install one target: claude-code, codex, cursor, vscode, or cursor-ide")
	documentBoolFlag(installCmd, "all", "install all detected agents non-interactively")
	installCmd.Flags().BoolP("yes", "y", false, "assume yes for non-interactive setup")
	documentBoolFlag(installCmd, "with-path-shim", "install agent launch shims in ~/.agentjail/bin")
	documentBoolFlag(installCmd, "with-apparmor", "install the Linux AppArmor user-namespace profile")
	documentBoolFlag(installCmd, "chain", "with --for vscode or cursor-ide, chain an existing wrapper")
	documentBoolFlag(installCmd, "replace", "with --for vscode or cursor-ide, replace an existing wrapper")
	documentBoolFlag(installCmd, "allow-unsupported", "deprecated compatibility flag")

	uninstallCmd.Use = "uninstall [flags]"
	documentStringFlag(uninstallCmd, "for", "", "remove one hook or IDE wrapper: claude-code, codex, cursor, vscode, or cursor-ide")
	documentBoolFlag(uninstallCmd, "path-shim-only", "remove only agent launch shims")
	documentBoolFlag(uninstallCmd, "keep-credentials", "during full uninstall, preserve the encrypted credential vault")
	documentBoolFlag(uninstallCmd, "keep-secrets", "deprecated alias for --keep-credentials")
	documentBoolFlag(uninstallCmd, "force", "continue teardown past recoverable failures")
	documentBoolFlag(statusCmd, "json", "write a versioned machine-readable status projection")

	updateCmd.Use = "update [flags]"
	documentBoolFlag(updateCmd, "force", "reinstall the current version")

	runCmd.Flags().Bool("tunnel", false, "route egress through the L7 policy tunnel")
	runCmd.Flags().Bool("no-sandbox", false, "disable OS isolation and use weaker hook-only enforcement")
	runCmd.Flags().Bool("git-ssh", false, "enable Git over SSH by delegating all loaded SSH-agent identities")
	runCmd.Flags().Bool("no-git-ssh", false, "disable policy-default Git over SSH for this launch")
	runCmd.Flags().Bool("verbose", false, "mirror shield diagnostics to stderr")
	runCmd.Flags().StringArray("credential", nil, "select an exact broker credential ID (repeatable)")
	claudeCmd.Flags().Bool("tunnel", false, "route egress through the L7 policy tunnel")
	claudeCmd.Flags().Bool("no-sandbox", false, "disable OS isolation and use weaker hook-only enforcement")
	claudeCmd.Flags().Bool("git-ssh", false, "enable Git over SSH by delegating all loaded SSH-agent identities")
	claudeCmd.Flags().Bool("no-git-ssh", false, "disable policy-default Git over SSH for this launch")
	claudeCmd.Flags().Bool("verbose", false, "mirror shield diagnostics to stderr")
	claudeCmd.Flags().StringArray("credential", nil, "select an exact broker credential ID (repeatable)")

	feedbackCmd.Use = "feedback [message...]"
	feedbackCmd.Long = "Send your message, AgentJail version, OS, random installation ID, and optional follow-up contact. If no message is supplied, prompt interactively."
	telemetryCmd.Use = "telemetry"

	documentBoolFlag(mcpScanCmd, "json", "output as JSON")
	documentBoolFlag(mcpWhereCmd, "json", "output as JSON")
	documentBoolFlag(mcpToolsCmd, "json", "output as JSON")
	documentBoolFlag(skillListCmd, "json", "output as JSON")
	documentBoolFlag(mcpToolListCmd, "json", "output as JSON")
	for _, cmd := range []*cobra.Command{skillAllowCmd, skillBlockCmd, skillAskCmd, skillClearCmd} {
		documentStringFlag(cmd, "project", "", "apply policy only to project directory PATH (default: global)")
	}
	_ = installCmd.Flags().MarkHidden("allow-unsupported")
	_ = uninstallCmd.Flags().MarkHidden("keep-secrets")
	_ = replayCmd.Flags().MarkHidden("list")
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
