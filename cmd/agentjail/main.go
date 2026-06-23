package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/LuD1161/agentjail/internal/ui"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}

	args, _ := parseTopLevelFlags(os.Args[1:])
	if len(args) == 0 {
		usage(os.Stderr)
		os.Exit(2)
	}

	if args[0] != "telemetry" {
		recordFeatureUsed(args[0])
		// Fire the throttled update check + heartbeat asynchronously. Never
		// adds latency; all network/file errors are silently discarded.
		defer maybeRunUpdateCheck()()
	}

	switch args[0] {
	case "install":
		runInstallCmd(args[1:])
	case "uninstall":
		runUninstallCmd(args[1:])
	case "status":
		runStatusCmd()
	case "version":
		runVersionCmd()
	case "try":
		os.Exit(runTry(args[1:]))
	case "logs":
		os.Exit(runLogs(args[1:]))
	case "replay":
		os.Exit(runReplay(args[1:]))
	case "policy":
		os.Exit(runPolicy(args[1:]))
	case "mcp":
		os.Exit(runMCP(args[1:]))
	case "secret":
		os.Exit(runSecret(args[1:]))
	case "ui":
		os.Exit(runUI(args[1:]))
	case "telemetry":
		os.Exit(runTelemetry(args[1:]))
	case "feedback":
		os.Exit(runFeedback(args[1:]))
	case "update":
		os.Exit(runUpdate(args[1:]))
	case "help", "-h", "--help":
		// Explicit help request: write to stdout, exit 0 (success).
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "agentjail: unknown command %q\n\n", args[0])
		usage(os.Stderr)
		os.Exit(2)
	}
}

// parseTopLevelFlags pulls long-form wrapper options out of the raw
// argument vector before the subcommand switch. Today's surface is
// minimal (no top-level flags), but the parser is preserved so future
// flags can be added without disturbing per-subcommand parsers.
func parseTopLevelFlags(in []string) (rest []string, agentSlug string) {
	rest = make([]string, 0, len(in))
	i := 0
	for i < len(in) {
		a := in[i]
		switch {
		case a == "--agent":
			if i+1 >= len(in) {
				fmt.Fprintln(os.Stderr, "agentjail: --agent requires a value")
				os.Exit(2)
			}
			agentSlug = in[i+1]
			i += 2
			continue
		case strings.HasPrefix(a, "--agent="):
			agentSlug = strings.TrimPrefix(a, "--agent=")
			i++
			continue
		}
		rest = append(rest, in[i:]...)
		return rest, agentSlug
	}
	return rest, agentSlug
}

// usage writes styled usage information to w and returns.
// Call with os.Stdout (exit 0) for explicit help requests, or os.Stderr
// (exit 2) for missing/unknown-command errors.
func usage(w io.Writer) {
	u := ui.New(w)
	const bodyIndent = "  "

	ver := version
	if ver == "" {
		ver = "dev"
	}

	fmt.Fprintln(w, u.Header("agentjail", ver, currentGOOS))
	fmt.Fprintln(w)
	fmt.Fprintln(w, u.Section("Usage"))
	fmt.Fprintln(w, bodyIndent+"agentjail <command> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, u.Section("Commands"))

	type cmd struct {
		name string
		desc string
	}
	cmds := []cmd{
		{"install", "Install hooks for supported coding agents"},
		{"status", "Show hook, daemon, and policy health"},
		{"try", "Check whether an action would be allowed by policy (nothing is executed)"},
		{"logs", "View policy decisions"},
		{"replay", "Replay decisions from a saved session"},
		{"policy", "Manage optional hardening rules"},
		{"mcp", "Manage MCP server allow/block lists"},
		{"secret", "Manage scoped secret grants"},
		{"ui", "Open the local web UI"},
		{"telemetry", "Manage anonymous usage statistics"},
		{"feedback", "Send anonymous feedback to the maintainers"},
	}

	for _, c := range cmds {
		fmt.Fprintln(w, bodyIndent+u.KeyValue(c.name, c.desc, ""))
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, u.Section("Maintenance"))
	maintenance := []cmd{
		{"update", "Update agentjail binaries to the latest release"},
		{"uninstall", "Remove hooks, daemon service, and local policy state"},
		{"version", "Print version information"},
		{"help", "Show help"},
	}
	for _, c := range maintenance {
		fmt.Fprintln(w, bodyIndent+u.KeyValue(c.name, c.desc, ""))
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, u.Section("Examples"))
	examples := []string{
		"agentjail try \"rm -rf /\"",
		"agentjail install --for codex",
		"agentjail status",
		"agentjail logs --action=deny --since=1h",
		"agentjail replay --list",
		"agentjail policy enable no_shell_init_write",
		"agentjail mcp allow filesystem",
		"agentjail secret list",
		"agentjail mcp list",
	}
	for _, ex := range examples {
		fmt.Fprintln(w, bodyIndent+ex)
	}
	fmt.Fprintln(w)
}
