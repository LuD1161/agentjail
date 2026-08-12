package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

const gettingStartedHelp = `Getting Started with agentjail
==============================

1. Install hooks for your coding agent:
   agentjail install                   # auto-detect supported agents
   agentjail install --for codex       # install one CLI hook
   agentjail install --for vscode      # install one IDE wrapper

2. Check protection:
   agentjail status                    # quick component snapshot
   agentjail doctor                    # comprehensive diagnostics

3. Allow MCP servers your agent needs:
   agentjail mcp scan
   agentjail mcp allow filesystem

4. Review recorded activity:
   agentjail logs --action=deny
   agentjail sessions
   agentjail replay --session <id>

5. Fine-tune MCP tool and skill policy:
   agentjail mcp tool list
   agentjail mcp tool block linear-server delete_comment
   agentjail skill list
   agentjail skill block "posthog:*"

6. Open the local web UI:
   agentjail ui

Configuration: ~/.agentjail/policy.yaml
Documentation: https://agentjail.io/docs`

var legacyHelpAliases = map[string][]string{
	"mcp-tools": {"mcp", "tool"},
	"scan":      {"mcp", "scan"},
}

// runHelp resolves command paths through Cobra so command help has one source
// of truth. Only getting-started remains a standalone cross-command guide.
func runHelp(args []string) int {
	if len(args) == 0 {
		printHelpTopics(os.Stdout)
		return 0
	}
	if args[0] == "getting-started" {
		fmt.Fprintln(os.Stdout, gettingStartedHelp)
		return 0
	}
	if alias, ok := legacyHelpAliases[args[0]]; ok {
		args = append(append([]string{}, alias...), args[1:]...)
	}
	cmd, remaining, err := rootCmd.Find(args)
	if err != nil || cmd == rootCmd || len(remaining) != 0 {
		fmt.Fprintf(os.Stderr, "agentjail help: unknown command or guide %q\n\n", strings.Join(args, " "))
		printHelpTopics(os.Stderr)
		return 2
	}
	cmd.SetOut(os.Stdout)
	if err := cmd.Help(); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail help: %v\n", err)
		return 1
	}
	return 0
}

func printHelpTopics(w io.Writer) {
	fmt.Fprintln(w, "Use 'agentjail help <command> [subcommand]' for command help.")
	fmt.Fprintln(w, "Available guide:")
	fmt.Fprintln(w, "  getting-started  Install AgentJail and review your first decisions")
}
