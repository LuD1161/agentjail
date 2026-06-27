// cmd_mcp.go -- cobra command tree for `agentjail mcp`.
//
// Subcommands:
//
//	agentjail mcp allow <server>
//	agentjail mcp block <server>
//	agentjail mcp list
//	agentjail mcp scan [--json]
//	agentjail mcp where <server> [--json]
//	agentjail mcp tools [server] [--json]
//	agentjail mcp tool allow <server> <tool> [--project <dir>]
//	agentjail mcp tool block <server> <tool> [--project <dir>]
//	agentjail mcp tool ask   <server> <tool> [--project <dir>]
//	agentjail mcp tool clear <server> <tool> [--project <dir>]
package main

import (
	"os"

	"github.com/spf13/cobra"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Manage MCP server allow/block lists",
}

var mcpAllowCmd = &cobra.Command{
	Use:   "allow <server>",
	Short: "Add a server to the MCP allowed list",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runMCPAllow(args[0]))
	},
}

var mcpBlockCmd = &cobra.Command{
	Use:   "block <server>",
	Short: "Add a server to the MCP blocked list (and remove from allowed)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runMCPBlock(args[0]))
	},
}

var mcpListCmd = &cobra.Command{
	Use:   "list",
	Short: "Show current allowed and blocked MCP servers",
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runMCPList())
	},
}

// scan, where, tools parse their own --json flag so we disable cobra flag
// parsing and pass args through to the existing run functions unchanged.

var mcpScanCmd = &cobra.Command{
	Use:                "scan [--json]",
	Short:              "Discover all MCP servers: configs, npm, pip, Docker, audit, remote connectors",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runMCPScan(args))
	},
}

var mcpWhereCmd = &cobra.Command{
	Use:                "where <server> [--json]",
	Short:              "Show which projects use this MCP server",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runMCPWhere(args))
	},
}

var mcpToolsCmd = &cobra.Command{
	Use:                "tools [server] [--json]",
	Short:              "List all MCP tools per server with policy status",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runMCPTools(args))
	},
}

// mcp tool -- per-tool policy management (three levels deep).

var mcpToolCmd = &cobra.Command{
	Use:   "tool",
	Short: "Per-tool policy management",
}

// mcpToolProjectFlag holds the value of --project for the tool subcommands.
var mcpToolProjectFlag string

var mcpToolAllowCmd = &cobra.Command{
	Use:   "allow <server> <tool>",
	Short: "Allow a specific tool on a server",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runMCPToolAllow(args[0], args[1], mcpToolProjectFlag))
	},
}

var mcpToolBlockCmd = &cobra.Command{
	Use:   "block <server> <tool>",
	Short: "Block a specific tool on a server",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runMCPToolBlock(args[0], args[1], mcpToolProjectFlag))
	},
}

var mcpToolAskCmd = &cobra.Command{
	Use:   "ask <server> <tool>",
	Short: "Require confirmation for a specific tool",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runMCPToolAsk(args[0], args[1], mcpToolProjectFlag))
	},
}

var mcpToolClearCmd = &cobra.Command{
	Use:   "clear <server> <tool>",
	Short: "Remove per-tool policy (inherit server default)",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runMCPToolClear(args[0], args[1], mcpToolProjectFlag))
	},
}

func init() {
	// --project flag on all mcp tool subcommands (persistent so it propagates).
	mcpToolCmd.PersistentFlags().StringVar(&mcpToolProjectFlag, "project", "", "Project directory for scoped policy")

	mcpToolCmd.AddCommand(mcpToolAllowCmd, mcpToolBlockCmd, mcpToolAskCmd, mcpToolClearCmd)
	mcpCmd.AddCommand(mcpAllowCmd, mcpBlockCmd, mcpListCmd, mcpScanCmd, mcpWhereCmd, mcpToolsCmd, mcpToolCmd)
	rootCmd.AddCommand(mcpCmd)
}
