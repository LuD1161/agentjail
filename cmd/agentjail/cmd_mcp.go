// cmd_mcp.go -- cobra command tree for `agentjail mcp`.
//
// Subcommands:
//
//	agentjail mcp allow <server>
//	agentjail mcp block <server>
//	agentjail mcp list
//	agentjail mcp scan [--json]
//	agentjail mcp where <server> [--json]
//	agentjail mcp tool list [server] [--json]
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
	Long:  "Allow an exact server name from 'agentjail mcp scan' or 'agentjail mcp list'. This mutation must run from a trusted interactive terminal.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runMCPAllow(args[0]))
	},
}

var mcpBlockCmd = &cobra.Command{
	Use:   "block <server>",
	Short: "Add a server to the MCP blocked list (and remove from allowed)",
	Long:  "Block an exact server name from 'agentjail mcp scan' or 'agentjail mcp list'. This mutation must run from a trusted interactive terminal.",
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
	Use:                "scan",
	Short:              "Discover all MCP servers: configs, npm, pip, Docker, audit, remote connectors",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		if helpRequested(cmd, args) {
			return
		}
		os.Exit(runMCPScan(args))
	},
}

var mcpWhereCmd = &cobra.Command{
	Use:                "where <server>",
	Short:              "Show which projects use this MCP server",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		if helpRequested(cmd, args) {
			return
		}
		os.Exit(runMCPWhere(args))
	},
}

var mcpToolsCmd = &cobra.Command{
	Use:                "tools [server]",
	Short:              "Compatibility alias for 'agentjail mcp tool list'",
	Hidden:             true,
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		if helpRequested(cmd, args) {
			return
		}
		os.Exit(runMCPTools(args))
	},
}

// mcp tool -- per-tool policy management (three levels deep).

var mcpToolCmd = &cobra.Command{
	Use:   "tool",
	Short: "List and manage per-tool MCP policy",
	Long: `List discovered MCP tool identifiers or change their policy. Use
'agentjail mcp tool list' first to copy the exact server and tool names.
Policy mutations must run from a trusted interactive terminal.`,
}

var mcpToolListCmd = &cobra.Command{
	Use:                "list [server]",
	Short:              "List discovered MCP tools with policy status",
	Long:               "List MCP tools observed in audit history, session logs, or policy, optionally restricted to one server.",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		if helpRequested(cmd, args) {
			return
		}
		os.Exit(runMCPTools(args))
	},
}

// mcpToolProjectFlag holds the value of --project for the tool subcommands.
var mcpToolProjectFlag string

var mcpToolAllowCmd = &cobra.Command{
	Use:   "allow <server> <tool>",
	Short: "Allow a specific tool on a server",
	Long:  "Allow exact server and tool names from 'agentjail mcp tool list'. This mutation must run from a trusted interactive terminal. Without --project, update global policy.",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runMCPToolAllow(args[0], args[1], mcpToolProjectFlag))
	},
}

var mcpToolBlockCmd = &cobra.Command{
	Use:   "block <server> <tool>",
	Short: "Block a specific tool on a server",
	Long:  "Block exact server and tool names from 'agentjail mcp tool list'. This mutation must run from a trusted interactive terminal. Without --project, update global policy.",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runMCPToolBlock(args[0], args[1], mcpToolProjectFlag))
	},
}

var mcpToolAskCmd = &cobra.Command{
	Use:   "ask <server> <tool>",
	Short: "Require confirmation for a specific tool",
	Long:  "Require confirmation for exact server and tool names from 'agentjail mcp tool list'. This mutation must run from a trusted interactive terminal. Without --project, update global policy.",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runMCPToolAsk(args[0], args[1], mcpToolProjectFlag))
	},
}

var mcpToolClearCmd = &cobra.Command{
	Use:   "clear <server> <tool>",
	Short: "Remove per-tool policy (inherit server default)",
	Long:  "Clear explicit policy for exact server and tool names from 'agentjail mcp tool list'. This mutation must run from a trusted interactive terminal. Without --project, inherit server policy.",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runMCPToolClear(args[0], args[1], mcpToolProjectFlag))
	},
}

func init() {
	for _, cmd := range []*cobra.Command{mcpToolAllowCmd, mcpToolBlockCmd, mcpToolAskCmd, mcpToolClearCmd} {
		cmd.Flags().StringVar(&mcpToolProjectFlag, "project", "", "apply policy only to project directory PATH (default: global)")
	}

	mcpToolCmd.AddCommand(mcpToolListCmd, mcpToolAllowCmd, mcpToolBlockCmd, mcpToolAskCmd, mcpToolClearCmd)
	mcpCmd.AddCommand(mcpAllowCmd, mcpBlockCmd, mcpListCmd, mcpScanCmd, mcpWhereCmd, mcpToolsCmd, mcpToolCmd)
	rootCmd.AddCommand(mcpCmd)
}
