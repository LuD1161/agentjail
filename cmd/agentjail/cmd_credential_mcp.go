package main

import (
	"os"

	"github.com/LuD1161/agentjail/internal/credentialmcp"
	"github.com/spf13/cobra"
)

var credentialMCPCmd = &cobra.Command{
	Use:    "credential-mcp",
	Short:  "Serve the session credential MCP (internal)",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return credentialmcp.RunFromEnvironment(cmd.Context(), os.Stdin, os.Stdout)
	},
}

func init() {
	rootCmd.AddCommand(credentialMCPCmd)
}
