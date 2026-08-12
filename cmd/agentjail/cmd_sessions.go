package main

import (
	"os"

	"github.com/spf13/cobra"
)

var sessionsCmd = &cobra.Command{
	Use:                "sessions",
	Short:              "List recorded agent sessions",
	Long:               "List recorded sessions from the local SQLite event store. Use the session ID with 'agentjail replay --session ID'.",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		if helpRequested(cmd, args) {
			return
		}
		os.Exit(runSessions(args))
	},
}

func init() {
	rootCmd.AddCommand(sessionsCmd)
}
