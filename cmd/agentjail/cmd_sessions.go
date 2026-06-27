package main

import (
	"os"

	"github.com/spf13/cobra"
)

var sessionsCmd = &cobra.Command{
	Use:                "sessions",
	Short:              "List and inspect agent sessions",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runSessions(args))
	},
}

func init() {
	rootCmd.AddCommand(sessionsCmd)
}
