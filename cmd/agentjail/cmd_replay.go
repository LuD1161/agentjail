package main

import (
	"os"

	"github.com/spf13/cobra"
)

var replayCmd = &cobra.Command{
	Use:                "replay",
	Short:              "Replay decisions from a saved session",
	Long:               "Replay recorded decisions for one session. Use 'agentjail sessions' to find and filter session IDs, then pass an exact ID or unique prefix with --session.",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		if helpRequested(cmd, args) {
			return
		}
		os.Exit(runReplay(args))
	},
}

func init() {
	rootCmd.AddCommand(replayCmd)
}
