package main

import (
	"os"

	"github.com/spf13/cobra"
)

var statsCmd = &cobra.Command{
	Use:                "stats",
	Short:              "Summarize final outcomes, policy denies, latency, and recording coverage",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		if helpRequested(cmd, args) {
			return
		}
		os.Exit(runStats(args))
	},
}

func init() {
	rootCmd.AddCommand(statsCmd)
}
