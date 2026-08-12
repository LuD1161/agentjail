package main

import (
	"os"

	"github.com/spf13/cobra"
)

var feedbackCmd = &cobra.Command{
	Use:                "feedback",
	Short:              "Send feedback with disclosed diagnostic metadata",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		if helpRequested(cmd, args) {
			return
		}
		os.Exit(runFeedback(args))
	},
}

func init() {
	rootCmd.AddCommand(feedbackCmd)
}
