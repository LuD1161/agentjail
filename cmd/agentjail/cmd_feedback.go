package main

import (
	"os"

	"github.com/spf13/cobra"
)

var feedbackCmd = &cobra.Command{
	Use:                "feedback",
	Short:              "Send anonymous feedback to the maintainers",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runFeedback(args))
	},
}

func init() {
	rootCmd.AddCommand(feedbackCmd)
}
