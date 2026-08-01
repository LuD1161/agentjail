package main

import (
	"os"

	"github.com/spf13/cobra"
)

var costCmd = &cobra.Command{
	Use:                "cost",
	Short:              "Summarize agent spending across projects and models",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		if helpRequested(cmd, args) {
			return
		}
		os.Exit(runCost(args))
	},
}

func init() {
	rootCmd.AddCommand(costCmd)
}
