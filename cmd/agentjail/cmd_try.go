package main

import (
	"os"

	"github.com/spf13/cobra"
)

var tryCmd = &cobra.Command{
	Use:                "try",
	Short:              "Check whether an action would be allowed by policy (nothing is executed)",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runTry(args))
	},
}

func init() {
	rootCmd.AddCommand(tryCmd)
}
