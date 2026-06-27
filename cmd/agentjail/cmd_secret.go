package main

import (
	"os"

	"github.com/spf13/cobra"
)

var secretCmd = &cobra.Command{
	Use:                "secret",
	Short:              "Manage scoped secret grants",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runSecret(args))
	},
}

func init() {
	rootCmd.AddCommand(secretCmd)
}
