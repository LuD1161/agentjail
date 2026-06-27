package main

import (
	"os"

	"github.com/spf13/cobra"
)

var updateCmd = &cobra.Command{
	Use:                "update",
	Short:              "Update agentjail binaries to the latest release",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runUpdate(args))
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)
}
