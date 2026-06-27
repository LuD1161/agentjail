package main

import (
	"os"

	"github.com/spf13/cobra"
)

var uiCmd = &cobra.Command{
	Use:                "ui",
	Short:              "Open the local web UI",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runUI(args))
	},
}

func init() {
	rootCmd.AddCommand(uiCmd)
}
