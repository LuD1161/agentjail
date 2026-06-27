package main

import (
	"os"

	"github.com/spf13/cobra"
)

var logsCmd = &cobra.Command{
	Use:                "logs",
	Short:              "View policy decisions",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runLogs(args))
	},
}

func init() {
	rootCmd.AddCommand(logsCmd)
}
