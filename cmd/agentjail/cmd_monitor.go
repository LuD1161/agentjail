package main

import (
	"os"

	"github.com/spf13/cobra"
)

var monitorCmd = &cobra.Command{
	Use:                "monitor",
	Short:              "Show what policy would have blocked (monitor mode report)",
	Long:               "Summarize decisions recorded while enforcement was in monitor mode. Rows may come from an earlier monitor-mode window even when enforcement is currently enabled.",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		if helpRequested(cmd, args) {
			return
		}
		os.Exit(runMonitor(args))
	},
}

func init() {
	rootCmd.AddCommand(monitorCmd)
}
