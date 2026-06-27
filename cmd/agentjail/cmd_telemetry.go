package main

import (
	"os"

	"github.com/spf13/cobra"
)

var telemetryCmd = &cobra.Command{
	Use:                "telemetry",
	Short:              "Manage anonymous usage statistics",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runTelemetry(args))
	},
}

func init() {
	rootCmd.AddCommand(telemetryCmd)
}
