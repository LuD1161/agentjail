package main

import (
	"os"

	"github.com/spf13/cobra"
)

var telemetryCmd = &cobra.Command{
	Use:   "telemetry",
	Short: "Review and control privacy-preserving usage statistics",
	Long: `Review whether usage statistics are enabled, inspect locally queued events,
or change consent. Events use a random installation ID and do not include
source code, command arguments, file paths, credential values, or policy data.`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runTelemetry([]string{"status"}))
	},
}

func telemetryActionCommand(use, short, long string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Long:  long,
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			os.Exit(runTelemetry([]string{cmd.Name()}))
		},
	}
}

var telemetryStatusJSON bool
var telemetryStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show telemetry consent and identifier",
	Long:  "Show whether telemetry is enabled, which setting selected that state, and the random installation ID attached to queued events.",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runArgs := []string{"status"}
		if telemetryStatusJSON {
			runArgs = append(runArgs, "json")
		}
		os.Exit(runTelemetry(runArgs))
	},
}
var telemetryEnableCmd = telemetryActionCommand("enable", "Enable privacy-preserving usage statistics", "Persist consent to send privacy-preserving usage statistics for this installation.")
var telemetryDisableCmd = telemetryActionCommand("disable", "Disable usage statistics", "Persist an opt-out so new usage events are not sent.")
var telemetryViewCmd = telemetryActionCommand("view", "Inspect locally queued telemetry events", "Print the complete local telemetry spool as JSON so you can review what would be sent.")
var telemetryResetCmd = telemetryActionCommand("reset", "Replace the random ID and clear queued events", "Delete all locally queued telemetry events and replace the random installation ID. This cannot be undone.")
var telemetryMacOSSetupCmd = &cobra.Command{
	Use:    "macos-setup <stage> <outcome>",
	Hidden: true,
	Args:   cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runTelemetry([]string{cmd.Name(), args[0], args[1]}))
	},
}

func init() {
	telemetryStatusCmd.Flags().BoolVar(&telemetryStatusJSON, "json", false, "print machine-readable status without the anonymous ID")
	telemetryCmd.AddCommand(telemetryStatusCmd, telemetryEnableCmd, telemetryDisableCmd, telemetryViewCmd, telemetryResetCmd, telemetryMacOSSetupCmd)
	rootCmd.AddCommand(telemetryCmd)
}
