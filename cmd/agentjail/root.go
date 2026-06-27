package main

import (
	"os"

	"github.com/spf13/cobra"
)

// agentSlug is set by the persistent --agent flag and is available to all
// subcommands (including legacy pass-through wrappers).
var agentSlug string

// updateCleanup is the wait function returned by maybeRunUpdateCheck(). It is
// stored here so PersistentPreRun can start the goroutine and PersistentPostRun
// can block until it finishes (mirrors the original `defer maybeRunUpdateCheck()()`).
var updateCleanup func()

var rootCmd = &cobra.Command{
	Use:           "agentjail",
	Short:         "policy guardrails for agents",
	Long:          "agentjail gives every coding agent a policy guardrail -- enforcing what files\nit can read/write, which MCPs it can call, and which shell commands it can run.",
	SilenceUsage:  true,
	SilenceErrors: true,

	// Show the legacy styled usage when the user runs `agentjail` with no args.
	RunE: func(cmd *cobra.Command, args []string) error {
		usage(os.Stderr)
		os.Exit(2)
		return nil
	},

	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Mirror main.go: record feature usage for every command except telemetry.
		if cmd.Name() != "telemetry" {
			recordFeatureUsed(cmd.Name())
			// Start the throttled update check + heartbeat asynchronously.
			// Never adds latency; all network/file errors are silently discarded.
			// The cleanup func is saved and called in PersistentPostRun.
			updateCleanup = maybeRunUpdateCheck()
		}
	},

	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if updateCleanup != nil {
			updateCleanup()
			updateCleanup = nil
		}
	},
}

func init() {
	// Persistent --agent flag mirrors the old parseTopLevelFlags handling.
	rootCmd.PersistentFlags().StringVar(&agentSlug, "agent", "", "Agent slug")
}

// Execute runs the root command and exits non-zero on error.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
