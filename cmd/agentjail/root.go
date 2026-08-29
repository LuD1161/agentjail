package main

import (
	"os"
	"strings"

	"github.com/LuD1161/agentjail/internal/ui"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var noColorOutput bool

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

	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		ui.SetNoColor(noColorOutput)
		// Mirror main.go: record feature usage for every command except telemetry.
		if !strings.HasPrefix(cmd.CommandPath(), "agentjail telemetry") && cmd.Name() != "approval-exec" && cmd.Name() != "credential-mcp" && cmd.Name() != "_reconcile-guidance" {
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
	rootCmd.PersistentFlags().BoolVar(&noColorOutput, "no-color", false, "Disable color in human-readable output")

	// Show the legacy styled usage when the user runs `agentjail` with no
	// args. Assigned in init() (rather than inline in the var literal above)
	// so that usage()'s reference back to rootCmd.Commands() (via
	// commandList) doesn't create a package-level initialization cycle.
	rootCmd.RunE = func(cmd *cobra.Command, args []string) error {
		usage(os.Stderr)
		os.Exit(2)
		return nil
	}
}

// Execute runs the root command and exits non-zero on error.
func Execute() {
	configureCompletionCommands(rootCmd)
	configureCommandUseLines(rootCmd)
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func configureCompletionCommands(root *cobra.Command) {
	root.InitDefaultCompletionCmd()
	for _, cmd := range root.Commands() {
		if cmd.Name() != "completion" {
			continue
		}
		for _, shell := range cmd.Commands() {
			if shell.Name() == "powershell" {
				// Native Windows is deferred, so keep the completion surface to
				// documented macOS/Linux shells. See ADR 0027-cobra-cli-framework.
				cmd.RemoveCommand(shell)
			}
		}
	}
}

// Omit [flags] when a command has no options of its own. Inherited global
// flags remain documented in their separate help section.
func configureCommandUseLines(root *cobra.Command) {
	var visit func(*cobra.Command)
	visit = func(cmd *cobra.Command) {
		hasCommandOption := false
		markOption := func(flag *pflag.Flag) {
			if flag.Name != "help" {
				hasCommandOption = true
			}
		}
		cmd.LocalNonPersistentFlags().VisitAll(markOption)
		cmd.PersistentFlags().VisitAll(markOption)
		cmd.InheritedFlags().VisitAll(func(flag *pflag.Flag) {
			if root.PersistentFlags().Lookup(flag.Name) == nil {
				markOption(flag)
			}
		})
		cmd.DisableFlagsInUseLine = !hasCommandOption || strings.Contains(cmd.Use, "[flags]")
		for _, child := range cmd.Commands() {
			visit(child)
		}
	}
	visit(root)
}
