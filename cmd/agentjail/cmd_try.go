package main

import (
	"os"

	"github.com/spf13/cobra"
)

var tryCmd = &cobra.Command{
	Use:   "try",
	Short: "Check whether an action would be allowed by policy (nothing is executed)",
	Long: `Evaluate an action against the live daemon without executing it. For a
one-shot check, choose exactly one of a positional command, --read, or --write.
With no action, open an interactive policy-evaluation REPL; press Ctrl-D to exit.`,
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		if helpRequested(cmd, args) {
			return
		}
		os.Exit(runTry(args))
	},
}

func init() {
	rootCmd.AddCommand(tryCmd)
}
