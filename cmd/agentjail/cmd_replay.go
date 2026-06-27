package main

import (
	"os"

	"github.com/spf13/cobra"
)

var replayCmd = &cobra.Command{
	Use:                "replay",
	Short:              "Replay decisions from a saved session",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runReplay(args))
	},
}

func init() {
	rootCmd.AddCommand(replayCmd)
}
