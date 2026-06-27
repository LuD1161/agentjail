package main

import (
	"os"

	"github.com/spf13/cobra"
)

// helpTopicCmd replaces cobra's built-in help command with the legacy styled
// usage output. Using SetHelpCommand avoids registering a duplicate "help"
// entry alongside cobra's own.
var helpTopicCmd = &cobra.Command{
	Use:   "help [topic]",
	Short: "Show help for a topic",
	Long:  "Show detailed help for a specific topic. Run without arguments to see available topics.",
	Run: func(cmd *cobra.Command, args []string) {
		usage(os.Stdout)
	},
}

func init() {
	rootCmd.SetHelpCommand(helpTopicCmd)
}
