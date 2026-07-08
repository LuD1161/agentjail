package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// helpTopicCmd replaces cobra's built-in help command with the legacy styled
// usage output, and dispatches "agentjail help <topic>" to runHelp (help.go)
// for the deeper topic screens (mcp, mcp-tools, skill, policy, scan, replay,
// getting-started). Using SetHelpCommand avoids registering a duplicate
// "help" entry alongside cobra's own.
//
// RunE (not Run+os.Exit) is used deliberately: runHelp's exit code needs to
// reach the process exit status for an unknown topic, but calling os.Exit
// directly from Run would terminate the process mid-test when this command
// is exercised via rootCmd.Execute() in-process (see help_test.go). Returning
// an error lets cobra's normal Execute()/main() error path set exit 1
// without an in-process os.Exit call.
var helpTopicCmd = &cobra.Command{
	Use:   "help [topic]",
	Short: "Show help for a topic",
	Long:  "Show detailed help for a specific topic. Run without arguments to see the full command list.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			usage(os.Stdout)
			return nil
		}
		if code := runHelp(args); code != 0 {
			return fmt.Errorf("unknown help topic %q", args[0])
		}
		return nil
	},
}

func init() {
	rootCmd.SetHelpCommand(helpTopicCmd)
}
