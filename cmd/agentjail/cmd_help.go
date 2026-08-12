package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// helpTopicCmd replaces cobra's built-in help command with the legacy styled
// usage output, and dispatches "agentjail help <command>" to runHelp (help.go)
// for command-tree help or the getting-started guide. Using SetHelpCommand avoids registering a duplicate
// "help" entry alongside cobra's own.
//
// RunE (not Run+os.Exit) is used deliberately: runHelp's exit code needs to
// reach the process exit status for an unknown topic, but calling os.Exit
// directly from Run would terminate the process mid-test when this command
// is exercised via rootCmd.Execute() in-process (see help_test.go). Returning
// an error lets cobra's normal Execute()/main() error path set exit 1
// without an in-process os.Exit call.
var helpTopicCmd = &cobra.Command{
	Use:   "help [command] [subcommand]",
	Short: "Show command help or the getting-started guide",
	Long: `Show the same help as '<command> [subcommand] --help', or open the
'getting-started' cross-command guide. Run without arguments to show the full
command list.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			usage(os.Stdout)
			return nil
		}
		if code := runHelp(args); code != 0 {
			return fmt.Errorf("unknown help command or guide %q", strings.Join(args, " "))
		}
		return nil
	},
}

func init() {
	rootCmd.SetHelpCommand(helpTopicCmd)
}
