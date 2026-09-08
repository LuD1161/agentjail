package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestStyledHelpIncludesNestedLocalAndInheritedOptions(t *testing.T) {
	var out bytes.Buffer
	parent := &cobra.Command{Use: "example"}
	parent.SetOut(&out)
	parent.SetHelpFunc(styledCommandHelp)
	parent.PersistentFlags().Bool("shared", false, "shared option")
	child := &cobra.Command{Use: "report", Short: "Show a report", Example: "  example report --json"}
	child.Flags().Bool("json", false, "JSON output")
	parent.AddCommand(child)
	if err := child.Help(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"example report", "Show a report", "Usage", "Examples", "--json", "--shared", "--help"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("help missing %q: %s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("non-terminal help contains ANSI escapes")
	}
}

func TestRunHelpAliasMatchesHelpFlag(t *testing.T) {
	var alias, flag bytes.Buffer
	previous := runCmd.OutOrStdout()
	t.Cleanup(func() { runCmd.SetOut(previous) })
	runCmd.SetOut(&alias)
	runCmd.Run(runCmd, []string{"help"})
	runCmd.SetOut(&flag)
	runCmd.Run(runCmd, []string{"--help"})
	if alias.String() == "" || alias.String() != flag.String() {
		t.Fatalf("run help and run --help differ:\n%s\n%s", alias.String(), flag.String())
	}
	_, args, err := parseRunOptions([]string{"--", "help"})
	if err != nil || len(args) != 2 || args[0] != "--" || args[1] != "help" {
		t.Fatalf("explicit separator must preserve child named help: %q, %v", args, err)
	}
}
