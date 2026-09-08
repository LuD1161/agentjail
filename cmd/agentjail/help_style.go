package main

import (
	"fmt"
	"strings"

	"github.com/LuD1161/agentjail/internal/ui"
	"github.com/spf13/cobra"
)

// Cobra owns the help content; the shared UI owns its presentation.
func styledCommandHelp(cmd *cobra.Command, _ []string) {
	w := cmd.OutOrStdout()
	u := ui.New(w)
	if noColorOutput {
		u = ui.NewNoColor(w)
	}
	if cmd == rootCmd {
		ui.SetNoColor(noColorOutput)
		usage(w)
		return
	}
	fmt.Fprintln(w, u.Section(cmd.CommandPath()))
	description := cmd.Long
	if description == "" {
		description = cmd.Short
	}
	fmt.Fprintln(w, strings.TrimSpace(description))
	fmt.Fprintln(w)
	fmt.Fprintln(w, u.Section("Usage"))
	fmt.Fprintln(w, "  "+cmd.UseLine())
	if cmd.HasAvailableSubCommands() {
		fmt.Fprintln(w)
		fmt.Fprintln(w, u.Section("Commands"))
		for _, child := range cmd.Commands() {
			if child.IsAvailableCommand() || child.Name() == "help" {
				fmt.Fprintln(w, "  "+u.KeyValue(child.Name(), child.Short, ""))
			}
		}
	}
	if cmd.HasExample() {
		fmt.Fprintln(w)
		fmt.Fprintln(w, u.Section("Examples"))
		fmt.Fprintln(w, cmd.Example)
	}
	cmd.InitDefaultHelpFlag()
	if flags := cmd.LocalFlags(); flags.HasAvailableFlags() {
		fmt.Fprintln(w)
		fmt.Fprintln(w, u.Section("Flags"))
		fmt.Fprint(w, flags.FlagUsages())
	}
	if flags := cmd.InheritedFlags(); flags.HasAvailableFlags() {
		fmt.Fprintln(w)
		fmt.Fprintln(w, u.Section("Global Flags"))
		fmt.Fprint(w, flags.FlagUsages())
	}
	fmt.Fprintln(w)
}
