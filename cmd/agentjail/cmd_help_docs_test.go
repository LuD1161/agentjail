package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestVisibleCommandsIncludeExamples(t *testing.T) {
	var visit func(*cobra.Command)
	visit = func(parent *cobra.Command) {
		for _, cmd := range parent.Commands() {
			// Cobra owns completion help and embeds shell-specific setup steps.
			if cmd.Hidden || cmd.Name() == "completion" || cmd.Name() == "help" {
				continue
			}
			if strings.TrimSpace(cmd.Example) == "" {
				t.Errorf("%s help has no examples", cmd.CommandPath())
			}
			visit(cmd)
		}
	}

	if strings.TrimSpace(rootCmd.Example) == "" {
		t.Error("agentjail root help has no examples")
	}
	if strings.TrimSpace(helpTopicCmd.Example) == "" {
		t.Error("agentjail help command has no examples")
	}
	visit(rootCmd)
}
