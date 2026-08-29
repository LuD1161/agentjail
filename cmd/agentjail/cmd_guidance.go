package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/LuD1161/agentjail/internal/agentguidance"
	"github.com/LuD1161/agentjail/internal/agents"
	"github.com/spf13/cobra"
)

type guidanceReconciler interface {
	ReconcileGuidance(agents.Env) error
}

var reconcileGuidanceCmd = &cobra.Command{
	Use:    agentguidance.ReconcileCommand,
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("determine home directory: %w", err)
		}
		return reconcileInstalledAgentGuidance(home)
	},
}

func reconcileInstalledAgentGuidance(home string) error {
	env := buildAgentsEnv(home)
	var errs []error
	for _, agent := range agents.Registry() {
		reconciler, ok := agent.(guidanceReconciler)
		if !ok || !agent.Status(env).Installed {
			continue
		}
		if err := reconciler.ReconcileGuidance(env); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", agent.DisplayName(), err))
		}
	}
	return errors.Join(errs...)
}

func init() {
	rootCmd.AddCommand(reconcileGuidanceCmd)
}
