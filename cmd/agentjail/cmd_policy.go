package main

import (
	"os"

	"github.com/spf13/cobra"
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage optional hardening rules",
	Long:  "Manage core, library, and custom policy rules. See 'agentjail policy --help' for subcommands.",
}

var policyListCmd = &cobra.Command{
	Use:   "list",
	Short: "Show all rules and their status",
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runPolicyList())
	},
}

var policyEnableCmd = &cobra.Command{
	Use:   "enable <name|rule_id>",
	Short: "Enable a library rule or re-enable a disabled rule_id",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runPolicyEnable(args[0]))
	},
}

var policyDisableForce bool

var policyDisableCmd = &cobra.Command{
	Use:   "disable <name|rule_id>",
	Short: "Disable a rule (core rule_ids require --force and interactive TTY)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runPolicyDisableWithForce(args[0], policyDisableForce))
	},
}

var policyAddCmd = &cobra.Command{
	Use:   "add <file.rego>",
	Short: "Validate and install a custom rule file into ~/.agentjail/rules/",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runPolicyAdd(args[0]))
	},
}

var policyRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove a custom rule by file stem",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runPolicyRemove(args[0]))
	},
}

func init() {
	policyDisableCmd.Flags().BoolVar(&policyDisableForce, "force", false, "Force disable of a core rule (requires interactive TTY confirmation)")

	policyCmd.AddCommand(policyListCmd)
	policyCmd.AddCommand(policyEnableCmd)
	policyCmd.AddCommand(policyDisableCmd)
	policyCmd.AddCommand(policyAddCmd)
	policyCmd.AddCommand(policyRemoveCmd)

	rootCmd.AddCommand(policyCmd)
}
