package main

import (
	"os"

	"github.com/spf13/cobra"
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage optional hardening rules",
	Long:  "List, enable, disable, install, or remove core, library, and custom policy rules.",
}

var policyListCmd = &cobra.Command{
	Use:   "list",
	Short: "Show all rules and their status",
	Run: func(cmd *cobra.Command, args []string) {
		if policyListJSON {
			home, err := os.UserHomeDir()
			if err != nil {
				cmd.PrintErrf("agentjail policy list: %v\n", err)
				os.Exit(1)
			}
			if err := printPolicyReportJSONOutput(os.Stdout, home); err != nil {
				cmd.PrintErrf("agentjail policy list: %v\n", err)
				os.Exit(1)
			}
			return
		}
		os.Exit(runPolicyList())
	},
}

var policyListJSON bool

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
	Short: "Disable a library rule or a user-tunable core rule",
	Long: `Disable a library rule by name, or suppress a known rule by rule_id.

Core does not mean locked. Most core rules are user-tunable, but disabling one
weakens AgentJail's standard security posture and therefore requires both
--force and confirmation by a human in an interactive terminal. Agents and
non-interactive scripts are refused even when they pass --force.

Locked self-protection rules can never be disabled:

  file_policy/agentjail_self
  command_policy/no-policy-mutation
  resolver/default (and all resolver/* rules)

Run 'agentjail policy list' to see whether each rule is on, off, or locked.`,
	Args: cobra.ExactArgs(1),
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
	policyListCmd.Flags().BoolVar(&policyListJSON, "json", false, "write the bounded policy inventory and local match history as JSON")
	policyDisableCmd.Flags().BoolVar(&policyDisableForce, "force", false, "allow a non-locked core rule to be disabled after interactive human confirmation")

	policyCmd.AddCommand(policyListCmd)
	policyCmd.AddCommand(policyEnableCmd)
	policyCmd.AddCommand(policyDisableCmd)
	policyCmd.AddCommand(policyAddCmd)
	policyCmd.AddCommand(policyRemoveCmd)

	rootCmd.AddCommand(policyCmd)
}
