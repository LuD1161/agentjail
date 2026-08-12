// cmd_skill.go -- cobra command tree for `agentjail skill`.
//
// Subcommands:
//
//	agentjail skill list [--json]
//	agentjail skill allow <skill> [--project <dir>]
//	agentjail skill block <skill> [--project <dir>]
//	agentjail skill ask   <skill> [--project <dir>]
//	agentjail skill clear <skill> [--project <dir>]
//
// runSkillList parses --json itself, so its cobra command uses
// DisableFlagParsing and passes args through unchanged.
//
// runSkillMutate parses --project itself (via flag.FlagSet), so the
// allow/block/ask/clear commands likewise use DisableFlagParsing.
package main

import (
	"os"

	"github.com/spf13/cobra"
)

var skillCmd = &cobra.Command{
	Use:   "skill",
	Short: "Manage skill allow/block/ask lists",
	Long:  "Review skills observed in AgentJail's audit history and manage their policy. Mutations must run from a trusted interactive terminal.",
}

// skillListCmd: runSkillList already handles --json via flag.FlagSet, so we
// disable cobra flag parsing and hand args through as-is.
var skillListCmd = &cobra.Command{
	Use:                "list",
	Short:              "Show skills observed in audit history with policy status",
	Long:               "List skill names observed in recorded agent activity together with their effective policy. This does not scan installed skill files.",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		if helpRequested(cmd, args) {
			return
		}
		os.Exit(runSkillList(args))
	},
}

// allow/block/ask/clear all go through runSkillMutate which parses --project
// via its own flag.FlagSet. Disable cobra flag parsing so the flag reaches
// runSkillMutate intact.

var skillAllowCmd = &cobra.Command{
	Use:                "allow <skill>",
	Short:              "Permit a specific skill",
	Long:               "Permit an exact skill name from 'agentjail skill list'. Run from a trusted interactive terminal. Without --project, update global policy.",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		if helpRequested(cmd, args) {
			return
		}
		os.Exit(runSkillMutate("allow", args))
	},
}

var skillBlockCmd = &cobra.Command{
	Use:                "block <skill>",
	Short:              "Deny a specific skill",
	Long:               "Deny an exact skill name from 'agentjail skill list'. Run from a trusted interactive terminal. Without --project, update global policy.",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		if helpRequested(cmd, args) {
			return
		}
		os.Exit(runSkillMutate("block", args))
	},
}

var skillAskCmd = &cobra.Command{
	Use:                "ask <skill>",
	Short:              "Require confirmation for a specific skill",
	Long:               "Require confirmation for an exact skill name from 'agentjail skill list'. Run from a trusted interactive terminal. Without --project, update global policy.",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		if helpRequested(cmd, args) {
			return
		}
		os.Exit(runSkillMutate("ask", args))
	},
}

var skillClearCmd = &cobra.Command{
	Use:                "clear <skill>",
	Short:              "Remove per-skill policy (revert to inherited behavior)",
	Long:               "Clear explicit policy for an exact skill name from 'agentjail skill list'. Run from a trusted interactive terminal. Without --project, update global policy.",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		if helpRequested(cmd, args) {
			return
		}
		os.Exit(runSkillMutate("clear", args))
	},
}

func init() {
	skillCmd.AddCommand(skillListCmd, skillAllowCmd, skillBlockCmd, skillAskCmd, skillClearCmd)
	rootCmd.AddCommand(skillCmd)
}
