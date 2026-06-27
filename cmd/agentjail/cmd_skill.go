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
}

// skillListCmd: runSkillList already handles --json via flag.FlagSet, so we
// disable cobra flag parsing and hand args through as-is.
var skillListCmd = &cobra.Command{
	Use:                "list [--json]",
	Short:              "Show all known skills with policy status",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runSkillList(args))
	},
}

// allow/block/ask/clear all go through runSkillMutate which parses --project
// via its own flag.FlagSet. Disable cobra flag parsing so the flag reaches
// runSkillMutate intact.

var skillAllowCmd = &cobra.Command{
	Use:                "allow [--project <dir>] <skill>",
	Short:              "Permit a specific skill",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runSkillMutate("allow", args))
	},
}

var skillBlockCmd = &cobra.Command{
	Use:                "block [--project <dir>] <skill>",
	Short:              "Deny a specific skill",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runSkillMutate("block", args))
	},
}

var skillAskCmd = &cobra.Command{
	Use:                "ask [--project <dir>] <skill>",
	Short:              "Require confirmation for a specific skill",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runSkillMutate("ask", args))
	},
}

var skillClearCmd = &cobra.Command{
	Use:                "clear [--project <dir>] <skill>",
	Short:              "Remove per-skill policy (revert to inherited behavior)",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runSkillMutate("clear", args))
	},
}

func init() {
	skillCmd.AddCommand(skillListCmd, skillAllowCmd, skillBlockCmd, skillAskCmd, skillClearCmd)
	rootCmd.AddCommand(skillCmd)
}
