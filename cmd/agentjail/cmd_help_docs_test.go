package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func TestCredentialSetHelpDefinesCredentialNameAndSources(t *testing.T) {
	help := credentialSetCmd.Long + "\n" + credentialSetCmd.Example
	for _, flagName := range []string{"from-env", "from-file", "from-stdin", "label", "tag"} {
		help += "\n" + credentialSetCmd.Flags().Lookup(flagName).Usage
	}

	for _, want := range []string{
		"arbitrary identifier",
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"KUBECONFIG",
		"SLACK_TOKEN",
		"descriptive only",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("credential set help does not explain %q", want)
		}
	}
	if credentialSetCmd.Flags().Lookup("tool") != nil || credentialSetCmd.Flags().Lookup("from-current-env") != nil {
		t.Fatal("provider-coupled credential flags remain public")
	}
}

func TestCredentialListHelpExplainsOutputAndNextStep(t *testing.T) {
	help := strings.Join(strings.Fields(credentialListCmd.Long+"\n"+credentialListCmd.Example), " ")
	for _, want := range []string{
		"never printed",
		"exact returned ID",
		"--credential aws-read-only-cred-dev",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("credential list help does not explain %q", want)
		}
	}
}

func TestCommandsWithoutOptionsDoNotAdvertiseFlags(t *testing.T) {
	configureCommandUseLines(rootCmd)
	var visit func(*cobra.Command)
	visit = func(parent *cobra.Command) {
		for _, cmd := range parent.Commands() {
			if cmd.Hidden {
				continue
			}
			hasCommandOption := false
			markOption := func(flag *pflag.Flag) {
				if flag.Name != "help" {
					hasCommandOption = true
				}
			}
			cmd.LocalNonPersistentFlags().VisitAll(markOption)
			cmd.PersistentFlags().VisitAll(markOption)
			cmd.InheritedFlags().VisitAll(func(flag *pflag.Flag) {
				if rootCmd.PersistentFlags().Lookup(flag.Name) == nil {
					markOption(flag)
				}
			})
			if !hasCommandOption && strings.Contains(cmd.UseLine(), "[flags]") {
				t.Errorf("%s usage advertises nonexistent command options: %s", cmd.CommandPath(), cmd.UseLine())
			}
			visit(cmd)
		}
	}
	visit(rootCmd)
}

func TestAllowHelpMapsIntentToHostSubcommand(t *testing.T) {
	help := strings.Join(strings.Fields(allowCmd.Long+"\n"+allowCmd.Example), " ")
	for _, want := range []string{
		"agentjail allow host <hostname>",
		"DNS name",
		"not a URL",
		"does not grant access by itself",
		"future",
		"current",
		"--reason",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("allow help does not explain %q", want)
		}
	}
}

func TestGrantDecisionExamplesExplainHowToGetID(t *testing.T) {
	for _, cmd := range []*cobra.Command{grantApproveCmd, grantDenyCmd} {
		for _, want := range []string{"First list pending requests", "copy the GRANT_ID", "Then"} {
			if !strings.Contains(cmd.Example, want) {
				t.Errorf("%s example does not explain %q", cmd.CommandPath(), want)
			}
		}
	}
}

func TestSelfExplanatoryCommandsDoNotRepeatUsageAsExamples(t *testing.T) {
	for _, cmd := range []*cobra.Command{
		grantListCmd, grantHistoryCmd, mcpListCmd, policyListCmd, statusCmd,
		telemetryStatusCmd, telemetryEnableCmd, telemetryDisableCmd,
		telemetryViewCmd, telemetryResetCmd, trustListCmd, versionCmd,
	} {
		if strings.TrimSpace(cmd.Example) != "" {
			t.Errorf("%s has a tautological example %q", cmd.CommandPath(), cmd.Example)
		}
	}
}

func TestCanonicalCommandHierarchy(t *testing.T) {
	for _, path := range [][]string{
		{"grant", "list"}, {"grant", "history"},
		{"mcp", "tool", "list"},
		{"telemetry", "status"}, {"telemetry", "reset"},
		{"trust", "add"}, {"trust", "remove"},
	} {
		cmd, remaining, err := rootCmd.Find(path)
		if err != nil || len(remaining) != 0 || cmd == rootCmd {
			t.Errorf("canonical command %q not registered: cmd=%v remaining=%v err=%v", strings.Join(path, " "), cmd, remaining, err)
		}
	}
	for _, cmd := range []*cobra.Command{grantsCmd, mcpToolsCmd, untrustCmd} {
		if !cmd.Hidden {
			t.Errorf("compatibility command %s remains visible", cmd.CommandPath())
		}
	}
}

func TestSecretCommandIsNotPublic(t *testing.T) {
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == "secret" {
			t.Fatal("unfinished phantom-token secret command remains registered")
		}
	}
}

func TestPolicyDisableHelpDistinguishesCoreFromLocked(t *testing.T) {
	help := strings.Join(strings.Fields(policyDisableCmd.Long+"\n"+policyDisableCmd.Example), " ")
	for _, want := range []string{
		"Core does not mean locked",
		"requires both --force",
		"interactive terminal",
		"non-interactive scripts are refused",
		"Locked self-protection rules can never be disabled",
		"file_policy/agentjail_self",
		"command_policy/no-policy-mutation",
		"resolver/default",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("policy disable help does not explain %q", want)
		}
	}
	if strings.Contains(policyDisableCmd.Example, "custom/example/rule") {
		t.Error("policy disable help demonstrates an unknown custom rule_id")
	}
}

func TestSingleSubcommandParentsShowConcreteInvocation(t *testing.T) {
	var visit func(*cobra.Command)
	visit = func(parent *cobra.Command) {
		visibleChildren := make([]*cobra.Command, 0, len(parent.Commands()))
		for _, child := range parent.Commands() {
			if !child.Hidden {
				visibleChildren = append(visibleChildren, child)
			}
			visit(child)
		}
		if len(visibleChildren) != 1 {
			return
		}
		invocation := parent.CommandPath() + " " + visibleChildren[0].Name()
		if !strings.Contains(parent.Long+"\n"+parent.Example, invocation) {
			t.Errorf("%s has one subcommand but does not show %q in its help", parent.CommandPath(), invocation)
		}
	}
	visit(rootCmd)
}

func TestUserCLIDoesNotExposeAgentHookFlag(t *testing.T) {
	if flag := rootCmd.PersistentFlags().Lookup("agent"); flag != nil {
		t.Fatalf("user CLI exposes hook-only --agent flag: %s", flag.Usage)
	}
	var output strings.Builder
	usage(&output)
	if strings.Contains(stripANSI(output.String()), "--agent") {
		t.Fatal("styled user help exposes hook-only --agent flag")
	}
}

func TestCompletionCommandsMatchSupportedShells(t *testing.T) {
	configureCompletionCommands(rootCmd)
	completion, _, err := rootCmd.Find([]string{"completion"})
	if err != nil {
		t.Fatalf("find completion command: %v", err)
	}
	got := make([]string, 0, len(completion.Commands()))
	for _, cmd := range completion.Commands() {
		if !cmd.Hidden {
			got = append(got, cmd.Name())
		}
	}
	want := []string{"bash", "fish", "zsh"}
	if !slices.Equal(got, want) {
		t.Fatalf("completion shells = %v, want %v", got, want)
	}
}
