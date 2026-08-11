package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var credentialCmd = &cobra.Command{
	Use:   "credential",
	Short: "Manage credentials for shielded CLI tools",
	Long: `Manage static credentials in AgentJail's encrypted local broker.

These credentials are delivered directly to explicitly selected CLI tools.
They are not narrowed by a credential policy or JIT issuer.`,
}

var (
	credentialSetTool      string
	credentialSetFromEnv   bool
	credentialSetFromFile  string
	credentialSetFromStdin bool
	credentialSetLabel     string
	credentialSetAccount   string
	credentialSetContext   string
)

var credentialSetCmd = &cobra.Command{
	Use:   "set <name>",
	Short: "Import a static AWS, Kubernetes, or GitHub CLI credential",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		value, err := buildCredentialValue(credentialSourceOptions{
			Tool:      credentialSetTool,
			FromEnv:   credentialSetFromEnv,
			FromFile:  credentialSetFromFile,
			FromStdin: credentialSetFromStdin,
			Label:     credentialSetLabel,
			Account:   credentialSetAccount,
			Context:   credentialSetContext,
		}, os.Stdin, os.Getenv, os.ReadFile)
		if err != nil {
			return err
		}
		if err := callSecretsSetStdin(args[0], value); err != nil {
			return fmt.Errorf("store credential in encrypted broker: %w", err)
		}
		fmt.Fprintf(os.Stdout, "credential stored: %s (tool=%s)\n", args[0], credentialSetTool)
		return nil
	},
}

var credentialListCmd = &cobra.Command{
	Use:   "list",
	Short: "List broker credential names without values",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return callSecretsCommand("list")
	},
}

var credentialRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove a credential from the encrypted broker",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return callSecretsDelete(args[0])
	},
}

func init() {
	credentialSetCmd.Flags().StringVar(&credentialSetTool, "tool", "", "credential contract: aws, kubectl, or gh (required)")
	credentialSetCmd.Flags().BoolVar(&credentialSetFromEnv, "from-current-env", false, "import the tool's standard credential environment variables")
	credentialSetCmd.Flags().StringVar(&credentialSetFromFile, "from-file", "", "import credential content from PATH")
	credentialSetCmd.Flags().BoolVar(&credentialSetFromStdin, "from-stdin", false, "import credential content from stdin")
	credentialSetCmd.Flags().StringVar(&credentialSetLabel, "label", "", "non-secret label shown to coding agents")
	credentialSetCmd.Flags().StringVar(&credentialSetAccount, "account", "", "non-secret account or tenant identifier")
	credentialSetCmd.Flags().StringVar(&credentialSetContext, "context", "", "non-secret cluster or context identifier")
	_ = credentialSetCmd.MarkFlagRequired("tool")
	credentialCmd.AddCommand(credentialSetCmd, credentialListCmd, credentialRemoveCmd)
	rootCmd.AddCommand(credentialCmd)
}
