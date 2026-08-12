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
	Long: `Import one credential into AgentJail's encrypted local broker.

<name> is the identifier you choose for this credential, such as
aws/development. You use the same name later with
'agentjail run --credential=aws=aws/development -- ...'. The --tool value
selects both the credential format and the shielded CLI that may receive it.

Choose exactly one source: --from-current-env, --from-file, or --from-stdin.
--from-current-env reads variables inherited from the shell as follows:

  --tool aws       Requires AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.
                   Also imports optional AWS_SESSION_TOKEN and
                   AWS_REGION or AWS_DEFAULT_REGION.
  --tool kubectl   Reads the kubeconfig file named by KUBECONFIG, which must
                   contain exactly one file path.
  --tool gh        Reads GH_TOKEN, falling back to GITHUB_TOKEN.`,
	Args: cobra.ExactArgs(1),
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
	Short: "List stored credential identifiers without revealing their values",
	Long: `List the user-chosen identifiers stored in AgentJail's encrypted broker,
one per line, such as aws/development or github/work.

Credential values and metadata are never printed. No output means the broker
contains no credentials. Use a returned identifier as NAME in
'agentjail run --credential=TOOL=NAME -- <agent>'.`,
	Args: cobra.NoArgs,
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
	credentialSetCmd.Flags().StringVar(&credentialSetTool, "tool", "", "CLI allowed to receive the credential: aws, kubectl, or gh (required)")
	credentialSetCmd.Flags().BoolVar(&credentialSetFromEnv, "from-current-env", false, "import from the current shell environment using the variables documented above")
	credentialSetCmd.Flags().StringVar(&credentialSetFromFile, "from-file", "", "import a kubeconfig or other credential content from PATH")
	credentialSetCmd.Flags().BoolVar(&credentialSetFromStdin, "from-stdin", false, "read credential content from standard input (useful for tokens and scripts)")
	credentialSetCmd.Flags().StringVar(&credentialSetLabel, "label", "", "non-secret label shown to coding agents")
	credentialSetCmd.Flags().StringVar(&credentialSetAccount, "account", "", "non-secret account or tenant identifier")
	credentialSetCmd.Flags().StringVar(&credentialSetContext, "context", "", "non-secret cluster or context identifier")
	_ = credentialSetCmd.MarkFlagRequired("tool")
	credentialCmd.AddCommand(credentialSetCmd, credentialListCmd, credentialRemoveCmd)
	rootCmd.AddCommand(credentialCmd)
}
