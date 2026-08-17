package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var credentialCmd = &cobra.Command{
	Use:   "credential",
	Short: "Manage credentials for shielded sessions",
	Long: `Manage static credentials in AgentJail's encrypted local broker.

Credential names are arbitrary exact identifiers. AgentJail does not infer a
provider, account, permission level, or intended command from a name or tag.`,
}

var (
	credentialSetFromEnv      []string
	credentialSetFromFile     []string
	credentialSetFromStdinEnv string
	credentialSetLabel        string
	credentialSetTags         []string
)

var credentialSetCmd = &cobra.Command{
	Use:   "set <name>",
	Short: "Store a credential under an arbitrary exact name",
	Long: `Store one credential bundle in AgentJail's encrypted local broker.

<name> is an arbitrary identifier such as aws-read-only-cred-prod or
slack-channel-read-token. Names and optional labels/tags are descriptive only;
the external service still defines what the credential can do.

Use one or more --from-env NAME flags to capture current environment values.
Use --from-file ENV=PATH to expose copied content through ENV as a private
mode-0600 session file. For a single value on stdin, use --from-stdin ENV.
Credential values must never be placed directly in command arguments.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		value, err := buildCredentialValue(credentialSourceOptions{
			FromEnv: credentialSetFromEnv, FromFile: credentialSetFromFile,
			FromStdinEnv: credentialSetFromStdinEnv,
			Label:        credentialSetLabel, Tags: credentialSetTags,
		}, os.Stdin, os.Getenv, os.ReadFile)
		if err != nil {
			return reportCredentialError(cmd, err)
		}
		if err := callSecretsSetStdin(args[0], value); err != nil {
			return reportCredentialError(cmd, fmt.Errorf("store credential in encrypted broker: %w", err))
		}
		fmt.Fprintf(os.Stdout, "credential stored: %s\n", args[0])
		return nil
	},
}

var credentialListCmd = &cobra.Command{
	Use:   "list",
	Short: "List stored credential identifiers without revealing values",
	Long: `List the user-chosen identifiers stored in AgentJail's encrypted broker.

Credential values and metadata are never printed. Use an exact returned ID with
'agentjail run --credential ID -- <command>'.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := callSecretsCommand("credential-list"); err != nil {
			return reportCredentialError(cmd, err)
		}
		return nil
	},
}

var credentialRemoveCmd = &cobra.Command{
	Use: "remove <name>", Short: "Remove a credential from the encrypted broker",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := callSecretsDelete(args[0]); err != nil {
			return reportCredentialError(cmd, err)
		}
		fmt.Fprintf(os.Stdout, "credential removed: %s\n", args[0])
		return nil
	},
}

func reportCredentialError(cmd *cobra.Command, err error) error {
	fmt.Fprintln(cmd.ErrOrStderr(), err)
	return err
}

func init() {
	credentialSetCmd.Flags().StringArrayVar(&credentialSetFromEnv, "from-env", nil, "capture environment variable NAME and deliver it under the same name (repeatable)")
	credentialSetCmd.Flags().StringArrayVar(&credentialSetFromFile, "from-file", nil, "copy PATH into a private session file and expose its path through ENV, as ENV=PATH (repeatable)")
	credentialSetCmd.Flags().StringVar(&credentialSetFromStdinEnv, "from-stdin", "", "read one credential value from standard input and deliver it through ENV")
	credentialSetCmd.Flags().StringVar(&credentialSetLabel, "label", "", "optional non-secret description shown during discovery")
	credentialSetCmd.Flags().StringArrayVar(&credentialSetTags, "tag", nil, "optional non-secret discovery tag (repeatable)")
	credentialCmd.AddCommand(credentialSetCmd, credentialListCmd, credentialRemoveCmd)
	rootCmd.AddCommand(credentialCmd)
}
