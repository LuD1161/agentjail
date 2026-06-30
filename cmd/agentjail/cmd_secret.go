// cmd_secret.go -- cobra command tree for `agentjail secret`.
//
// Subcommands:
//
//	agentjail secret set <name> --value <val> --hosts <hosts> [--methods GET,POST] [--header Authorization --scheme Bearer]
//	agentjail secret set <name> --from-env <VAR> --hosts <hosts>
//	agentjail secret list
//	agentjail secret remove <name>
//
// The set command stores the credential in the encrypted vault (via
// agentjail-secrets) and writes a CredentialConfig entry to policy.yaml.
// The list command shows configured credentials from policy.yaml (no values).
// The remove command removes from both.
package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// --- secret (parent) -------------------------------------------------------

var secretCmd = &cobra.Command{
	Use:   "secret",
	Short: "Manage scoped credential grants",
	Long: `Manage credentials for the phantom token registry.

The 'set' command stores a credential in the encrypted vault and writes its
access policy to policy.yaml.  The agent never sees the real credential;
instead it receives a phantom token that the proxy swaps for the real value
on outbound requests that match the access policy.`,
}

// --- secret set -------------------------------------------------------------

var (
	secretSetValue   string
	secretSetFromEnv string
	secretSetHosts   string
	secretSetMethods string
	secretSetPaths   string
	secretSetHeader  string
	secretSetScheme  string
	secretSetType    string
	secretSetViola   string
	secretSetTTL     string
)

var secretSetCmd = &cobra.Command{
	Use:   "set <name>",
	Short: "Store a credential and configure its access policy",
	Long: `Store a credential in the encrypted vault and write a CredentialConfig entry
to policy.yaml.  The credential is identified by <name> (e.g. "github").

Either --value or --from-env is required.  When --from-env is used, the value
is read from the named environment variable.

--hosts is required: it restricts which destination hosts may receive the
real credential.  Multiple hosts are comma-separated.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSecretSet(args[0])
	},
}

// --- secret list ------------------------------------------------------------

var secretListCmd = &cobra.Command{
	Use:   "list",
	Short: "Show configured credentials (no values)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSecretList()
	},
}

// --- secret remove ----------------------------------------------------------

var secretRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove a credential from the vault and policy",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSecretRemove(args[0])
	},
}

func init() {
	// set flags
	secretSetCmd.Flags().StringVar(&secretSetValue, "value", "", "credential value (mutually exclusive with --from-env)")
	secretSetCmd.Flags().StringVar(&secretSetFromEnv, "from-env", "", "read credential from this environment variable")
	secretSetCmd.Flags().StringVar(&secretSetHosts, "hosts", "", "comma-separated allowed hosts (required)")
	secretSetCmd.Flags().StringVar(&secretSetMethods, "methods", "", "comma-separated allowed HTTP methods (empty = all)")
	secretSetCmd.Flags().StringVar(&secretSetPaths, "paths", "", "comma-separated allowed path globs (empty = all)")
	secretSetCmd.Flags().StringVar(&secretSetHeader, "header", "Authorization", "HTTP header for injection")
	secretSetCmd.Flags().StringVar(&secretSetScheme, "scheme", "Bearer", "auth scheme (Bearer, token, or empty)")
	secretSetCmd.Flags().StringVar(&secretSetType, "type", "bearer_header", "injection type: bearer_header, header, query_parameter")
	secretSetCmd.Flags().StringVar(&secretSetViola, "violation", "block-and-log", "enforcement action: block, block-and-log, terminate")
	secretSetCmd.Flags().StringVar(&secretSetTTL, "ttl", "", "credential lifetime (e.g. 8h, 30m)")

	_ = secretSetCmd.MarkFlagRequired("hosts")

	secretCmd.AddCommand(secretSetCmd)
	secretCmd.AddCommand(secretListCmd)
	secretCmd.AddCommand(secretRemoveCmd)
	rootCmd.AddCommand(secretCmd)
}

// splitCSV splits a comma-separated string into a trimmed slice.
// Returns nil for an empty input.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// inferEnvVar guesses the env var name from a credential ID.
// "github" -> "GITHUB_TOKEN", "anthropic" -> "ANTHROPIC_API_KEY".
func inferEnvVar(name string) string {
	upper := strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
	switch upper {
	case "ANTHROPIC":
		return "ANTHROPIC_API_KEY"
	case "OPENAI":
		return "OPENAI_API_KEY"
	default:
		return upper + "_TOKEN"
	}
}

// formatInjection returns a human-readable injection description.
func formatInjection(header, scheme string) string {
	if scheme != "" {
		return fmt.Sprintf("%s: %s", header, scheme)
	}
	return header
}
