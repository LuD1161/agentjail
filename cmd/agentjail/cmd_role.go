package main

import (
	"fmt"
	"os"

	"github.com/LuD1161/agentjail/internal/ctlauth"
	"github.com/LuD1161/agentjail/internal/daemonapp"
	"github.com/LuD1161/agentjail/internal/netproxyapp"
	"github.com/LuD1161/agentjail/internal/secretsapp"
	"github.com/LuD1161/agentjail/internal/shieldapp"
	"github.com/spf13/cobra"
)

var (
	roleUserHomeDir      = os.UserHomeDir
	roleAuthorizeRestart = authorizeDaemonRestart
	roleConfirmRestart   = confirmDaemonRestart
	roleRestartDaemon    = restartDaemonViaSupervisor
)

// Restart is a protected control action, not a daemon process argument.
// See ADR 0067-control-plane-token-auth and GOTCHAS #25.
func runDaemonRole(args []string) int {
	if len(args) == 1 && args[0] == "restart" {
		home, err := roleUserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentjail daemon restart: determine home: %v\n", err)
			return 1
		}
		if err := roleAuthorizeRestart(home); err != nil {
			fmt.Fprintf(os.Stderr, "agentjail daemon restart: REFUSED — %v\n", err)
			fmt.Fprintln(os.Stderr, "  Run this command from a human-controlled host terminal outside the shielded agent session.")
			return 1
		}
		if !roleConfirmRestart() {
			return 1
		}
		if err := roleRestartDaemon(home); err != nil {
			fmt.Fprintf(os.Stderr, "agentjail daemon restart: %v\n", err)
			return 1
		}
		fmt.Fprintln(os.Stdout, "agentjail daemon restarted")
		return 0
	}
	return daemonapp.Run(args)
}

func authorizeDaemonRestart(home string) error {
	if _, err := ctlauth.LoadForHome(home); err != nil {
		return fmt.Errorf("control authorization unavailable: %w", err)
	}
	return nil
}

func confirmDaemonRestart() bool {
	return requireInteractiveConfirm(
		"agentjail daemon restart: REFUSED — no interactive terminal detected.\n"+
			"  Run this command from a human-controlled host terminal.\n",
		"\n  Restart the AgentJail policy daemon? Pending approvals will be cancelled.\n"+
			"  Type 'y' to confirm, anything else to cancel: ",
	)
}

// roleCommands registers hidden `agentjail <role> ...` subcommands that
// forward straight into the corresponding role app's own arg handling.
// DisableFlagParsing is set on each so cobra does not attempt to interpret
// the role's own flags (e.g. `-c`, `--config`) -- args are passed through
// verbatim, exactly as if the role's standalone binary had been invoked.
//
// This is the "subcommand" half of the multicall binary (T3); the other
// half is the argv[0] dispatch in main() for symlinked invocations like
// `agentjail-daemon`.
var daemonCmd = &cobra.Command{
	Use:                "daemon",
	Short:              "Run the agentjail daemon (internal)",
	Hidden:             true,
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		os.Exit(runDaemonRole(args))
		return nil
	},
}

var shieldCmd = &cobra.Command{
	Use:                "shield",
	Short:              "Run the agentjail shield (internal)",
	Hidden:             true,
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		os.Exit(shieldapp.Run(args))
		return nil
	},
}

var netproxyCmd = &cobra.Command{
	Use:                "netproxy",
	Short:              "Run the agentjail netproxy (internal)",
	Hidden:             true,
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		os.Exit(netproxyapp.Run(args))
		return nil
	},
}

var secretsCmd = &cobra.Command{
	Use:                "secrets",
	Short:              "Run the agentjail secrets helper (internal)",
	Hidden:             true,
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		os.Exit(secretsapp.Run(args))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(daemonCmd, shieldCmd, netproxyCmd, secretsCmd)
}
