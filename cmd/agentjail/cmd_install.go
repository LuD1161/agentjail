package main

import "github.com/spf13/cobra"

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install hooks or IDE wrappers for supported coding agents",
	Long: `Install AgentJail for one target, every detected agent, or an optional
standalone component. --chain and --replace apply only to VS Code/Cursor IDE
wrappers. --with-path-shim and --with-apparmor are standalone setup modes when
used without --for or --all.`,
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		if helpRequested(cmd, args) {
			return
		}
		runInstallCmd(args)
	},
}

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove AgentJail components or all local AgentJail data",
	Long: `With --for, remove only one agent hook or IDE wrapper. With
--path-shim-only, remove only launch shims. With neither option, stop services,
remove every owned hook and wrapper, and delete operational state, including policy,
recorded sessions, statistics, logs, trust state, and credentials.

Small inert hook/status-line compatibility scripts and an uninstall receipt remain
for commands held by open agent sessions. The app respects explicit removal.

Use --keep-credentials during a full uninstall to preserve the encrypted
credential vault and its key.`,
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		if helpRequested(cmd, args) {
			return
		}
		runUninstallCmd(args)
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show a quick installed-component snapshot",
	Long:  "Show a fast read-only summary of detected agents, installed hooks, daemon state, and policy location. Use 'agentjail doctor' for comprehensive enforcement diagnostics or repair.",
	Run: func(cmd *cobra.Command, args []string) {
		jsonOutput, _ := cmd.Flags().GetBool("json")
		runStatusCmd(jsonOutput)
	},
}

func init() {
	rootCmd.AddCommand(installCmd)
	rootCmd.AddCommand(uninstallCmd)
	rootCmd.AddCommand(statusCmd)
}
