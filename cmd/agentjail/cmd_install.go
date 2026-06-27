package main

import "github.com/spf13/cobra"

var installCmd = &cobra.Command{
	Use:                "install",
	Short:              "Install hooks for supported coding agents",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		runInstallCmd(args)
	},
}

var uninstallCmd = &cobra.Command{
	Use:                "uninstall",
	Short:              "Remove hooks, daemon service, and local policy state",
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		runUninstallCmd(args)
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show hook, daemon, and policy health",
	Run: func(cmd *cobra.Command, args []string) {
		runStatusCmd()
	},
}

func init() {
	rootCmd.AddCommand(installCmd)
	rootCmd.AddCommand(uninstallCmd)
	rootCmd.AddCommand(statusCmd)
}
