package main

import "github.com/spf13/cobra"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		runVersionCmd()
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
