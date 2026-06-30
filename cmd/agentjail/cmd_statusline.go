package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

var statuslineCmd = &cobra.Command{
	Use:    "statusline",
	Short:  "Output status line indicator for Claude Code",
	Hidden: true,
	Run:    runStatusline,
}

var statuslineChain string

func init() {
	statuslineCmd.Flags().StringVar(&statuslineChain, "chain", "", "chain with another status line command")
	rootCmd.AddCommand(statuslineCmd)
}

func runStatusline(cmd *cobra.Command, args []string) {
	var parts []string

	if os.Getenv("AGENTJAIL_SHIELDED") == "1" {
		parts = append(parts, "🔒 [secured by \033[38;5;208magentjail\033[0m]")
	}

	if statuslineChain != "" {
		stdin, _ := io.ReadAll(os.Stdin)
		chainParts := strings.Fields(statuslineChain)
		if len(chainParts) > 0 {
			c := exec.Command(chainParts[0], chainParts[1:]...)
			c.Stdin = strings.NewReader(string(stdin))
			out, err := c.CombinedOutput()
			if err == nil {
				s := strings.TrimSpace(string(out))
				if s != "" {
					parts = append(parts, s)
				}
			}
		}
	}

	if len(parts) > 0 {
		fmt.Print(strings.Join(parts, " · "))
	}
}
