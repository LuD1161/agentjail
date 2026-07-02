package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime/debug"
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

// buildCommit returns the short git revision the running binary was built from,
// read from the Go build info embedded automatically on `go build` from the repo
// (no ldflags needed). A trailing "*" marks a dirty (uncommitted) build tree, so
// the operator can tell whether the deployed binary matches a clean commit.
// Returns "" when no VCS info is embedded (e.g. built outside the repo).
func buildCommit() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	var rev string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return ""
	}
	if len(rev) > 6 {
		rev = rev[:6]
	}
	if dirty {
		rev += "*"
	}
	return rev
}

func runStatusline(cmd *cobra.Command, args []string) {
	var parts []string

	if os.Getenv("AGENTJAIL_SHIELDED") == "1" {
		byline := "🔒 [secured by \033[38;5;208magentjail\033[0m"
		if c := buildCommit(); c != "" {
			byline += " (" + c + ")"
		}
		byline += "]"
		parts = append(parts, byline)
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
