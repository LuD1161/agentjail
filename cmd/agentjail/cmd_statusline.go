package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"

	"github.com/LuD1161/agentjail/internal/buildinfo"
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

// displayVersion returns the compact version shown in the status line. A binary
// built exactly on a release tag renders as that tag (e.g. "v0.6.0"); a binary
// built N commits past the last tag renders as "<tag>+N" (e.g. "v0.6.0+5"); a
// dirty tree appends "*". It parses the `git describe --tags --dirty` shape
// "v0.6.0-5-g1a2b3c4[-dirty]" embedded via -ldflags into `version`. When no
// usable version was embedded (plain `go build`, or the legacy "dev-<hash>"
// default), it falls back to the short commit hash from build info, or "" when
// that too is absent.
func displayVersion() string {
	v := strings.TrimSpace(buildinfo.Version)
	if v == "" || v == "dev" || strings.HasPrefix(v, "dev-") {
		return buildCommit()
	}

	dirty := false
	if s := strings.TrimSuffix(v, "-dirty"); s != v {
		v, dirty = s, true
	}

	out := v
	// git describe emits "<tag>-<N>-g<hash>" when the build is N commits past
	// <tag>. Collapse that to "<tag>+<N>". An exact tag has no "-g" segment.
	if i := strings.LastIndex(v, "-g"); i >= 0 {
		rest := v[:i] // "<tag>-<N>"
		if j := strings.LastIndex(rest, "-"); j >= 0 {
			if n := rest[j+1:]; isAllDigits(n) {
				out = rest[:j] + "+" + n
			}
		}
	}
	if dirty {
		out += "*"
	}
	return out
}

// isAllDigits reports whether s is non-empty and every rune is an ASCII digit.
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func runStatusline(cmd *cobra.Command, args []string) {
	var parts []string

	if os.Getenv("AGENTJAIL_SHIELDED") == "1" {
		byline := "🔒 [secured by \033[38;5;208magentjail\033[0m"
		if v := displayVersion(); v != "" {
			byline += " (" + v + ")"
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
