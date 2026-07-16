package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"time"

	"github.com/LuD1161/agentjail/internal/buildinfo"
	"github.com/LuD1161/agentjail/internal/wire"
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

// protection is the session's enforcement state. The three constants are the
// whole domain: every session is exactly one of them, so the badge can never
// have nothing to render. See ADR 0085-statusline-attests-daemon.
type protection int

const (
	// unshielded: no kernel-level enforcement. Zero value, so a protection that
	// was never computed reads as unprotected rather than as secured.
	unshielded protection = iota
	// shieldedPolicyDown: Landlock/sbpl is on, but the daemon is unreachable and
	// the hook is failing open — the AGE-212 state.
	shieldedPolicyDown
	// fullySecured: shield active and daemon answering.
	fullySecured
)

// statuslineProbeTimeout bounds the liveness dial. Deliberately tighter than
// install.go's one-shot 200ms and doctor's 500ms: this runs on every prompt
// render. AF_UNIX connect is kernel-local (~1ms of plumbing, ADR 0002) and a
// stale socket fails instantly. See ADR 0085-statusline-attests-daemon.
const statuslineProbeTimeout = 50 * time.Millisecond

// daemonAlive reports whether a listener accepts on sockPath. A missing file
// (ENOENT) and a stale file with no listener (ECONNREFUSED) both fail fast and
// both mean the same thing here: policy is not being enforced.
func daemonAlive(sockPath string) bool {
	conn, err := net.DialTimeout("unix", sockPath, statuslineProbeTimeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// detectProtection resolves the session's state. The probe is skipped when the
// shield is off — the badge is UNSECURED either way, so the dial would buy
// nothing but latency. See ADR 0085-statusline-attests-daemon.
func detectProtection(shielded bool, probe func() bool) protection {
	if !shielded {
		return unshielded
	}
	if !probe() {
		return shieldedPolicyDown
	}
	return fullySecured
}

// badge renders the state. It always returns a non-empty string: silence is not
// an option here, because this status line is the only channel that survives.
// agentjail-shield and the PATH shim warn on stderr when a session is
// unprotected, but Claude Code takes over the terminal on startup and those
// warnings scroll away unread. See ADR 0064-statusline-always-attests.
//
// Rendering nothing is reserved for agentjail not being installed at all, which
// happens by construction — uninstall removes the statusLine entry (ADR
// 0063-uninstall-restores-statusline), so this code is not running.
func (p protection) badge() string {
	switch p {
	case fullySecured:
		b := "🔒 [secured by \033[38;5;208magentjail\033[0m"
		if v := displayVersion(); v != "" {
			b += " (" + v + ")"
		}
		return b + "]"
	case shieldedPolicyDown:
		return "⚠ [\033[1;33mPOLICY OFF\033[0m · shield only · \033[38;5;208magentjail\033[0m]"
	default:
		// unshielded, and any state this switch does not know: an unrecognised
		// protection must never claim to be secured.
		return "⚠ [\033[1;31mUNSECURED\033[0m · \033[38;5;208magentjail\033[0m]"
	}
}

// shieldBadge renders the badge for the current session.
func shieldBadge() string {
	shielded := os.Getenv("AGENTJAIL_SHIELDED") == "1"
	return detectProtection(shielded, func() bool {
		return daemonAlive(wire.DefaultSocketPath())
	}).badge()
}

func runStatusline(cmd *cobra.Command, args []string) {
	parts := []string{shieldBadge()}

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

	fmt.Print(strings.Join(parts, " · "))
}
