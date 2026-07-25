package main

import (
	"encoding/base64"
	"fmt"
	"io"
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
	Short:  "Output status line indicator for supported coding agents",
	Hidden: true,
	Run:    runStatusline,
}

var statuslineChain string
var statuslineChainBase64 string
var statuslineIntegration string

func init() {
	statuslineCmd.Flags().StringVar(&statuslineChain, "chain", "", "chain with another status line command")
	statuslineCmd.Flags().StringVar(&statuslineChainBase64, "chain-base64", "", "chain with an encoded status line command")
	statuslineCmd.Flags().StringVar(&statuslineIntegration, "integration", "", "status line host integration")
	_ = statuslineCmd.Flags().MarkHidden("integration")
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

// Hang guard, not a budget: only bites on a wedged daemon.
// See ADR 0085-statusline-attests-daemon.
const statuslineProbeTimeout = 50 * time.Millisecond

// Must ping, not dial: connect() succeeds against a wedged daemon, so a dial
// badges one that enforces nothing as secured.
// See ADR 0085-statusline-attests-daemon.
func daemonAlive(sockPath string) bool {
	l, _ := probeDaemon(sockPath, statuslineProbeTimeout)
	return l == daemonHealthy
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

// Never returns empty: silence is indistinguishable from protection, and this
// is the only channel that survives.
// See ADR 0064-statusline-always-attests.
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

	chain := statuslineChain
	if statuslineChainBase64 != "" {
		if decoded, err := base64.RawStdEncoding.DecodeString(statuslineChainBase64); err == nil {
			chain = string(decoded)
		}
	}
	if chain != "" {
		stdin, _ := io.ReadAll(os.Stdin)
		if chained := runChainedStatusline(chain, stdin); chained != "" {
			parts = append(parts, chained)
		}
	}

	fmt.Print(strings.Join(parts, " · "))
}

func runChainedStatusline(command string, stdin []byte) string {
	c := exec.Command("/bin/sh", "-c", command)
	c.Stdin = strings.NewReader(string(stdin))
	out, err := c.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
