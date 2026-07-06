// cmd_allow.go -- cobra command tree for `agentjail allow`.
//
// Subcommands:
//
//	agentjail allow host <host> [--ttl 1h] [--reason "..."]
//
// This command is agent-safe: it runs INSIDE the sandbox. It never talks to
// a privileged control socket (daemon-ctl.sock / netproxy-ctl.sock are both
// agent-unreachable by construction); it only files a grant REQUEST over
// the daemon's agent-reachable socket (daemon.sock, see internal/wire).
// Filing a request grants nothing -- a human must approve it out-of-band
// with `agentjail grant approve` from a trusted terminal. See docs/adr/0044
// (Phase 3 runtime host grants) and AGE-116 (daemon-hosted grant control
// plane).
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/LuD1161/agentjail/internal/grantctl"
	"github.com/LuD1161/agentjail/internal/hostgrant"
	"github.com/LuD1161/agentjail/internal/wire"
	"github.com/spf13/cobra"
)

// allowRequestTimeout bounds how long `agentjail allow host` waits for the
// daemon to answer the grant request before giving up.
const allowRequestTimeout = 10 * time.Second

var (
	allowHostTTL    string
	allowHostReason string
)

var allowCmd = &cobra.Command{
	Use:   "allow",
	Short: "Request a runtime widening of this session's network egress",
}

var allowHostCmd = &cobra.Command{
	Use:   "host <host>",
	Short: "Request that a host be added to this session's allowlist",
	Long: `Files a grant REQUEST for host with the running agentjail daemon for the
CURRENT session. This command only files intent -- it grants nothing by
itself. A human must run 'agentjail grants' and 'agentjail grant approve
<grant_id>' from a trusted terminal (outside the sandbox) to actually widen
egress.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runAllowHost(args[0], allowHostTTL, allowHostReason))
	},
}

func init() {
	allowHostCmd.Flags().StringVar(&allowHostTTL, "ttl", "1h", "How long the grant should last once approved (Go duration, e.g. 30m, 2h)")
	allowHostCmd.Flags().StringVar(&allowHostReason, "reason", "", "Optional justification shown to the human approver")

	allowCmd.AddCommand(allowHostCmd)
	rootCmd.AddCommand(allowCmd)
}

// runAllowHost validates host locally, then files a grant request with the
// daemon over daemon.sock. It returns the process exit code.
func runAllowHost(host, ttl, reason string) int {
	validHost, err := hostgrant.Validate(host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail allow host: %v\n", err)
		return 1
	}

	if ttl == "" {
		ttl = "1h"
	}
	dur, err := time.ParseDuration(ttl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail allow host: invalid --ttl %q: %v\n", ttl, err)
		return 1
	}
	ttlMs := dur.Milliseconds()
	if ttlMs > grantctl.MaxGrantTTLMs {
		ttlMs = grantctl.MaxGrantTTLMs
	}

	if len(reason) > grantctl.MaxReasonLen {
		fmt.Fprintf(os.Stderr, "agentjail allow host: --reason too long (%d > %d bytes)\n", len(reason), grantctl.MaxReasonLen)
		return 1
	}

	sessionID := os.Getenv("AGENTJAIL_SESSION_ID")
	if sessionID == "" {
		sessionID = "unknown"
	}
	cwd, _ := os.Getwd()

	sock := wire.DefaultSocketPath()
	grantID, err := grantctl.GrantRequest(sock, sessionID, cwd, validHost, ttlMs, reason, allowRequestTimeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail allow host: request failed: %v\n", err)
		return 1
	}

	grantSuffix := ""
	if grantID != "" {
		grantSuffix = fmt.Sprintf(" (grant_id %s)", grantID)
	}
	fmt.Printf("requested host %s (ttl %s) - pending human approval%s; run 'agentjail grants' in a trusted terminal to approve\n", validHost, ttl, grantSuffix)
	return 0
}
