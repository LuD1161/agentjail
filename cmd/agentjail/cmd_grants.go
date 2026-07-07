// cmd_grants.go -- cobra command tree for `agentjail grants` / `agentjail grant`.
//
// Subcommands:
//
//	agentjail grants                              list pending grant requests
//	agentjail grant approve <grant_id>
//	agentjail grant deny <grant_id>
//
// These commands are the HUMAN (approve) side of runtime host grants
// (AGE-116, ADR 0047). The daemon hosts the grant control plane on
// daemon-ctl.sock (internal/grantctl); this socket is agent-unreachable
// by construction. A sandboxed agent cannot run these -- it can only file
// a request via `agentjail allow host` (cmd_allow.go).
package main

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/LuD1161/agentjail/internal/grantctl"
	"github.com/spf13/cobra"
)

// grantControlTimeout bounds how long the human-facing grant commands wait
// on the daemon's control socket before giving up.
const grantControlTimeout = 3 * time.Second

var grantsCmd = &cobra.Command{
	Use:   "grants",
	Short: "List pending runtime host grant requests",
	Long: `Lists the grant requests currently pending on the running daemon, across
all shielded sessions being served. Requests are filed by a sandboxed agent
via 'agentjail allow host <h>' and expire on their own if never approved.
Approve or deny one with 'agentjail grant approve|deny <grant_id>'.`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runGrantsList())
	},
}

var grantCmd = &cobra.Command{
	Use:   "grant",
	Short: "Approve or deny a pending runtime host grant request",
}

var grantApproveCmd = &cobra.Command{
	Use:   "approve <grant_id>",
	Short: "Approve a pending grant request",
	Long: `Approves the pending grant request identified by <grant_id> (see 'agentjail
grants'). The daemon persists the host into the owning session's
.agentjail/policy.yaml overlay and re-trusts it so future sessions inherit
the grant. The current sandboxed session picks up the change on next launch.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runGrantApprove(args[0]))
	},
}

var grantDenyCmd = &cobra.Command{
	Use:   "deny <grant_id>",
	Short: "Deny a pending grant request",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runGrantDeny(args[0]))
	},
}

func init() {
	grantCmd.AddCommand(grantApproveCmd, grantDenyCmd)
	rootCmd.AddCommand(grantsCmd)
	rootCmd.AddCommand(grantCmd)
}

func runGrantsList() int {
	sock := grantctl.ControlSocketPath()
	grants, err := grantctl.GrantList(sock, grantControlTimeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail grants: %v\n", err)
		return 1
	}
	if len(grants) == 0 {
		fmt.Println("no pending grant requests")
		return 0
	}

	tw := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "GRANT_ID\tHOST\tTTL\tCWD\tREASON")
	for _, g := range grants {
		reason := g.Reason
		if reason == "" {
			reason = "-"
		}
		cwd := g.CWD
		if cwd == "" {
			cwd = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", g.GrantID, g.Host, time.Duration(g.TTLMs)*time.Millisecond, cwd, reason)
	}
	if err := tw.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail grants: %v\n", err)
		return 1
	}
	return 0
}

func runGrantApprove(grantID string) int {
	sock := grantctl.ControlSocketPath()
	if err := grantctl.GrantApprove(sock, grantID, grantControlTimeout); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail grant approve: %v\n", err)
		return 1
	}
	fmt.Println("approved and persisted for future sessions")
	return 0
}

func runGrantDeny(grantID string) int {
	sock := grantctl.ControlSocketPath()
	if err := grantctl.GrantDeny(sock, grantID, grantControlTimeout); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail grant deny: %v\n", err)
		return 1
	}
	fmt.Println("denied")
	return 0
}
