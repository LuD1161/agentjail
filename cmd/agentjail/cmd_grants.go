// cmd_grants.go -- cobra command tree for `agentjail grants` / `agentjail grant`.
//
// Subcommands:
//
//	agentjail grants                              list pending grant requests
//	agentjail grant approve <grant_id>
//	agentjail grant deny <grant_id>
//
// These commands are the HUMAN (approve) side of runtime host grants
// (see ADR 0047). The daemon hosts the grant control plane on
// daemon-ctl.sock (internal/grantctl). A sandboxed agent cannot run these:
// they authenticate with the ctlauth token, which it cannot read (ADR 0069).
// It can only file a request via `agentjail allow host` (cmd_allow.go).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/LuD1161/agentjail/internal/ctlauth"
	"github.com/LuD1161/agentjail/internal/grantctl"
	"github.com/LuD1161/agentjail/internal/store"
	"github.com/spf13/cobra"
)

// grantControlTimeout bounds how long the human-facing grant commands wait
// on the daemon's control socket before giving up.
const grantControlTimeout = 3 * time.Second

// grantsLogLimit is the number of most-recent grant audit_log entries shown
// by `agentjail grants --log`. A diagnostic/history view, not a
// primary workflow -- kept small and non-configurable to keep it simple.
const grantsLogLimit = 50

var grantsLog bool

var grantsCmd = &cobra.Command{
	Use:   "grants",
	Short: "List pending runtime host grant requests",
	Long: `Lists the grant requests currently pending on the running daemon, across
all shielded sessions being served. Requests are filed by a sandboxed agent
via 'agentjail allow host <h>' and expire on their own if never approved.
Approve or deny one with 'agentjail grant approve|deny <grant_id>'.

--log shows the history of approved/denied grants from the local SQLite
audit log instead of the currently pending requests.`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if grantsLog {
			os.Exit(runGrantsLog())
		}
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
	grantsCmd.Flags().BoolVar(&grantsLog, "log", false, "show history of approved/denied grants from the SQLite audit log")
	grantCmd.AddCommand(grantApproveCmd, grantDenyCmd)
	rootCmd.AddCommand(grantsCmd)
	rootCmd.AddCommand(grantCmd)
}

// ctlToken reads the control token for daemon-ctl.sock. A read failure inside a
// shielded session is the boundary doing its job (ADR 0069), not a
// misconfiguration -- approving a grant is a human's decision, made from outside.
func ctlToken(cmdName string) (string, bool) {
	tok, err := ctlauth.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail %s: %v\n", cmdName, err)
		fmt.Fprintln(os.Stderr, "  This command must run outside a shielded agent session.")
		return "", false
	}
	return tok, true
}

func runGrantsList() int {
	sock := grantctl.ControlSocketPath()
	tok, ok := ctlToken("grants")
	if !ok {
		return 1
	}
	grants, err := grantctl.GrantList(sock, tok, grantControlTimeout)
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
	tok, ok := ctlToken("grant approve")
	if !ok {
		return 1
	}
	if err := grantctl.GrantApprove(sock, tok, grantID, grantControlTimeout); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail grant approve: %v\n", err)
		return 1
	}
	fmt.Println("approved and persisted for future sessions")
	return 0
}

func runGrantDeny(grantID string) int {
	sock := grantctl.ControlSocketPath()
	tok, ok := ctlToken("grant deny")
	if !ok {
		return 1
	}
	if err := grantctl.GrantDeny(sock, tok, grantID, grantControlTimeout); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail grant deny: %v\n", err)
		return 1
	}
	fmt.Println("denied")
	return 0
}

// grantLogStatus maps a grant audit_log event_type to the human-readable
// STATUS shown in `agentjail grants --log`.
var grantLogStatus = map[string]string{
	"daemon.grant_requested":  "requested",
	"daemon.grant_denied":     "denied",
	"policy.change_requested": "approving",
	"policy.changed":          "approved",
}

// grantLogDetail is the subset of the JSON audit_log.detail column that
// `agentjail grants --log` cares about (see grantserver.go's Emit calls,
// which set "host" and sometimes "cwd"/"overlay").
type grantLogDetail struct {
	Host string `json:"host"`
}

// runGrantsLog opens the SQLite event store read-only and prints the most
// recent grant-related audit_log entries (requested/denied/approved),
// newest first. This is a diagnostic/history view -- it does not talk to
// the daemon's control socket at all, so it works even when no daemon is
// running, as long as ~/.agentjail/agentjail.db exists.
func runGrantsLog() int {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail grants --log: resolve home directory: %v\n", err)
		return 1
	}
	dbPath := filepath.Join(home, ".agentjail", "agentjail.db")

	st, err := store.OpenReadOnly(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail grants --log: open %s: %v\n", dbPath, err)
		return 1
	}
	defer st.Close()

	entries, err := st.ListGrantAuditLog(context.Background(), grantsLogLimit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail grants --log: %v\n", err)
		return 1
	}
	if len(entries) == 0 {
		fmt.Println("no grant history found")
		return 0
	}

	tw := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "TIMESTAMP\tEVENT\tHOST\tGRANT_ID\tSTATUS")
	for _, e := range entries {
		host := "-"
		var d grantLogDetail
		if e.Detail != "" && json.Unmarshal([]byte(e.Detail), &d) == nil && d.Host != "" {
			host = d.Host
		}
		grantID := e.RefID
		if grantID == "" {
			grantID = "-"
		}
		status, ok := grantLogStatus[e.EventType]
		if !ok {
			status = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			e.Ts.Local().Format(time.RFC3339), e.EventType, host, grantID, status)
	}
	if err := tw.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail grants --log: %v\n", err)
		return 1
	}
	return 0
}
