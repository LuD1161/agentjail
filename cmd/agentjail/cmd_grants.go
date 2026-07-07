// cmd_grants.go -- cobra command tree for `agentjail grants` / `agentjail grant`.
//
// Subcommands:
//
//	agentjail grants                              list pending grant requests
//	agentjail grant approve <grant_id> [--persist] [--dir <path>]
//	agentjail grant deny <grant_id>
//
// These commands are the HUMAN (approve) side of Phase 3 runtime host
// grants. As of AGE-116, the daemon hosts the primary grant control plane
// on daemon-ctl.sock (internal/grantctl); the legacy netproxy control socket
// (netproxy-ctl.sock, internal/proxyctl) is still queried when present so
// grants filed through an older netproxy are not orphaned during rollout.
// Both are agent-unreachable by construction. A sandboxed agent cannot run
// these -- it can only file a request via `agentjail allow host`
// (cmd_allow.go). See docs/adr/0044 (Phase 3 runtime host grants).
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/grantctl"
	"github.com/LuD1161/agentjail/internal/projectpolicy"
	"github.com/LuD1161/agentjail/internal/proxyctl"
	"github.com/spf13/cobra"
)

// grantControlTimeout bounds how long the human-facing grant commands wait
// on the daemon's or netproxy's control socket before giving up.
const grantControlTimeout = 3 * time.Second

var grantsCmd = &cobra.Command{
	Use:   "grants",
	Short: "List pending runtime host grant requests",
	Long: `Lists the grant requests currently pending on the running daemon (and, if
present, a legacy netproxy), across all shielded sessions being served.
Requests are filed by a sandboxed agent via 'agentjail allow host <h>' and
expire on their own if never approved. Approve or deny one with 'agentjail
grant approve|deny <grant_id>'.`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runGrantsList())
	},
}

var grantCmd = &cobra.Command{
	Use:   "grant",
	Short: "Approve or deny a pending runtime host grant request",
}

var (
	grantApprovePersist bool
	grantApproveDir     string
)

var grantApproveCmd = &cobra.Command{
	Use:   "approve <grant_id>",
	Short: "Approve a pending grant request, widening the live session's allowlist",
	Long: `Approves the pending grant request identified by <grant_id> (see 'agentjail
grants'). The daemon (or, for a legacy grant, netproxy) applies the host to
the OWNING session's live allowlist for the request's TTL immediately.
Daemon-side approvals persist the host into the owning session's
./.agentjail/policy.yaml overlay automatically as part of approval.

--persist ADDITIONALLY writes the host into that repo's ./.agentjail/policy.yaml
overlay and re-trusts it, so future sessions inherit the grant. It only
applies to legacy netproxy grants (a no-op for daemon grants, which always
persist). The overlay is resolved relative to --dir, which defaults to the
current working directory -- run 'agentjail grant approve --persist' from the
SAME repo the grant's cwd (shown by 'agentjail grants') points at, or pass
--dir explicitly. If --persist fails, the live grant still stands; the
command reports the persist failure and exits non-zero rather than silently
succeeding.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runGrantApprove(args[0], grantApprovePersist, grantApproveDir))
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
	grantApproveCmd.Flags().BoolVar(&grantApprovePersist, "persist", false, "Also persist the host into ./.agentjail/policy.yaml (see --dir) and re-trust it")
	grantApproveCmd.Flags().StringVar(&grantApproveDir, "dir", "", "Repo directory to persist into (default: current working directory); only used with --persist")

	grantCmd.AddCommand(grantApproveCmd, grantDenyCmd)
	rootCmd.AddCommand(grantsCmd)
	rootCmd.AddCommand(grantCmd)
}

// grantRow is the display-normalized shape both backends' GrantInfo types
// are flattened into before printing, plus SOURCE so a human can tell which
// control plane (daemon or netproxy) is holding the request.
type grantRow struct {
	GrantID string
	Host    string
	TTLMs   int64
	CWD     string
	Reason  string
	Source  string
}

// resolveGrantSocket returns the control socket path for grant operations
// that only talk to one backend (approve/deny fallback). It prefers
// netproxy-ctl.sock (live grants) when reachable; otherwise it falls back to
// daemon-ctl.sock.
func resolveGrantSocket() (sock string, isNetproxy bool) {
	np := proxyctl.ControlSocketPath()
	if grantctl.IsAvailable(np) {
		return np, true
	}
	return grantctl.ControlSocketPath(), false
}

// runGrantsList queries BOTH the daemon's grant control socket
// (daemon-ctl.sock, the primary backend as of AGE-116) and, if reachable,
// the legacy netproxy control socket (netproxy-ctl.sock), merging the
// results into one table with a SOURCE column. Either backend being
// unreachable is not itself an error -- only both failing is.
func runGrantsList() int {
	var rows []grantRow
	var daemonErr, netproxyErr error

	daemonGrants, dErr := grantctl.GrantList(grantctl.ControlSocketPath(), grantControlTimeout)
	if dErr != nil {
		daemonErr = dErr
	} else {
		for _, g := range daemonGrants {
			rows = append(rows, grantRow{GrantID: g.GrantID, Host: g.Host, TTLMs: g.TTLMs, CWD: g.CWD, Reason: g.Reason, Source: "daemon"})
		}
	}

	npSock := proxyctl.ControlSocketPath()
	npAvailable := grantctl.IsAvailable(npSock)
	if npAvailable {
		npGrants, nErr := proxyctl.GrantList(npSock, grantControlTimeout)
		if nErr != nil {
			netproxyErr = nErr
		} else {
			for _, g := range npGrants {
				rows = append(rows, grantRow{GrantID: g.GrantID, Host: g.Host, TTLMs: g.TTLMs, CWD: g.Cwd, Reason: g.Reason, Source: "netproxy"})
			}
		}
	}

	if daemonErr != nil && (!npAvailable || netproxyErr != nil) {
		if netproxyErr != nil {
			fmt.Fprintf(os.Stderr, "agentjail grants: daemon: %v; netproxy: %v\n", daemonErr, netproxyErr)
		} else {
			fmt.Fprintf(os.Stderr, "agentjail grants: %v\n", daemonErr)
		}
		return 1
	}

	if len(rows) == 0 {
		fmt.Println("no pending grant requests")
		return 0
	}

	tw := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "GRANT_ID\tHOST\tTTL\tCWD\tREASON\tSOURCE")
	for _, g := range rows {
		reason := g.Reason
		if reason == "" {
			reason = "-"
		}
		cwd := g.CWD
		if cwd == "" {
			cwd = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", g.GrantID, g.Host, time.Duration(g.TTLMs)*time.Millisecond, cwd, reason, g.Source)
	}
	if err := tw.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail grants: %v\n", err)
		return 1
	}
	return 0
}

// runGrantApprove tries the daemon's grant control socket first. A daemon
// error containing "unbound" (grantctl/daemon's errGrantUnbound sentinel --
// the grant was never bound to a session CWD, so there is nowhere to persist
// the host) is terminal: it is NOT a "try the other backend" situation, it
// means the grant cannot be approved anywhere. Any other daemon error (not
// reachable, or "grant not found" because the request was filed against
// netproxy instead) falls through to the legacy netproxy backend, preserving
// the pre-AGE-116 --persist flow for netproxy-owned grants.
func runGrantApprove(grantID string, persist bool, dir string) int {
	daemonErr := grantctl.GrantApprove(grantctl.ControlSocketPath(), grantID, grantControlTimeout)
	if daemonErr == nil {
		fmt.Println("granted host to the live session")
		if persist {
			fmt.Println("note: --persist is a no-op for daemon grants; the daemon persists the host automatically on approval")
		}
		return 0
	}
	if strings.Contains(daemonErr.Error(), "unbound") {
		fmt.Fprintf(os.Stderr, "agentjail grant approve: %v\n", daemonErr)
		return 1
	}

	return runGrantApproveNetproxy(grantID, persist, dir)
}

// runGrantApproveNetproxy is the legacy netproxy approve path (pre-AGE-116
// behavior): find the host via grant_list before claiming, approve, then
// optionally persist into ./.agentjail/policy.yaml and re-trust it.
func runGrantApproveNetproxy(grantID string, persist bool, dir string) int {
	sock := proxyctl.ControlSocketPath()

	// GrantApprove atomically claims the pending entry, so the host must be
	// captured from grant_list BEFORE approving -- once claimed, the entry
	// no longer appears in grant_list and its host is unrecoverable from the
	// control plane (approve's response carries no host, by design: the
	// approve verb identifies its target solely by grant_id).
	var host string
	if persist {
		h, err := findGrantHost(sock, grantID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentjail grant approve: %v\n", err)
			return 1
		}
		host = h
	}

	if err := proxyctl.GrantApprove(sock, grantID, grantControlTimeout); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail grant approve: %v\n", err)
		return 1
	}
	fmt.Println("granted host to the live session")

	if !persist {
		return 0
	}

	if dir == "" {
		wd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "granted live, but persist failed: resolve current directory: %v\n", err)
			return 1
		}
		dir = wd
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "granted live, but persist failed: resolve %q: %v\n", dir, err)
		return 1
	}

	overlayPath, err := persistGrantHost(absDir, host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "granted live, but persist failed: %v\n", err)
		return 1
	}
	fmt.Printf("persisted %s into %s and re-trusted the overlay\n", host, overlayPath)
	return 0
}

// runGrantDeny tries the daemon's grant control socket first; if it reports
// the grant is not found there (or the daemon is unreachable), falls
// through to the legacy netproxy control socket. Deny never needs a bound
// CWD, so there is no "unbound" terminal case here (unlike approve).
func runGrantDeny(grantID string) int {
	if err := grantctl.GrantDeny(grantctl.ControlSocketPath(), grantID, grantControlTimeout); err == nil {
		fmt.Println("denied")
		return 0
	}

	sock := proxyctl.ControlSocketPath()
	if err := proxyctl.GrantDeny(sock, grantID, grantControlTimeout); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail grant deny: %v\n", err)
		return 1
	}
	fmt.Println("denied")
	return 0
}

// findGrantHost looks up the host for a still-pending grant_id via
// grant_list. It exists because grant_approve's protocol response carries no
// host (see proxyctl.GrantApprove) -- --persist needs the host, so
// runGrantApprove calls this BEFORE GrantApprove, while the entry is still
// listed (approve atomically claims/removes it).
func findGrantHost(sock, grantID string) (string, error) {
	grants, err := proxyctl.GrantList(sock, grantControlTimeout)
	if err != nil {
		return "", fmt.Errorf("look up host for grant_id %s: %w", grantID, err)
	}
	for _, g := range grants {
		if g.GrantID == grantID {
			return g.Host, nil
		}
	}
	return "", fmt.Errorf("grant_id %s not found among pending requests (already approved/denied/expired?); run 'agentjail grants' to see current pending requests", grantID)
}

// persistGrantHost merges host into <dir>/.agentjail/policy.yaml's
// network.allowed_hosts (creating the overlay if it does not exist yet),
// writes it atomically (config.Save: temp file + rename, same as the rest of
// the codebase's policy writers), then re-trusts the overlay by its new
// content hash so future sessions inherit the grant without a manual
// 'agentjail trust'. It returns the overlay path on success.
//
// This is only reachable from the human/trusted side (agentjail grant
// approve --persist), never from inside the sandbox: the sandboxed agent can
// only reach 'agentjail allow host', which never accepts --persist.
func persistGrantHost(dir, host string) (string, error) {
	overlayDir := filepath.Join(dir, projectpolicy.ProjectDirName)
	overlayPath := filepath.Join(overlayDir, projectpolicy.ProjectPolicyFile)

	var cfg *config.PolicyConfig
	if _, err := os.Stat(overlayPath); err == nil {
		loaded, err := config.Load(overlayPath)
		if err != nil {
			return "", fmt.Errorf("load %s: %w", overlayPath, err)
		}
		cfg = loaded
	} else if os.IsNotExist(err) {
		if err := os.MkdirAll(overlayDir, 0o755); err != nil {
			return "", fmt.Errorf("create %s: %w", overlayDir, err)
		}
		cfg = &config.PolicyConfig{}
	} else {
		return "", fmt.Errorf("stat %s: %w", overlayPath, err)
	}

	already := false
	for _, h := range cfg.Network.AllowedHosts {
		if strings.EqualFold(h, host) {
			already = true
			break
		}
	}
	if !already {
		cfg.Network.AllowedHosts = append(cfg.Network.AllowedHosts, host)
	}

	if err := config.Save(cfg, overlayPath); err != nil {
		return "", fmt.Errorf("write %s: %w", overlayPath, err)
	}

	// Recompute the hash from what actually landed on disk (not the
	// in-memory struct) so the trust entry matches byte-for-byte, mirroring
	// how 'agentjail trust' hashes the file it read.
	written, err := os.ReadFile(overlayPath)
	if err != nil {
		return "", fmt.Errorf("re-read %s after save: %w", overlayPath, err)
	}
	newHash := projectpolicy.HashContent(written)

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	trustPath := projectpolicy.TrustStorePath(filepath.Join(homeDir, projectpolicy.ProjectDirName))
	ts, err := projectpolicy.LoadTrustStore(trustPath)
	if err != nil {
		return "", fmt.Errorf("load trust store: %w", err)
	}
	ts.Trust(&projectpolicy.Overlay{Path: overlayPath, ContentHash: newHash})
	if err := ts.Save(); err != nil {
		return "", fmt.Errorf("save trust store (overlay was written but is now UNTRUSTED until you run 'agentjail trust %s'): %w", dir, err)
	}

	return overlayPath, nil
}
