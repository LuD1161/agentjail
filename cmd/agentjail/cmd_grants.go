// cmd_grants.go -- cobra command tree for `agentjail grants` / `agentjail grant`.
//
// Subcommands:
//
//	agentjail grants                              list pending grant requests
//	agentjail grant approve <grant_id> [--persist] [--dir <path>]
//	agentjail grant deny <grant_id>
//
// These commands are the HUMAN (approve) side of Phase 3 runtime host
// grants: they talk to netproxy's control socket (netproxy-ctl.sock), which
// is agent-unreachable by construction (see internal/proxyctl). A sandboxed
// agent cannot run these -- it can only file a request via `agentjail allow
// host` (cmd_allow.go). See docs/adr/0044 (Phase 3 runtime host grants).
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/projectpolicy"
	"github.com/LuD1161/agentjail/internal/proxyctl"
	"github.com/spf13/cobra"
)

// grantControlTimeout bounds how long the human-facing grant commands wait
// on netproxy's control socket before giving up.
const grantControlTimeout = 3 * time.Second

var grantsCmd = &cobra.Command{
	Use:   "grants",
	Short: "List pending runtime host grant requests",
	Long: `Lists the grant requests currently pending on the running netproxy, across
all shielded sessions it is serving. Requests are filed by a sandboxed agent
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

var (
	grantApprovePersist bool
	grantApproveDir     string
)

var grantApproveCmd = &cobra.Command{
	Use:   "approve <grant_id>",
	Short: "Approve a pending grant request, widening the live session's allowlist",
	Long: `Approves the pending grant request identified by <grant_id> (see 'agentjail
grants'). netproxy applies the host to the OWNING session's live allowlist
for the request's TTL immediately.

--persist ADDITIONALLY writes the host into that repo's ./.agentjail/policy.yaml
overlay and re-trusts it, so future sessions inherit the grant. The overlay
is resolved relative to --dir, which defaults to the current working
directory -- run 'agentjail grant approve --persist' from the SAME repo the
grant's cwd (shown by 'agentjail grants') points at, or pass --dir explicitly.
If --persist fails, the live grant still stands; the command reports the
persist failure and exits non-zero rather than silently succeeding.`,
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

func runGrantsList() int {
	sock := proxyctl.ControlSocketPath()
	grants, err := proxyctl.GrantList(sock, grantControlTimeout)
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
		cwd := g.Cwd
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

func runGrantApprove(grantID string, persist bool, dir string) int {
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

func runGrantDeny(grantID string) int {
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
