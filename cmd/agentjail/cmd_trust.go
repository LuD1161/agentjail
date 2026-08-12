package main

import (
	"fmt"
	"os"
	"path/filepath"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/projectpolicy"
	"github.com/spf13/cobra"
)

// trustCmd manages the direnv-style trust list for per-folder
// ./.agentjail/policy.yaml overlays. A project overlay may WIDEN a session's
// allowlist (add hosts / MCPs), but only after the user explicitly trusts the
// directory here -- otherwise a cloned repo could silently widen the agent's
// egress. Trust is keyed on the file's content hash, so editing it revokes
// trust until re-approved.
var trustCmd = &cobra.Command{
	Use:   "trust [path]",
	Short: "Manage trusted project policy overlays",
	Long: `Trust the ./.agentjail/policy.yaml overlay found at PATH (default: current
directory, searching up to the git root).

A project overlay can only WIDEN policy (add allowed hosts / MCP servers); it can
never drop the non-removable essentials, un-block a blocked MCP, or clear
disabled rules. Until you trust it, the overlay is ignored and only your global
~/.agentjail/policy.yaml applies. Editing the file after trusting it revokes
trust until you run 'agentjail trust' again.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runTrust(args)
	},
}

var trustAddCmd = &cobra.Command{
	Use:   "add [path]",
	Short: "Trust a project policy overlay",
	Long: `Trust the .agentjail/policy.yaml found at PATH. With no PATH, search from
the current directory up to the git root. Trust is tied to the file's content
hash, so editing the overlay requires approving it again.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runTrust(args)
	},
}

var trustListCmd = &cobra.Command{
	Use:   "list",
	Short: "List trusted overlays and whether their content is unchanged",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runTrustList()
	},
}

var untrustCmd = &cobra.Command{
	Use:    "untrust [path]",
	Short:  "Compatibility alias for 'agentjail trust remove'",
	Hidden: true,
	Args:   cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runUntrust(args)
	},
}

var trustRemoveCmd = &cobra.Command{
	Use:   "remove [path]",
	Short: "Remove a project policy overlay from the trust list",
	Long: `Remove the .agentjail/policy.yaml found at PATH from the trust list. With
no PATH, search from the current directory up to the git root; if the overlay
was deleted, target the conventional overlay path under the current directory.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runUntrust(args)
	},
}

func init() {
	trustCmd.AddCommand(trustAddCmd, trustRemoveCmd, trustListCmd)
	rootCmd.AddCommand(trustCmd)
	rootCmd.AddCommand(untrustCmd)
}

// startDirAndTrustPath resolves the search directory (from args or CWD) and the
// user's trust-store path.
func startDirAndTrustPath(args []string) (startDir, homeDir, trustPath string, err error) {
	homeDir, err = os.UserHomeDir()
	if err != nil {
		return "", "", "", fmt.Errorf("resolve home directory: %w", err)
	}
	if len(args) == 1 {
		startDir, err = filepath.Abs(args[0])
		if err != nil {
			return "", "", "", fmt.Errorf("resolve path %q: %w", args[0], err)
		}
	} else {
		startDir, err = os.Getwd()
		if err != nil {
			return "", "", "", fmt.Errorf("resolve current directory: %w", err)
		}
	}
	trustPath = projectpolicy.TrustStorePath(filepath.Join(homeDir, projectpolicy.ProjectDirName))
	return startDir, homeDir, trustPath, nil
}

func runTrust(args []string) error {
	startDir, homeDir, trustPath, err := startDirAndTrustPath(args)
	if err != nil {
		return err
	}
	o, err := projectpolicy.FindOverlay(startDir, homeDir)
	if err != nil {
		return fmt.Errorf("search for project overlay: %w", err)
	}
	if o == nil {
		return fmt.Errorf("no ./%s/%s found under %s (searching up to the git root)",
			projectpolicy.ProjectDirName, projectpolicy.ProjectPolicyFile, startDir)
	}

	ts, err := projectpolicy.LoadTrustStore(trustPath)
	if err != nil {
		return fmt.Errorf("load trust store: %w", err)
	}
	if ts.IsTrusted(o) {
		fmt.Printf("already trusted: %s (sha256 %s)\n", o.Path, shortHash(o.ContentHash))
		return nil
	}

	// Show what this overlay would add, so the user sees what they approve.
	printOverlayEffect(o)

	ts.Trust(o)
	if err := ts.Save(); err != nil {
		return fmt.Errorf("save trust store: %w", err)
	}
	fmt.Printf("trusted: %s (sha256 %s)\n", o.Path, shortHash(o.ContentHash))
	return nil
}

func runUntrust(args []string) error {
	startDir, homeDir, trustPath, err := startDirAndTrustPath(args)
	if err != nil {
		return err
	}
	ts, err := projectpolicy.LoadTrustStore(trustPath)
	if err != nil {
		return fmt.Errorf("load trust store: %w", err)
	}
	// Prefer the discovered overlay's path; fall back to the conventional path
	// under startDir so a deleted overlay can still be untrusted.
	target := filepath.Join(startDir, projectpolicy.ProjectDirName, projectpolicy.ProjectPolicyFile)
	if o, _ := projectpolicy.FindOverlay(startDir, homeDir); o != nil {
		target = o.Path
	}
	if !ts.Untrust(target) {
		fmt.Printf("not in the trust list: %s\n", target)
		return nil
	}
	if err := ts.Save(); err != nil {
		return fmt.Errorf("save trust store: %w", err)
	}
	fmt.Printf("untrusted: %s\n", target)
	return nil
}

func runTrustList() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home directory: %w", err)
	}
	trustPath := projectpolicy.TrustStorePath(filepath.Join(homeDir, projectpolicy.ProjectDirName))
	ts, err := projectpolicy.LoadTrustStore(trustPath)
	if err != nil {
		return fmt.Errorf("load trust store: %w", err)
	}
	entries := ts.Entries()
	if len(entries) == 0 {
		fmt.Println("no trusted project overlays")
		return nil
	}
	for _, e := range entries {
		status := "ok"
		if data, err := os.ReadFile(e.Path); err != nil {
			status = "MISSING"
		} else if projectpolicy.HashContent(data) != e.ContentHash {
			status = "CHANGED (trust revoked until re-approved)"
		}
		fmt.Printf("%s  sha256 %s  [%s]\n", e.Path, shortHash(e.ContentHash), status)
	}
	return nil
}

// printOverlayEffect parses the overlay and prints the hosts / MCPs it declares,
// so `agentjail trust` shows what is being approved (best-effort; a parse error
// is reported but does not block trusting -- the shield ignores an invalid
// overlay at launch anyway).
func printOverlayEffect(o *projectpolicy.Overlay) {
	overlayCfg, err := config.Load(o.Path)
	if err != nil {
		fmt.Printf("warning: overlay does not parse cleanly (%v); it will be ignored at launch until fixed\n", err)
		return
	}
	if len(overlayCfg.Network.AllowedHosts) > 0 {
		fmt.Printf("  adds allowed hosts: %v\n", overlayCfg.Network.AllowedHosts)
	}
	if len(overlayCfg.MCP.Allowed) > 0 {
		fmt.Printf("  adds allowed MCPs:  %v\n", overlayCfg.MCP.Allowed)
	}
	if len(overlayCfg.MCP.Blocked) > 0 {
		fmt.Printf("  adds blocked MCPs:  %v\n", overlayCfg.MCP.Blocked)
	}
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
