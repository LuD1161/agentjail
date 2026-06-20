// Package main is agentjail-shield — an OS-native sandbox launcher for coding agents.
//
// agentjail-shield wraps a coding agent (claude, codex, cursor, …) in the
// operating system's sandbox BEFORE exec'ing it.  Subprocesses inherit the
// sandbox, so bash tricks like:
//
//	printf 'x' > ~/.ssh/id_rsa
//	eval $(echo "…" | base64 -d)
//	python -c "open('~/.ssh/id_rsa','w').write('x')"
//
// all return EPERM at the kernel regardless of hook bypass.
//
// Platform behaviour:
//   - macOS: generates an Apple Seatbelt (sbpl) profile and execs via
//     /usr/bin/sandbox-exec.  Fails-open (with a loud warning) if
//     sandbox-exec is absent.
//   - Linux: calls Landlock landlock_create_ruleset + landlock_restrict_self
//     before execve; stubs out gracefully if the kernel predates 5.13.
//   - Other platforms: prints an "unsupported" warning and execs the agent
//     without any sandbox (fail-open).
//
// Usage:
//
//	agentjail-shield [--policy=PATH] [--profile-print] -- <agent-cmd> [args...]
//
// See also: docs/adr/0001-os-sandbox-enforcement-layer.md
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
)

// defaultPolicyPath returns ~/.agentjail/policy.yaml.
func defaultPolicyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/agentjail-policy.yaml"
	}
	return filepath.Join(home, ".agentjail", "policy.yaml")
}

func main() {
	policyPath := flag.String("policy", defaultPolicyPath(), "path to ~/.agentjail/policy.yaml")
	profilePrint := flag.Bool("profile-print", false, "print the sandbox profile to stderr and exit without running the agent")
	noNetproxy := flag.Bool("no-netproxy", false, "disable agentjail-netproxy; revert to port-based network filtering (no per-host enforcement)")
	auditJSON := flag.String("audit-json", "", "write environment audit findings as JSON to PATH (use '-' for stdout)")
	auditStrict := flag.Bool("audit-strict", false, "refuse to launch if critical audit findings (AdminAccess, root, IMDSv1)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: agentjail-shield [--policy=PATH] [--profile-print] [--no-netproxy] [--audit-json=PATH] [--audit-strict] -- <agent-cmd> [args...]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  --policy=PATH       path to ~/.agentjail/policy.yaml (default: ~/.agentjail/policy.yaml)")
		fmt.Fprintln(os.Stderr, "  --profile-print     print the generated sandbox profile to stderr and exit 0")
		fmt.Fprintln(os.Stderr, "  --no-netproxy       disable the localhost HTTPS proxy; reverts to port-based network filtering")
		fmt.Fprintln(os.Stderr, "  --audit-json=PATH   write environment audit as JSON to PATH (use '-' for stdout)")
		fmt.Fprintln(os.Stderr, "  --audit-strict      refuse to launch if critical audit findings")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Wraps the coding agent in the OS-native sandbox before exec.")
		fmt.Fprintln(os.Stderr, "Requires a '--' separator between shield flags and the agent command.")
		os.Exit(64) // EX_USAGE
	}
	flag.Parse()

	// The '--' separator is required.
	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "agentjail-shield: no agent command given after '--'")
		flag.Usage()
		return
	}

	// Load policy config. Errors (e.g. file not found) are tolerated:
	// we fall back to the built-in default baseline so the shield can
	// start even when no policy.yaml has been written yet.
	var cfg *config.PolicyConfig
	loaded, err := config.Load(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail-shield: could not load policy (%s): %v — using built-in defaults\n", *policyPath, err)
		cfg = config.Default()
	} else {
		// Merge loaded config with defaults so ExtraDeny/ExtraAllow are always
		// initialised even when the file omits those keys.
		defaults := config.Default()
		if loaded.File.ExtraDeny == nil {
			loaded.File.ExtraDeny = defaults.File.ExtraDeny
		}
		if loaded.File.ExtraAllow == nil {
			loaded.File.ExtraAllow = defaults.File.ExtraAllow
		}
		if loaded.Secrets.EnvBlocklist == nil {
			loaded.Secrets.EnvBlocklist = defaults.Secrets.EnvBlocklist
		}
		if loaded.Secrets.StripOnLaunch == nil {
			loaded.Secrets.StripOnLaunch = defaults.Secrets.StripOnLaunch
		}
		cfg = loaded
	}

	// Resolve the agent binary from PATH before we exec so we get a clear
	// error message instead of a confusing EPERM from inside the sandbox.
	agentCmd := args[0]
	agentPath, err := exec.LookPath(agentCmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail-shield: agent command %q not found in PATH: %v\n", agentCmd, err)
		os.Exit(127)
	}
	agentArgs := args[1:]

	// Run the environment audit before shield setup.  The audit is
	// best-effort and non-blocking: warnings are printed to stderr.
	// In --audit-strict mode, critical findings abort the launch.
	auditResult := runAudit()
	printAuditWarnings(auditResult)
	if *auditJSON != "" {
		if err := writeAuditJSON(auditResult, *auditJSON); err != nil {
			fmt.Fprintf(os.Stderr, "agentjail-shield: could not write audit JSON: %v\n", err)
		}
	}
	if *auditStrict && hasCriticalFindings(auditResult) {
		fmt.Fprintln(os.Stderr, "agentjail-shield: --audit-strict: refusing to launch due to critical audit findings")
		os.Exit(1)
	}

	// Delegate to the OS-specific sandbox implementation.
	runShield(cfg, agentPath, agentArgs, *profilePrint, *noNetproxy, *policyPath)
}
