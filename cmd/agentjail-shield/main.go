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
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/envaudit"
	"github.com/LuD1161/agentjail/internal/store"
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
	// Egress enforcement (agentjail-netproxy) is OPT-IN and OFF by default:
	// the credentialed proxy URL breaks Claude Code's MCP HTTP transport on
	// macOS, and the transparent tunnel (follow-up/follow-up) will supersede the
	// proxy with real per-session isolation and no proxy env. Until then the
	// shield runs port-only by default (filesystem/process/keychain sandbox
	// stays fully on); pass --netproxy to turn per-host egress filtering back
	// on. --no-netproxy is retained (now redundant with the default) so
	// existing shims/scripts do not break; if both are given, disable wins.
	// See ADR 0046.
	netproxyEnable := flag.Bool("netproxy", false, "enable agentjail-netproxy per-host egress enforcement (opt-in; default off until the transparent tunnel lands)")
	noNetproxy := flag.Bool("no-netproxy", false, "explicitly disable agentjail-netproxy (now the default); retained for back-compat")
	auditJSON := flag.String("audit-json", "", "write environment audit findings as JSON to PATH (use '-' for stdout)")
	auditStrict := flag.Bool("audit-strict", false, "refuse to launch if critical audit findings (AdminAccess, root, IMDSv1) or if cloud metadata (IMDS) is reachable in port-only mode")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: agentjail-shield [--policy=PATH] [--profile-print] [--netproxy] [--audit-json=PATH] [--audit-strict] -- <agent-cmd> [args...]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  --policy=PATH       path to ~/.agentjail/policy.yaml (default: ~/.agentjail/policy.yaml)")
		fmt.Fprintln(os.Stderr, "  --profile-print     print the generated sandbox profile to stderr and exit 0")
		fmt.Fprintln(os.Stderr, "  --netproxy          enable per-host egress enforcement via agentjail-netproxy (opt-in; default off)")
		fmt.Fprintln(os.Stderr, "  --no-netproxy       (default) port-based network filtering only, no per-host enforcement")
		fmt.Fprintln(os.Stderr, "  --audit-json=PATH   write environment audit as JSON to PATH (use '-' for stdout)")
		fmt.Fprintln(os.Stderr, "  --audit-strict      refuse to launch if critical audit findings, or if IMDS is reachable in port-only mode")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Wraps the coding agent in the OS-native sandbox before exec.")
		fmt.Fprintln(os.Stderr, "Requires a '--' separator between shield flags and the agent command.")
		os.Exit(64) // EX_USAGE
	}
	flag.Parse()
	startTime := time.Now()

	// Open the audit emitter BEFORE sandbox activation. After Landlock/
	// Seatbelt is applied, new file opens may be restricted. Pre-opened
	// file descriptors survive Landlock.
	var emitter audit.Emitter = audit.NopEmitter{}
	home, _ := os.UserHomeDir()
	if home != "" {
		dbPath := filepath.Join(home, ".agentjail", "agentjail.db")
		if st, err := store.Open(dbPath); err == nil {
			emitter = st
			defer st.Close()
		}
	}
	ctx := context.Background()

	// The '--' separator is required.
	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "agentjail-shield: no agent command given after '--'")
		flag.Usage()
		return
	}

	// Load policy config via the canonical enforcement path
	// (config.LoadPolicyForEnforcement): a MISSING file is tolerated --
	// first run, before `agentjail install` has written a policy.yaml --
	// and falls back to Merge(Default(), &PolicyConfig{}) (i.e. built-in
	// defaults). A PRESENT but unparseable/invalid file is NOT tolerated:
	// silently falling back to permissive built-in defaults on a typo (e.g.
	// a stray tab, or a bad mcp.allowed glob) would swap the enforced
	// policy out from under the user without any indication, which is
	// worse than refusing to launch. See ADR 0040 and ADR 0041.
	cfg, err := config.LoadPolicyForEnforcement(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail-shield: policy file %s exists but could not be loaded: %v\n", *policyPath, err)
		fmt.Fprintln(os.Stderr, "agentjail-shield: refusing to launch the agent with a malformed policy file -- fix the file or remove it to use built-in defaults")
		os.Exit(1)
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
	auditResult := envaudit.RunAudit()
	if *auditJSON != "" || *auditStrict {
		printAuditWarnings(auditResult)
	}
	if *auditJSON != "" {
		if err := writeAuditJSON(auditResult, *auditJSON); err != nil {
			fmt.Fprintf(os.Stderr, "agentjail-shield: could not write audit JSON: %v\n", err)
		}
	}
	if *auditStrict && envaudit.HasCriticalFindings(auditResult) {
		fmt.Fprintln(os.Stderr, "agentjail-shield: --audit-strict: refusing to launch due to critical audit findings")
		os.Exit(1)
	}

	// Emit audit findings to the unified audit log (best-effort).
	for _, f := range auditResult.Findings {
		_ = emitter.Emit(ctx, audit.Event{
			EventType: audit.ShieldAuditFinding,
			Entity:    f.Check,
			Detail:    map[string]string{"severity": string(f.Severity), "message": f.Message},
			Actor:     "shield",
		})
	}

	// Egress enforcement is opt-in: netproxy runs only when --netproxy is
	// passed and --no-netproxy is not. Default (neither flag) is port-only.
	noNetproxyEffective := resolveNoNetproxy(*netproxyEnable, *noNetproxy)

	// Cloud-metadata (IMDS) egress guard (P2/M2, ADR 0049). In the default
	// port-only mode neither backend can filter egress by destination IP
	// (CapMetadataIPFilter, shield_contract.go), so 169.254.169.254 is
	// reachable over the same allowlisted port 80 as any other host. Since
	// there is no network-layer mitigation available, this probes
	// reachability and either refuses to launch (--audit-strict) or emits a
	// loud warning + audit finding (default) -- run before runShield/exec
	// so a refusal never spawns the agent. --profile-print is exempted: it
	// only prints the profile and exits, never execs the agent.
	if !*profilePrint {
		decision := decideMetadataEgress(probeMetadataReachable(), noNetproxyEffective, *auditStrict)
		if decision.Applicable {
			fmt.Fprintf(os.Stderr, "agentjail-shield: %s\n", decision.Message)
			_ = emitter.Emit(ctx, audit.Event{
				EventType: audit.ShieldMetadataEgressExposed,
				Detail:    map[string]string{"refused": fmt.Sprintf("%t", decision.Refuse), "strict": fmt.Sprintf("%t", *auditStrict)},
				Actor:     "shield",
			})
			if decision.Refuse {
				os.Exit(1)
			}
		}
	}

	// Delegate to the OS-specific sandbox implementation.
	runShield(cfg, agentPath, agentArgs, *profilePrint, noNetproxyEffective, *policyPath, startTime, emitter)
}

// resolveNoNetproxy computes the effective "netproxy disabled" value from the
// two flags. Egress enforcement is OPT-IN (ADR 0046): it is on only when
// --netproxy is passed and --no-netproxy is not. The default (both false) is
// port-only, and an explicit --no-netproxy always wins over --netproxy.
func resolveNoNetproxy(netproxyEnable, noNetproxy bool) bool {
	return !netproxyEnable || noNetproxy
}
