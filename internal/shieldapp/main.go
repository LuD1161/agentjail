// Package shieldapp is agentjail-shield — an OS-native sandbox launcher for coding agents.
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
package shieldapp

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/envaudit"
	"github.com/LuD1161/agentjail/internal/netns"
	"github.com/LuD1161/agentjail/internal/netpolicy"
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

// Run executes the agentjail-shield entrypoint with the given args (i.e.
// os.Args[1:]) and returns a process exit code.
//
// NOTE (deferred to T2, per the multicall-binary refactor plan): runShield
// (shield_darwin.go / shield_linux.go / shield_other.go) and several helpers
// it calls (abortOnNetproxyFailure in netproxy_failure.go) call os.Exit
// directly, and on Linux/macOS the happy path replaces the process image via
// syscall.Exec — which never returns to this function at all. That exec/exit
// behavior is core to the shield's job (the shielded agent must exit with the
// exact exit code of the sandboxed child, and Landlock/Seatbelt activation
// happens right up to the exec boundary) and is NOT simply "entry path flag
// parsing" — reworking it into a clean `return int` chain is a larger,
// riskier change than this mechanical extraction and is left for a later
// task. Run() itself does not call os.Exit; every os.Exit remaining in this
// package lives beneath runShield/abortOnNetproxyFailure.
func Run(args []string) int {
	// If this process was re-exec'd as a transparent-tunnel namespace holder or
	// a hardened-exec shim, run that role and exit/exec before any flag parsing.
	// No-op in the normal case. MUST stay first: the holder never returns, and
	// the TUN-fd handoff EOFs without it (ADR 0079, AGE-148).
	netns.MaybeRunReexec()

	fs := flag.NewFlagSet("agentjail-shield", flag.ContinueOnError)
	policyPath := fs.String("policy", defaultPolicyPath(), "path to ~/.agentjail/policy.yaml")
	profilePrint := fs.Bool("profile-print", false, "print the sandbox profile to stderr and exit without running the agent")
	// Egress enforcement (agentjail-netproxy) is OPT-IN and OFF by default:
	// the credentialed proxy URL breaks Claude Code's MCP HTTP transport on
	// macOS, and the transparent tunnel (planned) will supersede the
	// proxy with real per-session isolation and no proxy env. Until then the
	// shield runs port-only by default (filesystem/process/keychain sandbox
	// stays fully on); pass --netproxy to turn per-host egress filtering back
	// on. --no-netproxy is retained (now redundant with the default) so
	// existing shims/scripts do not break; if both are given, disable wins.
	// See ADR 0046.
	netproxyEnable := fs.Bool("netproxy", false, "enable agentjail-netproxy per-host egress enforcement (opt-in; default off until the transparent tunnel lands)")
	noNetproxy := fs.Bool("no-netproxy", false, "explicitly disable agentjail-netproxy (now the default); retained for back-compat")
	tunnelMode := fs.Bool("tunnel", false, "route agent traffic through the unprivileged-userns transparent gVisor forwarder for interception (Linux only; no privileged daemon). Decrypts HTTPS by default so policy templates apply; --no-mitm relays TLS opaquely instead")
	// Separate switch from --tunnel, on by default, overridable both ways.
	// ADR 0077 (D1, D2).
	mitmMode := fs.Bool("mitm", false, "force TLS interception on for this launch, overriding a network.tunnel_mitm: false opt-out (interception is already the default)")
	noMITM := fs.Bool("no-mitm", false, "transparent-only: relay the agent's TLS opaquely instead of decrypting it. Keeps netns isolation and IP/SNI visibility, but HTTP(S) policy templates cannot match (ADR 0077)")
	// Opt out of the base-URL capture gateway (on by default for a detected
	// provider agent under --tunnel). See ADR 0109-baseurl-capture-gateway.
	noProviderGateway := fs.Bool("no-provider-gateway", false, "do not route a detected provider agent (e.g. Claude Code) through the local capture gateway; the agent talks to its provider directly and its LLM API bodies are not captured (ADR 0109)")
	auditJSON := fs.String("audit-json", "", "write environment audit findings as JSON to PATH (use '-' for stdout)")
	auditStrict := fs.Bool("audit-strict", false, "refuse to launch if critical audit findings (AdminAccess, root, IMDSv1) or if cloud metadata (IMDS) is reachable in port-only mode")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: agentjail-shield [--policy=PATH] [--profile-print] [--netproxy] [--tunnel] [--no-mitm] [--audit-json=PATH] [--audit-strict] -- <agent-cmd> [args...]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  --policy=PATH       path to ~/.agentjail/policy.yaml (default: ~/.agentjail/policy.yaml)")
		fmt.Fprintln(os.Stderr, "  --profile-print     print the generated sandbox profile to stderr and exit 0")
		fmt.Fprintln(os.Stderr, "  --netproxy          enable per-host egress enforcement via agentjail-netproxy (opt-in; default off)")
		fmt.Fprintln(os.Stderr, "  --no-netproxy       (default) port-based network filtering only, no per-host enforcement")
		fmt.Fprintln(os.Stderr, "  --tunnel            (Linux) route the agent's traffic through the transparent tunnel so HTTP(S) policy applies. Decrypts HTTPS by default — see --no-mitm")
		fmt.Fprintln(os.Stderr, "  --mitm              force TLS interception on, overriding a network.tunnel_mitm: false opt-out (already the default)")
		fmt.Fprintln(os.Stderr, "  --no-mitm           transparent-only: relay the agent's TLS opaquely. HTTP(S) policy templates cannot match (ADR 0077)")
		fmt.Fprintln(os.Stderr, "  --no-provider-gateway  do not route a detected provider agent through the local capture gateway (ADR 0109)")
		fmt.Fprintln(os.Stderr, "  --audit-json=PATH   write environment audit as JSON to PATH (use '-' for stdout)")
		fmt.Fprintln(os.Stderr, "  --audit-strict      refuse to launch if critical audit findings, or if IMDS is reachable in port-only mode")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Wraps the coding agent in the OS-native sandbox before exec.")
		fmt.Fprintln(os.Stderr, "Requires a '--' separator between shield flags and the agent command.")
	}
	if err := fs.Parse(args); err != nil {
		return 64 // EX_USAGE
	}
	// The transparent tunnel is the supported network path; netproxy is
	// deprecated and survives only as this explicit, non-default mode.
	// See ADR 0104-shield-apparmor-userns.
	if *netproxyEnable {
		fmt.Fprintln(os.Stderr,
			"⚠ --netproxy is deprecated and will be removed in a future release. The\n"+
				"  transparent tunnel (agentjail install --with-apparmor) is the supported\n"+
				"  path and will become the default.")
	}
	startTime := time.Now()

	// Open the audit emitter BEFORE sandbox activation. After Landlock/
	// Seatbelt is applied, new file opens may be restricted. Pre-opened
	// file descriptors survive Landlock.
	//
	// A failure here never blocks the launch, and never passes silently:
	// stderr is still the user's terminal at this point, and the marker is
	// what doctor can read later. See ADR 0089-record-shield-launches.
	var emitter audit.Emitter = audit.NopEmitter{}
	stateDir, err := shieldStateDir()
	if err != nil {
		fmt.Fprint(os.Stderr, unrecordableWarning("~/.agentjail/agentjail.db", err))
	} else {
		st, openErr := openShieldAudit(stateDir)
		if openErr != nil {
			fmt.Fprint(os.Stderr, unrecordableWarning(shieldDBPath(stateDir), openErr))
			markShieldUnrecorded(stateDir, openErr)
		} else {
			emitter = st
			defer st.Close()
		}
	}
	ctx := context.Background()

	// The '--' separator is required.
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "agentjail-shield: no agent command given after '--'")
		fs.Usage()
		return 64
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
		return 1
	}

	// --no-provider-gateway is a per-launch override that beats any config
	// opt-in, mirroring --no-mitm. See ADR 0109-baseurl-capture-gateway.
	if *noProviderGateway {
		cfg.Network.CaptureGateway = new(bool) // *bool -> false
	}

	// Same reasoning as the policy file above, applied to the L7 templates: a
	// malformed template used to load as a match-everything no-op, so a typo
	// silently disabled the rule the user thought they had. Checked here rather
	// than in startTunnel because the tunnel is fail-open by design -- a load
	// error there would drop to netproxy and lose the policy just as quietly.
	// Only when --tunnel is requested: that is when templates are consulted.
	// ADR 0040, ADR 0041, AGE-227.
	if *tunnelMode {
		if dir := resolveNetpacksDir(); dir != "" {
			// A configured-but-absent directory is its own mistake, and gets
			// its own message: it is not a malformed template. It used to fail
			// deeper in, where the gateway error dropped the whole tunnel to
			// netproxy -- so pointing at a typo'd path silently removed all L7
			// policy rather than saying so.
			if fi, serr := os.Stat(dir); serr != nil || !fi.IsDir() {
				fmt.Fprintf(os.Stderr, "agentjail-shield: network policy templates directory %s cannot be read: %v\n", dir, serr)
				fmt.Fprintln(os.Stderr, "agentjail-shield: refusing to launch -- templates were configured but none can be loaded, so no HTTP(S) policy would apply")
				return 1
			}
			if err := netpolicy.ValidateDir(dir); err != nil {
				fmt.Fprintf(os.Stderr, "agentjail-shield: invalid network policy template: %v\n", err)
				fmt.Fprintln(os.Stderr, "agentjail-shield: refusing to launch the agent with a malformed template -- a template that cannot be parsed enforces nothing")
				return 1
			}
		}
	}

	// Resolve the agent binary from PATH before we exec so we get a clear
	// error message instead of a confusing EPERM from inside the sandbox.
	agentCmd := rest[0]
	agentPath, err := exec.LookPath(agentCmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail-shield: agent command %q not found in PATH: %v\n", agentCmd, err)
		return 127
	}
	agentArgs := rest[1:]

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
		return 1
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

	// Pre-exec guards, all exempted under --profile-print (which never execs
	// the agent, only prints the profile and exits).
	if !*profilePrint {
		// Cloud-metadata (IMDS) egress guard (P2/M2, ADR 0049). In the default
		// port-only mode neither backend can filter egress by destination IP
		// (CapMetadataIPFilter, shield_contract.go), so 169.254.169.254 is
		// reachable over the same allowlisted port 80 as any other host. Since
		// there is no network-layer mitigation available, this probes
		// reachability and either refuses to launch (--audit-strict) or emits a
		// loud warning + audit finding (default) -- run before runShield/exec
		// so a refusal never spawns the agent.
		decision := decideMetadataEgress(probeMetadataReachable(), noNetproxyEffective, *auditStrict)
		if decision.Applicable {
			fmt.Fprintf(os.Stderr, "agentjail-shield: %s\n", decision.Message)
			_ = emitter.Emit(ctx, audit.Event{
				EventType: audit.ShieldMetadataEgressExposed,
				Detail:    map[string]string{"refused": fmt.Sprintf("%t", decision.Refuse), "strict": fmt.Sprintf("%t", *auditStrict)},
				Actor:     "shield",
			})
			if decision.Refuse {
				return 1
			}
		}

		// Hook-registration reassertion (P11, see shield_hook_reassert.go). Run
		// immediately before exec so every shielded launch starts with the
		// agentjail PreToolUse hook guaranteed present in the agent's settings,
		// regardless of what a previous session did to that file.
		reassertAgentHook(ctx, agentCmd, emitter)
	}

	// Delegate to the OS-specific sandbox implementation. runShield does not
	// return on the happy path (see the Run doc comment above): it either
	// syscall.Exec's into the sandboxed agent (replacing this process image)
	// or calls os.Exit itself on a fatal setup error. The return 0 below is
	// unreachable in practice but keeps this function's signature honest.
	runShield(cfg, agentPath, agentArgs, *profilePrint, noNetproxyEffective, *tunnelMode,
		resolveMITM(*mitmMode, *noMITM, cfg.Network.TunnelMITM), *policyPath, startTime, emitter)
	return 0
}

// unrecordedMarkerName is the file dropped beside the store when a launch could
// not open it. Without it, an absent shield.activated cannot be told apart from
// a shield that never ran. See ADR 0089-record-shield-launches.
const unrecordedMarkerName = "shield-unrecorded"

// shieldStateDir returns ~/.agentjail. Unlike defaultPolicyPath there is no
// /tmp fallback: a store written outside $HOME is one no reader looks in.
func shieldStateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if home == "" {
		return "", errors.New("home directory is empty")
	}
	return filepath.Join(home, ".agentjail"), nil
}

// shieldDBPath returns the audit store path inside stateDir.
func shieldDBPath(stateDir string) string {
	return filepath.Join(stateDir, "agentjail.db")
}

// openShieldAudit opens the shield's audit store. The error is returned rather
// than swallowed: the caller must warn and mark, not launch quietly.
func openShieldAudit(stateDir string) (store.EventStore, error) {
	st, err := store.Open(shieldDBPath(stateDir))
	if err != nil {
		return nil, err
	}
	return st, nil
}

// unrecordableWarning is the pre-sandbox stderr banner. Landlock/Seatbelt is
// not applied yet, so this is the last moment the shield can speak plainly.
func unrecordableWarning(dbPath string, err error) string {
	return fmt.Sprintf(
		"agentjail-shield: WARNING: audit store %s could not be opened: %v\n"+
			"agentjail-shield: the sandbox still applies, but this session will NOT be recorded --\n"+
			"agentjail-shield: it will be missing from `agentjail logs` and invisible to `agentjail doctor`.\n"+
			"agentjail-shield: fix the store to restore the audit trail; the agent is launching anyway.\n",
		dbPath, err)
}

// unrecordedMarker is the marker's on-disk shape.
type unrecordedMarker struct {
	TS     string `json:"ts"`
	PID    int    `json:"pid"`
	Reason string `json:"reason"`
}

// markShieldUnrecorded records that a launch proceeded without a store.
// Best-effort by necessity: the causes that break the store (unwritable dir,
// full disk) break this write too. See ADR 0089-record-shield-launches.
func markShieldUnrecorded(stateDir string, reason error) {
	b, err := json.Marshal(unrecordedMarker{
		TS:     time.Now().UTC().Format(time.RFC3339),
		PID:    os.Getpid(),
		Reason: reason.Error(),
	})
	if err != nil {
		return
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(stateDir, unrecordedMarkerName), append(b, '\n'), 0o600)
}

// resolveMITM decides whether this launch decrypts TLS. On by default -- it is
// the only way the DSL reaches HTTP(S) -- but always overridable: --no-mitm
// wins outright, then --mitm, then network.tunnel_mitm's standing posture.
// ADR 0077 (D2, D3).
func resolveMITM(mitmFlag, noMITMFlag bool, cfgTunnelMITM *bool) bool {
	switch {
	case noMITMFlag:
		return false
	case mitmFlag:
		return true
	case cfgTunnelMITM != nil:
		return *cfgTunnelMITM
	default:
		return true
	}
}

// resolveNoNetproxy computes the effective "netproxy disabled" value from the
// two flags. Egress enforcement is OPT-IN (ADR 0046): it is on only when
// --netproxy is passed and --no-netproxy is not. The default (both false) is
// port-only, and an explicit --no-netproxy always wins over --netproxy.
func resolveNoNetproxy(netproxyEnable, noNetproxy bool) bool {
	return !netproxyEnable || noNetproxy
}
