//go:build linux

package shieldapp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/ctlauth"
	"github.com/LuD1161/agentjail/internal/proxyctl"
	"github.com/LuD1161/agentjail/internal/sandbox"

	"golang.org/x/sys/unix"
)

// errLandlockUnsupported signals the kernel lacks Landlock (probe-time
// ENOSYS/EOPNOTSUPP). runShield fails OPEN only for this sentinel; every
// other applyLandlock error fails CLOSED.
var errLandlockUnsupported = errors.New("landlock not supported by kernel")

// netproxyDefaultPort is the TCP port the netproxy listens on.  Landlock
// network rules (ABI v4+, kernel 6.7+) allow the agent to CONNECT only to
// this port, forcing all HTTPS traffic through agentjail-netproxy which
// enforces network.allowed_hosts.
const netproxyDefaultPort = 9100

// landlockRuleNetPort is the rule type for Landlock network port rules.
// It corresponds to LANDLOCK_RULE_NET_PORT from include/uapi/linux/landlock.h.
// golang.org/x/sys/unix v0.45.0 does not yet expose this constant.
const landlockRuleNetPort = 2

// landlockNetPortAttr is the attribute struct for Landlock network port rules.
// It corresponds to struct landlock_net_port_attr from the kernel UAPI:
//
//	struct landlock_net_port_attr {
//	    __u64 allowed_access;
//	    __u64 port;
//	};
//
// golang.org/x/sys/unix v0.45.0 does not yet expose this struct.
type landlockNetPortAttr struct {
	AllowedAccess uint64
	Port          uint64
}

// LandlockNetPlan is the pure, inspectable network-rule plan applyLandlock
// will translate into landlock_add_rule calls. buildLandlockNetPlan builds
// this as data, with NO landlock_* syscalls, so tests can assert the plan
// honors the shared contract (NoNetproxyFallbackPorts, resolved OAuth bind
// ports) without triggering Landlock's irreversible restrict_self. See ADR
// 0039 and FIX4's "inspectable rule-plan" requirement.
type LandlockNetPlan struct {
	// ABI is the probed Landlock ABI version this plan was built for.
	ABI int
	// Handled is true if this plan asks Landlock to handle network access at
	// all (false on ABI < 4, where the network access-rights bits don't
	// exist yet and ruleset creation must not request them).
	Handled bool
	// HandleBindTCP is true if NET_BIND_TCP is included in the ruleset's
	// handled mask. Deliberately false in the --no-netproxy fallback case
	// (netproxyPort <= 0): including it would deny every unlisted bind,
	// which would regress dynamic (not-yet-in-credentials) OAuth callback
	// ports that Landlock cannot special-case ahead of time.
	HandleBindTCP bool
	// ConnectPorts are the ports the agent is allowed to TCP CONNECT to.
	ConnectPorts []int
	// BindPorts are the ports the agent is allowed to TCP bind to (only
	// meaningful when HandleBindTCP is true).
	BindPorts []int
	// Unsupported names, precisely, which shared-contract capabilities this
	// backend cannot honor and why -- never a silent drop. Always populated
	// regardless of network mode: Landlock has no filename/basename
	// primitive, and Landlock network rules are port-scoped only (no
	// per-interface/address restriction), on every ABI version.
	Unsupported map[CapabilityKey]UnsupportedReason
}

// buildLandlockNetPlan is the pure function FIX4 requires: it decides what
// network rules applyLandlock should add, as data, without calling any
// landlock_* syscall.
//
//   - netproxyPort > 0 (netproxy enabled): CONNECT restricted to netproxyPort
//     only; BIND restricted to the resolved OAuth callback ports (oauthPorts).
//   - netproxyPort <= 0 (--no-netproxy): CONNECT restricted to the shared
//     contract's NoNetproxyFallbackPorts() ({80, 443}); BIND is left
//     unhandled (see HandleBindTCP doc above).
//   - abi < 4: network access rights don't exist in this kernel's Landlock
//     ABI; Handled stays false and no network rules are added (FS-only
//     Landlock, unchanged pre-ABI-v4 behavior).
func buildLandlockNetPlan(abi int, netproxyPort int, oauthPorts []int) LandlockNetPlan {
	plan := LandlockNetPlan{
		ABI: abi,
		Unsupported: map[CapabilityKey]UnsupportedReason{
			CapFilenamePatternDeny: "landlock-has-no-filename-regex; enforced by hook layer (agentpolicy/policies/file_policy.rego)",
			CapLoopbackScopedBind:  "landlock net rules (LANDLOCK_RULE_NET_PORT) are port-scoped only; there is no per-interface/address restriction, so a granted bind/connect port is reachable on any interface, not loopback-only",
			CapMetadataIPFilter:    "landlock net rules (LANDLOCK_RULE_NET_PORT) are port-scoped only -- there is no destination-address component, so the port-only fallback's CONNECT-to-{22,80,443} rule cannot carve out a deny for 169.254.169.254; mitigated by the launch-time decideMetadataEgress guard in main.go instead (ADR 0049)",
		},
	}
	if abi < 4 {
		return plan
	}
	if netproxyPort > 0 {
		plan.Handled = true
		plan.HandleBindTCP = true
		plan.ConnectPorts = []int{netproxyPort}
		plan.BindPorts = oauthPorts
		return plan
	}
	// --no-netproxy fallback: restrict CONNECT to the shared contract's
	// fallback ports; leave BIND unhandled.
	plan.Handled = true
	plan.ConnectPorts = NoNetproxyFallbackPorts()
	return plan
}

// runShield is the Linux implementation of the shield launcher.
//
// It uses the Landlock LSM (Linux 5.13+, June 2021) to restrict the process
// and all its descendants from writing to sensitive paths.
//
// Landlock is allowlist-based (opposite of sbpl deny-list): you grant access
// to specific paths; everything not explicitly allowed is denied by default.
// This means the Linux implementation must enumerate all paths the agent
// legitimately needs to write (project CWD, /tmp, /dev/null, etc.) rather
// than just listing the paths to deny.
//
// Network egress: Landlock gained LANDLOCK_ACCESS_NET_CONNECT_TCP in ABI v4
// (Linux 6.7, Jan 2024).  When netproxy is enabled and the kernel supports
// ABI v4+, the agent is restricted to TCP connect only on the netproxy port
// (9100).  All other TCP connect is denied, including IMDS (169.254.169.254)
// and direct egress.  When --no-netproxy is set and ABI v4+ is available,
// CONNECT is instead restricted to the shared contract's
// NoNetproxyFallbackPorts() (80, 443) -- see buildLandlockNetPlan and ADR
// 0039; this replaced a prior "completely unrestricted" fallback.  On
// kernels < 6.7, network ABI is unavailable; a warning is printed and
// FS-only Landlock is applied (current behavior).
//
// Landlock caveat: truncate(2) is only covered as of ABI v3 (Linux 6.2).
// On kernels < 6.2 an agent can truncate sensitive files.  We document this
// boundary in the README.
//
// If the kernel does not support Landlock (< 5.13) or the feature is not
// compiled in, we fail open with a loud warning (errLandlockUnsupported
// sentinel). Any other applyLandlock error is fail-closed: we refuse to run
// the agent unsandboxed unless AGENTJAIL_SHIELD_ALLOW_UNSANDBOXED=1.
//
// Privilege requirement: none.  Landlock is designed for unprivileged use.
func runShield(cfg *config.PolicyConfig, agentPath string, agentArgs []string, profilePrint bool, noNetproxy bool, tunnelMode bool, mitmMode bool, policyPath string, startTime time.Time, emitter audit.Emitter) {
	ctx := context.Background()
	noColor := os.Getenv("NO_COLOR") != ""
	if noColor {
		fmt.Fprintln(os.Stderr, "  agentjail — setting up sandbox...")
	} else {
		fmt.Fprintln(os.Stderr, "  \033[38;5;208magentjail\033[0m — setting up sandbox...")
	}

	// Tunnel mode: try to start the unprivileged-userns transparent tunnel
	// (ADR 0079). On success the agent runs inside the namespace and its
	// traffic is intercepted by the userspace forwarder, so netproxy is
	// skipped. On ANY failure we fall back to netproxy (fail-open).
	var tunnelSess *tunnelSession
	if tunnelMode {
		if s, ready := startTunnel(ctx, mitmMode); ready {
			tunnelSess = s
			noNetproxy = true
			defer tunnelSess.cleanup()
			// Announce the posture ACHIEVED, not the one asked for: interception
			// can be requested and still fail open to the relay, and claiming we
			// decrypt when we don't is the misrepresentation D4 forbids.
			// ADR 0077 (D4, D5).
			posture := "TLS interception off — transparent-only, HTTP(S) policy will not match"
			if tunnelSess.mitmActive {
				posture = "TLS interception ON — decrypting this agent's HTTPS"
			}
			if noColor {
				fmt.Fprintf(os.Stderr, "  ✓ transparent tunnel active (userns) · %s\n", posture)
			} else {
				fmt.Fprintf(os.Stderr, "  \033[32m✓\033[0m transparent tunnel active (userns) · %s\n", posture)
			}
		} else {
			fmt.Fprintln(os.Stderr, "  ⚠ tunnel not available, falling back to netproxy")
		}
	}

	// Start netproxy as a child process BEFORE applying Landlock — netproxy
	// needs unrestricted network access to reach upstream hosts.  Landlock
	// (applied below) restricts the shield + agent, not the netproxy child
	// which was already forked before restriction.
	netproxyPort := 0
	var netproxyCmd *exec.Cmd       // non-nil only if WE started the proxy (we must clean it up)
	netproxyReady := false          // true if a proxy is available (ours or pre-existing)
	var sessionToken proxyctl.Token // this session's per-session proxy credential
	if !noNetproxy {
		netproxyPort = netproxyDefaultPort
		netproxyBin, findErr := findNetproxyBinary()
		if findErr != nil {
			// Fail-closed default (ADR 0041): netproxy was requested (no
			// --no-netproxy) but its binary could not be located. Aborting
			// here, rather than silently downgrading to no per-host
			// enforcement, keeps "the shield is running" and
			// "network.allowed_hosts is enforced" from silently diverging.
			abortOnNetproxyFailure(ctx, emitter, fmt.Sprintf("could not locate agentjail-netproxy binary: %v", findErr))
		}
		// Register THIS session's resolved allowlist with the (possibly shared)
		// netproxy and get back the token to inject. This runs BEFORE Landlock,
		// so the shield can still reach the control socket; the agent (post-
		// Landlock) cannot (the socket lives under the read-only ~/.agentjail
		// grant, and AF_UNIX connect needs write). Incompatible/unverifiable
		// proxy -> fail closed inside ensureSessionProxy.
		shieldCwd, _ := os.Getwd()
		cmd, tok, startErr := ensureSessionProxy(netproxyBin, netproxyDefaultAddr, fmt.Sprintf("shield-%d", os.Getpid()), shieldCwd, resolveSessionPolicy(ctx, cfg, emitter))
		if startErr != nil {
			abortOnNetproxyFailure(ctx, emitter, fmt.Sprintf("could not start/register netproxy: %v", startErr))
		}
		netproxyCmd = cmd // nil when reusing existing singleton
		sessionToken = tok
		netproxyReady = true
	}

	// netproxy started (or reused singleton)

	if profilePrint {
		fmt.Fprintln(os.Stderr, "=== agentjail-shield: Linux Landlock rule summary ===")
		fmt.Fprintln(os.Stderr, "Allow (read-write):")
		fmt.Fprintln(os.Stderr, "  /tmp")
		fmt.Fprintln(os.Stderr, "  <cwd> (agent working directory, if determinable)")
		fmt.Fprintln(os.Stderr, "Allow (read-only):")
		fmt.Fprintln(os.Stderr, "  /usr, /bin, /lib, /lib64, /etc, /dev, /proc, /sys")
		fmt.Fprintln(os.Stderr, "  $HOME (excluding .ssh, .aws, .gnupg)")
		fmt.Fprintln(os.Stderr, "  ~/.agentjail (read-only; only daemon.sock is writable for the hook)")
		fmt.Fprintln(os.Stderr, "Deny (all access):")
		fmt.Fprintln(os.Stderr, "  everything not listed above")
		fmt.Fprintln(os.Stderr, "Note: Landlock is allowlist-based; this is an inversion of the sbpl deny-list.")
		if netproxyPort > 0 {
			fmt.Fprintf(os.Stderr, "Network (ABI v4+, kernel 6.7+):\n")
			fmt.Fprintf(os.Stderr, "  Allow TCP connect to port %d (netproxy) only\n", netproxyPort)
			fmt.Fprintln(os.Stderr, "  Deny all other TCP connect (IMDS, direct egress)")
			fmt.Fprintln(os.Stderr, "  On kernel < 6.7: warning printed, FS-only Landlock applied")
		} else {
			// FIX4 (ADR 0039): --no-netproxy is no longer "unrestricted" on
			// ABI v4+ kernels -- CONNECT is restricted to the shared fallback
			// ports (contract NoNetproxyFallbackPorts). Bind stays unhandled
			// so dynamic OAuth callback binds are not regressed.
			fmt.Fprintf(os.Stderr, "Network (port-only default, ABI v4+, kernel 6.7+):\n")
			fmt.Fprintf(os.Stderr, "  Allow TCP connect to ports %v only (no per-host enforcement)\n", NoNetproxyFallbackPorts())
			fmt.Fprintln(os.Stderr, "  Deny all other TCP connect; TCP bind left unhandled by Landlock")
			fmt.Fprintln(os.Stderr, "  On kernel < 6.7: network ABI unavailable, FS-only Landlock applied")
		}
		fmt.Fprintln(os.Stderr, "=======================================================")
		cleanupNetproxy(netproxyCmd)
		os.Exit(0)
	}

	// Capture the control token BEFORE Landlock: applyLandlock restricts THIS
	// process, and the token is excluded from the agent's read grants, so after
	// this point we cannot read it either (ADR 0067). Best-effort -- a missing
	// token costs the grants, it must not block the sandbox.
	ctlToken, ctlTokenErr := ctlauth.Load()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Landlock application differs between the two exec paths (AGE-166):
	//
	//   - Non-tunnel: restrict the shield itself now; the agent child inherits
	//     the restriction across fork/exec (applyLandlock).
	//   - Tunnel: the agent is exec'd via nsenter, which must open the holder's
	//     /proc/<pid>/ns/{user,net,mnt}. Those are nsfs inodes Landlock cannot
	//     cover (landlock_add_rule returns EBADFD on nsfs), so restricting the
	//     shield BEFORE nsenter denies that open (nsenter: cannot open
	//     /proc/<pid>/ns/user: Permission denied). Instead we BUILD the ruleset
	//     here (no restrict_self) and hand the fd to the post-nsenter harden
	//     shim, which calls restrict_self AFTER it has joined the namespaces.
	//     The agent still ends up fully FS-sandboxed; only the timing moves.
	//
	// landlockRulesetFD is >= 0 only in the tunnel path when a ruleset was
	// successfully built; it is passed to AgentCommand for in-shim restrict.
	landlockRulesetFD := -1
	var landlockErr error
	if tunnelSess != nil {
		fd, err := buildLandlockRuleset(cfg, netproxyPort)
		landlockErr = err
		if err == nil {
			landlockRulesetFD = fd
		}
	} else {
		landlockErr = applyLandlock(cfg, netproxyPort)
	}

	// Apply Landlock to the current process.  The agent (run as a child
	// below) inherits all Landlock restrictions.
	if err := landlockErr; err != nil {
		if errors.Is(err, errLandlockUnsupported) {
			stepFail(noColor, "Landlock unavailable — sandbox enforcement disabled")
			fmt.Fprintf(os.Stderr, "  Requires Linux 5.13+ with CONFIG_SECURITY_LANDLOCK=y.\n"+
				"  The hook layer still runs on every PreToolUse call.\n")
			_ = emitter.Emit(ctx, audit.Event{
				EventType: audit.ShieldFailed,
				Detail:    map[string]string{"error": "landlock not supported by kernel"},
				Actor:     "shield",
			})
		} else {
			stepFail(noColor, "Failed to apply sandbox")
			fmt.Fprintf(os.Stderr, "  %v\n"+
				"  Refusing to run the agent unsandboxed (fail-closed).\n"+
				"  Set AGENTJAIL_SHIELD_ALLOW_UNSANDBOXED=1 to override (NOT recommended).\n", err)
			_ = emitter.Emit(ctx, audit.Event{
				EventType: audit.ShieldFailed,
				Detail:    map[string]string{"error": err.Error()},
				Actor:     "shield",
			})
			if os.Getenv("AGENTJAIL_SHIELD_ALLOW_UNSANDBOXED") != "1" {
				cleanupNetproxy(netproxyCmd)
				os.Exit(1)
			}
		}
	} else {
		_ = emitter.Emit(ctx, audit.Event{
			EventType: audit.ShieldActivated,
			Actor:     "shield",
		})
	}

	// Landlock applied

	// Build the agent's environment: clean allowlist + strip defence-in-depth + proxy vars + granted secrets.
	env := sandbox.BuildCleanEnv(os.Environ(), cfg)
	env = sandbox.StripEnv(env, cfg)
	env = sandbox.RemoveEnvKeys(env, "GIT_SSH_COMMAND", "AGENTJAIL_SSH_OVERRIDE")
	gitSSHEnv := sandbox.AgentGitSSHEnv(os.Getenv)
	env = append(env, gitSSHEnv...)
	if sshOverrideInjected(gitSSHEnv) {
		fmt.Fprintln(os.Stderr, "agentjail-shield INFO: injected agent-backed GIT_SSH_COMMAND (pinned IdentityFile blind spot workaround; set AGENTJAIL_NO_SSH_OVERRIDE=1 to opt out)")
	}
	if netproxyReady {
		env = append(env, proxyEnvVars(netproxyDefaultAddr, sessionToken)...)
	}
	env = append(env, "AGENTJAIL_SHIELDED=1")
	if ctlTokenErr != nil && cfg != nil && len(cfg.Secrets.Grants) > 0 {
		fmt.Fprintf(os.Stderr, "agentjail-shield WARNING: no control token (%v); configured secret grants will be refused\n", ctlTokenErr)
	}
	grantEnvVars, activeGrants := requestSecretGrants(cfg, ctlToken)
	env = append(env, grantEnvVars...)

	elapsed := time.Since(startTime)
	if noColor {
		fmt.Fprintf(os.Stderr, "  agentjail — sandbox ready in %dms\n", elapsed.Milliseconds())
	} else {
		fmt.Fprintf(os.Stderr, "  \033[38;5;208magentjail\033[0m — sandbox ready in %dms\n", elapsed.Milliseconds())
	}

	// Run the agent as a child process.  Unlike macOS (which uses
	// syscall.Exec to replace the shield process), Linux uses os/exec so
	// the shield stays alive as the parent and can:
	//   - forward signals (SIGINT, SIGTERM) to the agent
	//   - kill and reap the netproxy child on agent exit (zombie cleanup)
	//
	// Landlock restrictions are inherited by the agent child because
	// Landlock applies to the process and all fork/exec descendants.
	//
	// When the transparent tunnel is active, the agent must run INSIDE the
	// network namespace so its traffic hits the TUN/forwarder. AgentCommand
	// runs it via nsenter + a hardening shim (cap-drop + secbits) so the
	// uid-0-in-userns agent cannot regain privileges. The Landlock ruleset built
	// above is handed to the shim via landlockRulesetFD, which applies
	// restrict_self AFTER nsenter has joined the namespaces (AGE-166) — so the
	// agent is FS-sandboxed without blocking nsenter's open of the nsfs ns files.
	var agentCmd *exec.Cmd
	if tunnelSess != nil {
		agentCmd = tunnelSess.ns.AgentCommand(agentPath, agentArgs, landlockRulesetFD)
		// Runtimes that ignore the namespace trust store need the CA named in
		// the env (ADR 0034, AGE-113).
		for k, v := range tunnelSess.caEnv {
			env = append(env, k+"="+v)
		}
	} else {
		agentCmd = exec.Command(agentPath, agentArgs...)
	}
	agentCmd.Env = env
	agentCmd.Stdin = os.Stdin
	agentCmd.Stdout = os.Stdout
	agentCmd.Stderr = os.Stderr

	// Intercept SIGINT and SIGTERM so the shield survives to print the
	// session summary. The agent child is in the same process group and
	// receives the signal directly from the terminal; we don't need to
	// forward it. signal.Notify prevents Go's default handler from
	// killing the shield process.
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		for range sigCh {
			// Drain signals — the agent already received them from the TTY.
		}
	}()

	runErr := agentCmd.Run()
	sessionDuration := time.Since(startTime)

	// Kill and reap the netproxy child (zombie cleanup).
	cleanupNetproxy(netproxyCmd)
	revokeSecretGrants(activeGrants, ctlToken)

	// Print session summary.
	printSessionSummary(noColor, sessionDuration)

	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "agentjail-shield: agent failed: %v\n", runErr)
		os.Exit(1)
	}
}

func printSessionSummary(noColor bool, duration time.Duration) {
	d := formatDuration(duration)
	fmt.Fprintln(os.Stderr, "")
	if noColor {
		fmt.Fprintf(os.Stderr, "  agentjail — session ended (%s) · secured throughout\n", d)
	} else {
		fmt.Fprintf(os.Stderr, "  \033[38;5;208magentjail\033[0m — session ended (%s) · secured throughout\n", d)
	}
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
}

// applyLandlock configures and applies a Landlock ruleset to the current
// process.  After this call returns (nil error), the process and all its
// fork/exec descendants cannot access filesystem paths not explicitly allowed.
//
// When netproxyPort > 0 and the kernel supports ABI v4+ (Linux 6.7+), the
// ruleset also handles TCP network connect: only connects to netproxyPort
// are allowed; all other TCP connect is denied.  TCP bind is handled but
// never granted, so all bind operations are denied.  On kernels < 6.7,
// network rules are skipped and a warning is printed (FS-only Landlock).
//
// Landlock ABI negotiation: we probe for the supported ABI version and build
// the handled access mask accordingly:
//   - ABI v1 (Linux 5.13): base FS access set
//   - ABI v2 (Linux 5.19): adds REFER (cross-directory rename/hardlink)
//   - ABI v3 (Linux 6.2):  adds TRUNCATE
//   - ABI v4 (Linux 6.7):  adds NET_BIND_TCP, NET_CONNECT_TCP
//   - ABI v5 (Linux 6.10): adds IOCTL_DEV
//
// Note on REFER (ABI v2+): REFER is included in the *handled* mask so the
// ruleset takes ownership of it, but we never grant it in any path's
// allowed_access. This means cross-directory rename/hardlink is denied by
// default on v2+ kernels (safe). On v1 kernels REFER is unavailable and such
// operations follow legacy DAC — an acceptable trade-off for older kernels.
// cwdEnclosesHome reports whether granting read-write on cwd would also expose
// the home directory's protected subtree (~/.ssh, ~/.aws, ~/.gnupg) — i.e. cwd
// is the home directory itself or an ancestor of it. Both paths are cleaned
// before comparison so trailing slashes / "." segments don't defeat the check.
// homeChild is a direct child of $HOME to grant as workspace, with the dir flag
// so the caller can pick directory- vs file-scoped Landlock access.
type homeChild struct {
	path  string
	isDir bool
}

// visibleHomeChildren returns the non-hidden direct children of home — the set
// granted read-write as the agent's workspace when it is launched from $HOME.
// Dotfiles/dotdirs are excluded because that's where credentials live
// (~/.ssh, ~/.aws, ~/.gnupg, ~/.config, ~/.netrc, ...); the specific dot-entries
// the agent legitimately needs are re-granted via the home allowlist instead.
func visibleHomeChildren(home string) ([]homeChild, error) {
	entries, err := os.ReadDir(home)
	if err != nil {
		return nil, err
	}
	var out []homeChild
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			continue // hidden — deny by default
		}
		out = append(out, homeChild{path: filepath.Join(home, e.Name()), isDir: e.IsDir()})
	}
	return out, nil
}

// resolveSymlinks returns the fully symlink-resolved form of p, falling back to
// p unchanged if resolution fails (e.g. the path doesn't exist).
func resolveSymlinks(p string) string {
	if p == "" {
		return p
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

func cwdEnclosesHome(cwd, home string) bool {
	if home == "" {
		return false
	}
	c := filepath.Clean(cwd)
	h := filepath.Clean(home)
	if c == h || c == string(filepath.Separator) {
		return true // same dir, or cwd is the filesystem root (encloses everything)
	}
	return strings.HasPrefix(h, c+string(filepath.Separator))
}

// applyLandlock restricts the CURRENT process (and its fork/exec descendants).
// It is used by the non-tunnel path, where the shield itself is the direct
// parent of the agent. The transparent-tunnel path instead builds the ruleset
// with buildLandlockRuleset and hands the fd to the post-nsenter harden shim,
// which calls restrict_self AFTER nsenter has joined the namespaces — see
// restrictSelfWithRuleset and the AGE-166 note in runShield.
func applyLandlock(cfg *config.PolicyConfig, netproxyPort int) error {
	rulesetFd, err := buildLandlockRuleset(cfg, netproxyPort)
	if err != nil {
		return err
	}
	defer unix.Close(rulesetFd)
	return restrictSelfWithRuleset(rulesetFd)
}

// restrictSelfWithRuleset irreversibly applies an already-built Landlock
// ruleset fd to the current process. PR_SET_NO_NEW_PRIVS is a precondition for
// landlock_restrict_self; it is idempotent, so setting it here is safe even
// when the caller (the harden shim) already set it via ApplyHardening.
func restrictSelfWithRuleset(rulesetFd int) error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", err)
	}
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(rulesetFd), 0, 0); errno != 0 {
		return fmt.Errorf("landlock_restrict_self: %w", errno)
	}
	return nil
}

// buildLandlockRuleset probes the Landlock ABI, constructs the ruleset, and
// adds every filesystem and network allow-rule, returning the OPEN ruleset fd
// WITHOUT calling landlock_restrict_self. The caller owns the fd and must
// either apply it (restrictSelfWithRuleset) and close it, or hand it to the
// process that will (the transparent-tunnel harden shim). Splitting build from
// restrict lets the tunnel path defer restrict_self until AFTER nsenter has
// entered the namespaces: nsenter opens the holder's /proc/<pid>/ns/* (nsfs
// inodes that Landlock cannot grant — landlock_add_rule returns EBADFD on
// nsfs), so restricting before nsenter would deny that open (AGE-166).
func buildLandlockRuleset(cfg *config.PolicyConfig, netproxyPort int) (int, error) {
	// Probe supported Landlock ABI version (ruleset_attr=NULL, size=0, flags=VERSION).
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		if errno == unix.ENOSYS || errno == unix.EOPNOTSUPP {
			return -1, errLandlockUnsupported
		}
		return -1, fmt.Errorf("landlock_create_ruleset(probe): %w", errno)
	}

	// v1 (Linux 5.13) base FS access set — excludes REFER/TRUNCATE/IOCTL_DEV.
	handled := uint64(
		unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
			unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR |
			unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
			unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
			unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
			unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
			unix.LANDLOCK_ACCESS_FS_MAKE_SYM)
	if abi >= 2 {
		handled |= unix.LANDLOCK_ACCESS_FS_REFER // 5.19 — handled but never granted; see note above
	}
	if abi >= 3 {
		handled |= unix.LANDLOCK_ACCESS_FS_TRUNCATE // 6.2
	}
	if abi >= 5 {
		handled |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV // 6.10
	}

	// Network access handling (ABI v4+, Linux 6.7+). FIX4 (ADR 0039):
	// resolved via the pure, inspectable buildLandlockNetPlan -- see its doc
	// comment for the netproxy-enabled vs. --no-netproxy-fallback vs.
	// ABI<4 cases. home is resolved early (moved up from further below) so
	// OAuth callback ports can be read before the ruleset is created.
	home, _ := os.UserHomeDir()
	var oauthPorts []int
	if home != "" {
		oauthPorts = resolveOAuthCallbackPorts(filepath.Join(home, ".claude", ".credentials.json"))
	}
	netPlan := buildLandlockNetPlan(int(abi), netproxyPort, oauthPorts)
	handledNet := uint64(0)
	if netPlan.Handled {
		handledNet = unix.LANDLOCK_ACCESS_NET_CONNECT_TCP
		if netPlan.HandleBindTCP {
			handledNet |= unix.LANDLOCK_ACCESS_NET_BIND_TCP
		}
	}

	// Create the real ruleset.
	rulesetAttr := unix.LandlockRulesetAttr{
		Access_fs:  handled,
		Access_net: handledNet,
	}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&rulesetAttr)), unsafe.Sizeof(rulesetAttr), 0)
	if errno != 0 {
		return -1, fmt.Errorf("landlock_create_ruleset: %w", errno)
	}
	rulesetFd := int(fd)

	// Read-write access: places where the agent legitimately writes output.
	// The & handled masking inside allowPath ensures we never request bits
	// the current ABI doesn't know about (e.g. TRUNCATE on v1 kernels).
	rwAccess := uint64(
		unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
			unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR |
			unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
			unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
			unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
			unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
			unix.LANDLOCK_ACCESS_FS_MAKE_SYM |
			unix.LANDLOCK_ACCESS_FS_TRUNCATE | // ABI v3 (6.2); masked to 0 on older kernels
			unix.LANDLOCK_ACCESS_FS_IOCTL_DEV, // ABI v5 (6.10); masked to 0 on older kernels
	)
	// Read-only access: system directories, binaries.
	roAccess := uint64(unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR | unix.LANDLOCK_ACCESS_FS_EXECUTE)

	// File-only access (no directory flags like READ_DIR, MAKE_DIR, etc.).
	rwFileAccess := uint64(
		unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
			unix.LANDLOCK_ACCESS_FS_TRUNCATE |
			unix.LANDLOCK_ACCESS_FS_IOCTL_DEV,
	)
	roFileAccess := uint64(unix.LANDLOCK_ACCESS_FS_READ_FILE)

	// allowPath adds an allow rule for the given path with the specified access
	// rights (masked by the handled set so we never request unknown bits).
	// If the path does not exist the rule is silently skipped.
	allowPath := func(path string, allowedAccess uint64) error {
		dirFd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil // path absent → skip
		}
		defer unix.Close(dirFd)
		pathAttr := unix.LandlockPathBeneathAttr{
			Allowed_access: allowedAccess & handled,
			Parent_fd:      int32(dirFd),
		}
		if _, _, e := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE,
			uintptr(rulesetFd), unix.LANDLOCK_RULE_PATH_BENEATH,
			uintptr(unsafe.Pointer(&pathAttr)), 0, 0, 0); e != 0 {
			return fmt.Errorf("landlock_add_rule(%s): %w", path, e)
		}
		return nil
	}

	cwd, _ := os.Getwd()

	// Allow read-write on /tmp always. cwd is granted read-write too — UNLESS
	// cwd encloses $HOME. A wholesale grant on such a cwd would swallow the
	// sensitive home subtree (~/.ssh, ~/.aws, ~/.gnupg, and every other dotfile
	// where credentials live) that the allowlist below deliberately withholds,
	// since Landlock has no punch-through deny to carve them back out (macOS
	// filename-denies private keys regardless of cwd, which is why it was never
	// exposed there).
	//
	// Symlinks are resolved before the check: a cwd that is a symlink INTO $HOME
	// (e.g. a testbed's /home/<u>.linux -> /home/<u>.guest) must be recognised
	// as enclosing home, because the Landlock grant applies to the real target
	// directory, not the link.
	//
	// Three cases:
	//   - cwd IS $HOME → grant the *visible* (non-hidden) home children as the
	//     agent's workspace, but deny all dotfiles/dotdirs by default (that's
	//     where secrets live: ~/.ssh, ~/.aws, ~/.config/gh, ~/.netrc, ...). The
	//     specific dot-entries the agent legitimately needs (~/.claude, etc.)
	//     are re-granted by the home allowlist below. This keeps $HOME usable
	//     without a wholesale grant Landlock can't carve secrets out of.
	//   - cwd is a strict ancestor of $HOME (e.g. /home, /) → too broad to
	//     enumerate meaningfully; fall back to the home allowlist only.
	//   - otherwise (a normal project cwd) → grant cwd wholesale as before.
	resolvedCwd := resolveSymlinks(cwd)
	resolvedHome := resolveSymlinks(home)
	rwPaths := []string{"/tmp"}
	grantVisibleHomeChildren := false
	switch {
	case cwd == "":
		// cwd unknown — grant nothing extra.
	case resolvedHome != "" && resolvedCwd == resolvedHome:
		grantVisibleHomeChildren = true
		fmt.Fprintln(os.Stderr, "agentjail-shield: cwd is $HOME; granting non-hidden home "+
			"entries as the workspace — dotfiles (~/.ssh, ~/.aws, ~/.gnupg, ~/.config, ...) stay protected")
	case cwdEnclosesHome(resolvedCwd, resolvedHome):
		fmt.Fprintf(os.Stderr, "agentjail-shield: cwd %s encloses $HOME; "+
			"granting the home allowlist only so ~/.ssh, ~/.aws, ~/.gnupg stay protected\n", cwd)
	default:
		rwPaths = append(rwPaths, cwd)
	}
	for _, p := range rwPaths {
		if err := allowPath(p, rwAccess); err != nil {
			return -1, fmt.Errorf("allow %s: %w", p, err)
		}
	}

	// SSH agent socket: if SSH_AUTH_SOCK points outside /tmp (e.g.
	// /run/user/<uid>/... via systemd/gnome-keyring), grant RW on the
	// socket so ssh can connect(2) to the agent. The env var itself is
	// passed through via EnvAllowlistBaseline.
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if resolved, err := filepath.EvalSymlinks(sock); err == nil {
			if !strings.HasPrefix(resolved, "/tmp/") && !strings.HasPrefix(resolved, "/tmp") {
				if err := allowPath(resolved, rwFileAccess); err != nil {
					fmt.Fprintf(os.Stderr, "agentjail-shield: skip SSH_AUTH_SOCK %s: %v\n", resolved, err)
				}
			}
		}
	}

	// Option A: when launched from $HOME, grant each non-hidden child read-write
	// so the agent can actually work, while every dotfile/dotdir stays denied by
	// default (hidden == where credentials live). Best-effort: a child that
	// can't be granted is logged and skipped, never fatal.
	if grantVisibleHomeChildren {
		children, rerr := visibleHomeChildren(resolvedHome)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "agentjail-shield: cannot enumerate $HOME (%v); "+
				"falling back to home allowlist only\n", rerr)
		}
		for _, c := range children {
			access := rwFileAccess
			if c.isDir {
				access = rwAccess
			}
			if err := allowPath(c.path, access); err != nil {
				fmt.Fprintf(os.Stderr, "agentjail-shield: skip %s: %v\n", c.path, err)
			}
		}
	}

	// SSH agent socket: if SSH_AUTH_SOCK points outside /tmp (e.g.
	// /run/user/<uid>/... via systemd/gnome-keyring), grant RW on the
	// socket so ssh can connect(2) to the agent. The env var itself is
	// passed through via EnvAllowlistBaseline.
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if resolved, err := filepath.EvalSymlinks(sock); err == nil {
			if !strings.HasPrefix(resolved, "/tmp/") && !strings.HasPrefix(resolved, "/tmp") {
				if err := allowPath(resolved, rwFileAccess); err != nil {
					fmt.Fprintf(os.Stderr, "agentjail-shield: skip SSH_AUTH_SOCK %s: %v\n", resolved, err)
				}
			}
		}
	}

	// Allow only specific home subdirectories that Claude Code needs.
	// Default-deny: nothing in $HOME is accessible unless explicitly listed.
	// This is the allowlist model — the agent sees only what we grant.
	if home != "" {
		paths := agentPaths()
		for _, name := range paths.HomeRW {
			p := filepath.Join(home, name)
			if err := allowPath(p, rwAccess); err != nil {
				fmt.Fprintf(os.Stderr, "agentjail-shield: skip %s: %v\n", p, err)
			}
		}
		for _, name := range paths.HomeRO {
			p := filepath.Join(home, name)
			if name == ".agentjail" {
				// ~/.agentjail is read-only granted for observability EXCEPT
				// the secrets-broker master key and encrypted store (C2 fix):
				// a plain recursive grant on the whole directory would also
				// hand the agent secrets.key + secrets/<name>, letting it
				// decrypt every broker secret offline. Landlock allow rules
				// on a directory apply to its full subtree with no
				// punch-through deny, so instead of one recursive grant we
				// grant listing on the directory itself (READ_DIR only, no
				// READ_FILE/EXECUTE) and then grant full read-only access to
				// each child individually, skipping AgentjailReadDeniedNames (the
				// secrets store plus the control-plane token, ADR 0067).
				if err := allowPath(p, uint64(unix.LANDLOCK_ACCESS_FS_READ_DIR)); err != nil {
					fmt.Fprintf(os.Stderr, "agentjail-shield: skip %s: %v\n", p, err)
				}
				entries, rerr := os.ReadDir(p)
				if rerr != nil {
					continue // directory absent (fresh install) — nothing to grant
				}
				protected := AgentjailReadDeniedNames()
				for _, e := range entries {
					if protected[e.Name()] {
						continue
					}
					cp := filepath.Join(p, e.Name())
					// Directories need READ_DIR/EXECUTE too (so nested
					// content like bin/, run/ works); plain files only take
					// file-scoped access -- landlock_add_rule(EINVAL) if a
					// directory-only right is requested on a regular file.
					access := roFileAccess
					if e.IsDir() {
						access = roAccess
					}
					if err := allowPath(cp, access); err != nil {
						fmt.Fprintf(os.Stderr, "agentjail-shield: skip %s: %v\n", cp, err)
					}
				}
				continue
			}
			if name == ".config" {
				// ~/.config holds legitimate MCP server configs but also
				// credential-bearing subdirs (gh, gcloud, containers, ...).
				// Landlock path-beneath grants are purely additive -- there
				// is no way to carve a "deny" hole out of a directory once
				// its subtree is granted -- so grant each child individually
				// and skip the denylisted ones instead of granting ~/.config
				// as a whole. See ConfigCredentialSubdirs (P4).
				allowConfigDirExcludingCredentials(p, allowPath, roAccess)
				continue
			}
			if err := allowPath(p, roAccess); err != nil {
				fmt.Fprintf(os.Stderr, "agentjail-shield: skip %s: %v\n", p, err)
			}
		}
		// Individual files at $HOME root that Claude Code reads/writes.
		for _, name := range paths.HomeFilesRW {
			p := filepath.Join(home, name)
			if err := allowPath(p, rwFileAccess); err != nil {
				fmt.Fprintf(os.Stderr, "agentjail-shield: skip %s: %v\n", p, err)
			}
		}
		// Per-file read-only grants inside otherwise-denied directories.
		for _, g := range PerFileGrants() {
			if !g.PerFile || g.Mode != ReadOnly {
				continue
			}
			p := filepath.Join(home, g.Path)
			if err := allowPath(p, roFileAccess); err != nil {
				fmt.Fprintf(os.Stderr, "agentjail-shield: skip %s: %v\n", p, err)
			}
		}
	}

	// Allow read-only on standard system paths.
	roSysDirs := []string{
		"/usr", "/bin", "/lib", "/lib64", "/sbin",
		"/etc", "/proc", "/sys",
		"/opt", "/run",
	}
	for _, p := range roSysDirs {
		if err := allowPath(p, roAccess); err != nil {
			return -1, fmt.Errorf("allow %s: %w", p, err)
		}
	}
	// /dev needs write access for /dev/null, /dev/zero, /dev/urandom, ptys, etc.
	if err := allowPath("/dev", rwAccess); err != nil {
		return -1, fmt.Errorf("allow /dev: %w", err)
	}

	// Resolve common runtime binaries that MCP servers depend on. If they
	// live outside the standard system paths (e.g. ~/.bun/, ~/.nvm/, ~/.cargo/)
	// we add their real directory read-only so they can execute inside the sandbox.
	seen := make(map[string]bool)
	for _, name := range agentPaths().Runtimes {
		p, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			continue
		}
		dir := filepath.Dir(real)
		if seen[dir] {
			continue
		}
		seen[dir] = true
		if err := allowPath(dir, roAccess); err != nil {
			fmt.Fprintf(os.Stderr, "agentjail-shield: skip runtime dir %s: %v\n", dir, err)
		}
	}

	// Resolve MCP server binary paths from ~/.claude.json. MCP servers may
	// live in virtualenvs or tool-specific directories outside the standard
	// system paths. We read their command paths and allow their parent
	// directory trees so they can execute inside the sandbox.
	if home != "" {
		mcpPaths := resolveMCPServerPaths(filepath.Join(home, ".claude.json"))
		for _, mp := range mcpPaths {
			real, err := filepath.EvalSymlinks(mp)
			if err != nil {
				real = mp
			}
			dir := filepath.Dir(real)
			if seen[dir] {
				continue
			}
			// Allow the venv/tool directory tree (read-only + execute).
			topDir := findTopLevelDir(dir, home)
			// SECURITY (P3): ~/.claude.json is agent-writable. Without this
			// check, an agent could widen its own Landlock grants by
			// pointing a fake MCP server's `command` at a path inside
			// ~/.ssh, ~/.aws, or ~/.gnupg -- the code below would otherwise
			// grant read access to the resolved top-level directory on the
			// next launch. Refuse and warn instead of granting.
			grantTarget := topDir
			if grantTarget == "" {
				grantTarget = dir
			}
			if isSensitiveMCPTarget(grantTarget, home) {
				fmt.Fprintf(os.Stderr, "agentjail-shield: WARNING: refusing to grant MCP command path %q: resolves inside sensitive directory %s (check ~/.claude.json for a poisoned mcpServers command)\n", mp, grantTarget)
				continue
			}
			seen[dir] = true
			if topDir != "" && !seen[topDir] {
				seen[topDir] = true
				if err := allowPath(topDir, roAccess); err != nil {
					fmt.Fprintf(os.Stderr, "agentjail-shield: skip MCP dir %s: %v\n", topDir, err)
				}
			} else if !seen[dir] {
				if err := allowPath(dir, roAccess); err != nil {
					fmt.Fprintf(os.Stderr, "agentjail-shield: skip MCP dir %s: %v\n", dir, err)
				}
			}
		}
	}

	// Allow extra paths from policy.yaml (if any are configured as extra_allow).
	if cfg != nil {
		for _, p := range cfg.File.ExtraAllow {
			if err := allowPath(p, rwAccess); err != nil {
				return -1, fmt.Errorf("allow extra %s: %w", p, err)
			}
		}
	}

	// Network rules: apply netPlan (built above, before ruleset creation) --
	// CONNECT ports first, then BIND ports (only present when
	// netPlan.HandleBindTCP; see buildLandlockNetPlan). Landlock is
	// irreversible, so a bind port not in netPlan.BindPorts (e.g. a
	// brand-new MCP's first, not-yet-in-credentials OAuth callback) requires
	// out-of-jail initial auth via `claude mcp login`.
	if netPlan.Handled {
		for _, port := range netPlan.ConnectPorts {
			netAttr := landlockNetPortAttr{
				AllowedAccess: uint64(unix.LANDLOCK_ACCESS_NET_CONNECT_TCP),
				Port:          uint64(port),
			}
			if _, _, e := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE,
				uintptr(rulesetFd), uintptr(landlockRuleNetPort),
				uintptr(unsafe.Pointer(&netAttr)), 0, 0, 0); e != 0 {
				return -1, fmt.Errorf("landlock_add_rule(net connect port %d): %w", port, e)
			}
		}
		for _, port := range netPlan.BindPorts {
			bindAttr := landlockNetPortAttr{
				AllowedAccess: uint64(unix.LANDLOCK_ACCESS_NET_BIND_TCP),
				Port:          uint64(port),
			}
			if _, _, e := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE,
				uintptr(rulesetFd), uintptr(landlockRuleNetPort),
				uintptr(unsafe.Pointer(&bindAttr)), 0, 0, 0); e != 0 {
				fmt.Fprintf(os.Stderr, "agentjail-shield: skip OAuth bind port %d: %v\n", port, e)
			}
		}
	}

	// The ruleset is fully populated but NOT yet applied. restrict_self is the
	// caller's responsibility (restrictSelfWithRuleset): the non-tunnel path
	// applies it here in the shield; the tunnel path applies it in the harden
	// shim after nsenter. Both set PR_SET_NO_NEW_PRIVS immediately before.
	return rulesetFd, nil
}

func step(noColor bool, msg string) {
	if noColor {
		fmt.Fprintf(os.Stderr, "  ✓ %s\n", msg)
	} else {
		fmt.Fprintf(os.Stderr, "  \033[32m✓\033[0m %s\n", msg)
	}
}

func stepFail(noColor bool, msg string) {
	if noColor {
		fmt.Fprintf(os.Stderr, "  ✗ %s\n", msg)
	} else {
		fmt.Fprintf(os.Stderr, "  \033[31m✗\033[0m %s\n", msg)
	}
}

// resolveMCPServerPaths and resolveOAuthCallbackPorts moved to
// shield_contract.go (tag-free) so both backends share the same resolution
// logic. See ADR 0034 / ADR 0039.

// findTopLevelDir walks up from dir to find the first directory under parent.
// For dir="/home/user/.headroom-venv/bin" and parent="/home/user", returns
// "/home/user/.headroom-venv".
func findTopLevelDir(dir, parent string) string {
	parent = filepath.Clean(parent)
	dir = filepath.Clean(dir)
	if !strings.HasPrefix(dir, parent+"/") {
		return ""
	}
	rel := strings.TrimPrefix(dir, parent+"/")
	parts := strings.SplitN(rel, "/", 2)
	return filepath.Join(parent, parts[0])
}

// isSensitiveMCPTarget reports whether target (a directory an MCP server's
// resolved `command` would be granted Landlock read access to) falls inside
// one of the sensitive home directories in SensitiveMCPCommandDirs (P3:
// ~/.ssh, ~/.aws, ~/.gnupg). target may be the sensitive directory itself
// (e.g. a command living directly at ~/.ssh/foo) or any of its descendants.
func isSensitiveMCPTarget(target, home string) bool {
	if target == "" || home == "" {
		return false
	}
	home = filepath.Clean(home)
	target = filepath.Clean(target)
	if target != home && !strings.HasPrefix(target, home+"/") {
		return false
	}
	rel := strings.TrimPrefix(target, home+"/")
	if rel == target {
		// target == home itself; not a sensitive subdir.
		return false
	}
	top := strings.SplitN(rel, "/", 2)[0]
	for _, sensitive := range SensitiveMCPCommandDirs() {
		if top == sensitive {
			return true
		}
	}
	return false
}

// allowConfigDirExcludingCredentials grants read-only Landlock access to
// each immediate child of configDir (~/.config) individually, skipping the
// credential-bearing subdirectories named in ConfigCredentialSubdirs (P4:
// gh, gcloud, containers, git). Landlock path-beneath grants are purely
// additive, so this is the only way to keep e.g. ~/.config/gh unreadable
// while an MCP server's own ~/.config/<tool> directory stays readable.
//
// If configDir does not exist, this is a silent no-op (same semantics as
// allowPath skipping an absent path).
func allowConfigDirExcludingCredentials(configDir string, allowPath func(string, uint64) error, roAccess uint64) {
	denied := make(map[string]bool, len(ConfigCredentialSubdirs()))
	for _, d := range ConfigCredentialSubdirs() {
		denied[d] = true
	}
	entries, err := os.ReadDir(configDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if denied[e.Name()] {
			fmt.Fprintf(os.Stderr, "agentjail-shield: denying read access to %s (credential store)\n", filepath.Join(configDir, e.Name()))
			continue
		}
		p := filepath.Join(configDir, e.Name())
		if err := allowPath(p, roAccess); err != nil {
			fmt.Fprintf(os.Stderr, "agentjail-shield: skip %s: %v\n", p, err)
		}
	}
}
