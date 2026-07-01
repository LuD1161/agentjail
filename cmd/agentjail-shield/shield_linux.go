//go:build linux

package main

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
func runShield(cfg *config.PolicyConfig, agentPath string, agentArgs []string, profilePrint bool, noNetproxy bool, policyPath string, startTime time.Time, emitter audit.Emitter) {
	ctx := context.Background()
	noColor := os.Getenv("NO_COLOR") != ""
	if noColor {
		fmt.Fprintln(os.Stderr, "  agentjail — setting up sandbox...")
	} else {
		fmt.Fprintln(os.Stderr, "  \033[38;5;208magentjail\033[0m — setting up sandbox...")
	}

	// Start netproxy as a child process BEFORE applying Landlock — netproxy
	// needs unrestricted network access to reach upstream hosts.  Landlock
	// (applied below) restricts the shield + agent, not the netproxy child
	// which was already forked before restriction.
	netproxyPort := 0
	var netproxyCmd *exec.Cmd // non-nil only if WE started the proxy (we must clean it up)
	netproxyReady := false    // true if a proxy is available (ours or pre-existing)
	if !noNetproxy {
		netproxyPort = netproxyDefaultPort
		netproxyBin, findErr := findNetproxyBinary()
		if findErr != nil {
			fmt.Fprintf(os.Stderr,
				"agentjail-shield WARNING: %v\n"+
					"  Falling back to no per-host network enforcement.\n"+
					"  Use --no-netproxy to suppress this warning.\n",
				findErr,
			)
		} else {
			cmd, startErr := startNetproxy(netproxyBin, netproxyDefaultAddr, policyPath)
			if startErr != nil {
				fmt.Fprintf(os.Stderr,
					"agentjail-shield WARNING: could not start netproxy: %v\n"+
						"  Falling back to no per-host network enforcement.\n",
					startErr,
				)
			} else {
				netproxyCmd = cmd // nil when reusing existing singleton
				netproxyReady = true
			}
		}
	}

	// netproxy started (or reused singleton)

	if profilePrint {
		fmt.Fprintln(os.Stderr, "=== agentjail-shield: Linux Landlock rule summary ===")
		fmt.Fprintln(os.Stderr, "Allow (read-write):")
		fmt.Fprintln(os.Stderr, "  /tmp")
		fmt.Fprintln(os.Stderr, "  <cwd> (agent working directory, if determinable)")
		fmt.Fprintln(os.Stderr, "Allow (read-only):")
		fmt.Fprintln(os.Stderr, "  /usr, /bin, /lib, /lib64, /etc, /dev, /proc, /sys")
		fmt.Fprintln(os.Stderr, "  $HOME (excluding .ssh, .aws, .gnupg, .agentjail, .config)")
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
			fmt.Fprintf(os.Stderr, "Network (--no-netproxy, ABI v4+, kernel 6.7+):\n")
			fmt.Fprintf(os.Stderr, "  Allow TCP connect to ports %v only (no per-host enforcement)\n", NoNetproxyFallbackPorts())
			fmt.Fprintln(os.Stderr, "  Deny all other TCP connect; TCP bind left unhandled by Landlock")
			fmt.Fprintln(os.Stderr, "  On kernel < 6.7: network ABI unavailable, FS-only Landlock applied")
		}
		fmt.Fprintln(os.Stderr, "=======================================================")
		cleanupNetproxy(netproxyCmd)
		os.Exit(0)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Apply Landlock to the current process.  The agent (run as a child
	// below) inherits all Landlock restrictions.
	if err := applyLandlock(cfg, netproxyPort); err != nil {
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
	if netproxyReady {
		env = append(env, proxyEnvVars(netproxyDefaultAddr)...)
	}
	env = append(env, "AGENTJAIL_SHIELDED=1")
	grantEnvVars, activeGrants := requestSecretGrants(cfg)
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
	agentCmd := exec.Command(agentPath, agentArgs...)
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
	revokeSecretGrants(activeGrants)

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
func applyLandlock(cfg *config.PolicyConfig, netproxyPort int) error {
	// Probe supported Landlock ABI version (ruleset_attr=NULL, size=0, flags=VERSION).
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		if errno == unix.ENOSYS || errno == unix.EOPNOTSUPP {
			return errLandlockUnsupported
		}
		return fmt.Errorf("landlock_create_ruleset(probe): %w", errno)
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
		return fmt.Errorf("landlock_create_ruleset: %w", errno)
	}
	rulesetFd := int(fd)
	defer unix.Close(rulesetFd)

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
	_ = uint64(unix.LANDLOCK_ACCESS_FS_READ_FILE) // roFileAccess reserved for future use

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

	// Allow read-write on /tmp and cwd.
	for _, p := range []string{"/tmp", cwd} {
		if err := allowPath(p, rwAccess); err != nil {
			return fmt.Errorf("allow %s: %w", p, err)
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
	}

	// Allow read-only on standard system paths.
	roSysDirs := []string{
		"/usr", "/bin", "/lib", "/lib64", "/sbin",
		"/etc", "/proc", "/sys",
		"/opt", "/run",
	}
	for _, p := range roSysDirs {
		if err := allowPath(p, roAccess); err != nil {
			return fmt.Errorf("allow %s: %w", p, err)
		}
	}
	// /dev needs write access for /dev/null, /dev/zero, /dev/urandom, ptys, etc.
	if err := allowPath("/dev", rwAccess); err != nil {
		return fmt.Errorf("allow /dev: %w", err)
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
			seen[dir] = true
			// Allow the venv/tool directory tree (read-only + execute).
			topDir := findTopLevelDir(dir, home)
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
				return fmt.Errorf("allow extra %s: %w", p, err)
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
				return fmt.Errorf("landlock_add_rule(net connect port %d): %w", port, e)
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

	// PR_SET_NO_NEW_PRIVS: required before landlock_restrict_self.
	// Prevents the sandboxed process from gaining privileges via setuid/setgid.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", err)
	}

	// Apply the ruleset.  From this point forward, the process and all
	// its descendants are restricted.  This call is irreversible.
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(rulesetFd), 0, 0); errno != 0 {
		return fmt.Errorf("landlock_restrict_self: %w", errno)
	}

	return nil
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
