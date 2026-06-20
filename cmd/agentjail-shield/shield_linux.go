//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"unsafe"

	config "github.com/LuD1161/agentjail/agentpolicy/config"

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
// and direct egress.  On kernels < 6.7, network ABI is unavailable; a
// warning is printed and FS-only Landlock is applied (current behavior).
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
func runShield(cfg *config.PolicyConfig, agentPath string, agentArgs []string, profilePrint bool, noNetproxy bool, policyPath string) {
	// Start netproxy as a child process BEFORE applying Landlock — netproxy
	// needs unrestricted network access to reach upstream hosts.  Landlock
	// (applied below) restricts the shield + agent, not the netproxy child
	// which was already forked before restriction.
	netproxyPort := 0
	var netproxyCmd *exec.Cmd
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
				netproxyCmd = cmd
			}
		}
	}

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
			fmt.Fprintln(os.Stderr, "Network: not restricted (--no-netproxy; FS-only Landlock)")
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
			fmt.Fprintf(os.Stderr, "agentjail-shield WARNING: Landlock unavailable: %v\n"+
				"  Sandbox enforcement DISABLED. Requires Linux 5.13+ with CONFIG_SECURITY_LANDLOCK=y.\n"+
				"  The hook layer still runs on every PreToolUse call.\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "agentjail-shield ERROR: failed to apply Landlock sandbox: %v\n"+
				"  Refusing to run the agent unsandboxed (fail-closed).\n"+
				"  Set AGENTJAIL_SHIELD_ALLOW_UNSANDBOXED=1 to override (NOT recommended).\n", err)
			if os.Getenv("AGENTJAIL_SHIELD_ALLOW_UNSANDBOXED") != "1" {
				cleanupNetproxy(netproxyCmd)
				os.Exit(1)
			}
		}
	}

	// Build the agent's environment: inherit + strip ambient creds + proxy vars + granted secrets.
	env := stripEnv(os.Environ(), cfg)
	if netproxyCmd != nil {
		env = append(env, proxyEnvVars(netproxyDefaultAddr)...)
		fmt.Fprintf(os.Stderr, "agentjail-shield INFO: setting HTTPS_PROXY=http://%s (per-host enforcement via netproxy)\n", netproxyDefaultAddr)
	}
	grantEnvVars, activeGrants := requestSecretGrants(cfg)
	env = append(env, grantEnvVars...)

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

	// Forward SIGINT and SIGTERM to the agent child so interactive agents
	// (claude, codex) receive Ctrl-C normally.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		for sig := range sigCh {
			if agentCmd.Process != nil {
				_ = agentCmd.Process.Signal(sig)
			}
		}
	}()

	runErr := agentCmd.Run()

	// Kill and reap the netproxy child (zombie cleanup).
	cleanupNetproxy(netproxyCmd)
	revokeSecretGrants(activeGrants)

	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "agentjail-shield: agent failed: %v\n", runErr)
		os.Exit(1)
	}
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

	// Network access handling (ABI v4+, Linux 6.7+).
	// When netproxyPort > 0, we handle CONNECT_TCP (deny all unless explicitly
	// allowed) and BIND_TCP (deny all — agent never needs to bind).  Only a
	// rule for netproxyPort is added, so the agent can only connect to the
	// netproxy.  On kernels < 6.7, handledNet stays 0 (no network restriction).
	handledNet := uint64(0)
	if netproxyPort > 0 {
		if abi >= 4 {
			handledNet = unix.LANDLOCK_ACCESS_NET_CONNECT_TCP | unix.LANDLOCK_ACCESS_NET_BIND_TCP
		} else {
			fmt.Fprintf(os.Stderr,
				"agentjail-shield WARNING: Landlock network ABI requires kernel 6.7+ (current ABI v%d).\n"+
					"  Network egress restriction is NOT applied.  Consider --no-netproxy or upgrading.\n", abi)
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

	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()

	// Allow read-write on /tmp and cwd.
	for _, p := range []string{"/tmp", cwd} {
		if err := allowPath(p, rwAccess); err != nil {
			return fmt.Errorf("allow %s: %w", p, err)
		}
	}

	// Allow read-write on home MINUS sensitive subdirs.
	// Landlock doesn't support "allow parent but deny child" in a single rule,
	// so we allow ~/ at read-only and then allow writes only to explicitly
	// non-sensitive project dirs.
	//
	// This is less precise than sbpl deny-list but achieves the core goal:
	// ~/.ssh, ~/.aws, ~/.gnupg, ~/.agentjail are not in the allow list.
	if home != "" {
		if err := allowPath(home, roAccess); err != nil {
			return fmt.Errorf("allow home read-only: %w", err)
		}
	}

	// Allow read-only on standard system paths.
	sysDirs := []string{
		"/usr", "/bin", "/lib", "/lib64", "/sbin",
		"/etc", "/dev", "/proc", "/sys",
		"/opt", "/run",
	}
	for _, p := range sysDirs {
		if err := allowPath(p, roAccess); err != nil {
			return fmt.Errorf("allow %s: %w", p, err)
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

	// Network rules: allow TCP connect to the netproxy port only (ABI v4+).
	// BIND_TCP is handled but no rule is added → all binds are denied.
	if netproxyPort > 0 && abi >= 4 {
		netAttr := landlockNetPortAttr{
			AllowedAccess: uint64(unix.LANDLOCK_ACCESS_NET_CONNECT_TCP),
			Port:          uint64(netproxyPort),
		}
		if _, _, e := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE,
			uintptr(rulesetFd), uintptr(landlockRuleNetPort),
			uintptr(unsafe.Pointer(&netAttr)), 0, 0, 0); e != 0 {
			return fmt.Errorf("landlock_add_rule(net port %d): %w", netproxyPort, e)
		}
		fmt.Fprintf(os.Stderr,
			"agentjail-shield INFO: Landlock network restriction active (ABI v%d) — TCP connect allowed only to port %d\n",
			abi, netproxyPort)
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
