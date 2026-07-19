//go:build linux

// This file implements the unprivileged-userns TUN handoff (ADR 0079,
// AGE-148). It replaces the deprecated host-veth + privileged-daemon path
// (veth_linux.go / internal/daemon/namespace*.go): no host CAP_NET_ADMIN, no
// privileged socket, no install password.
//
// # Mechanism
//
// The privileged network operation — creating and configuring a TUN device —
// must run in a netns where the caller holds CAP_NET_ADMIN. An ordinary user
// does not hold it in the host netns, but DOES hold a full capability set
// (scoped to the namespaces it owns) inside a user namespace it created via
// unshare(CLONE_NEWUSER). So the holder process, which is the very process that
// created the userns+netns, opens and configures the TUN natively — no setns
// from the parent (which is unreliable without CAP_SYS_ADMIN; see the
// doInNetNS fallback in netns_linux.go).
//
// CreateWithTUN forks the shield binary re-exec'd as a namespace holder
// (reexecTUNArg). The holder, running as uid 0 inside the new user+net+mount
// namespaces, opens /dev/net/tun, assigns the netns address + a default route
// pointing at the TUN, then hands the open TUN fd back to the parent over an
// inherited Unix socket via SCM_RIGHTS (SendFD/RecvFD). The parent (the gateway
// process, in the host netns) read()/write()s raw IP packets on that fd and
// feeds them into the userspace forwarder. The holder then blocks to keep the
// namespaces alive for the session; Pdeathsig ties its lifetime to the shield.
//
// AgentCommand builds the command that runs the agent *inside* that netns,
// hardened: nsenter joins the holder's namespaces, then a re-exec shim
// (reexecHardenArg) applies ApplyHardening (cap-drop + secbits) before execve of
// the agent, so the uid-0-in-userns agent cannot regain privileges.
package netns

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/LuD1161/agentjail/internal/dnsvip"
)

const (
	// reexecTUNArg marks a re-exec of this binary as the namespace holder that
	// opens the TUN inside the new user+net namespace and hands its fd back.
	reexecTUNArg = "__agentjail_netns_tun_helper"

	// reexecHardenArg marks a re-exec that hardens the process (ApplyHardening)
	// then execve's the agent. Used by AgentCommand via nsenter.
	reexecHardenArg = "__agentjail_harden_exec"

	// shieldRoleName is the argv[0] basename the multicall binary dispatches on
	// to reach the shield role (see cmd/agentjail main.go). A re-exec MUST
	// present this name; os.Executable() resolves the installed agentjail-shield
	// SYMLINK to `agentjail`, which routes to the CLI so the TUN helper/harden
	// shim never runs and the tunnel silently falls back to netproxy.
	// See ADR 0103-shield-reexec-argv0.
	shieldRoleName = "agentjail-shield"

	// hardenLandlockFDFlag precedes the fd number of an inherited Landlock
	// ruleset in the harden shim's args. When present, the shim applies that
	// ruleset (landlock_restrict_self) AFTER nsenter has joined the namespaces
	// (AGE-166) — the shield cannot restrict itself before nsenter because
	// nsenter must open the holder's nsfs ns files, which Landlock cannot cover.
	hardenLandlockFDFlag = "--landlock-fd"

	// hardenWorkdirFlag precedes the directory the shim chdirs into, inside the
	// namespaces. Without it the agent inherits the holder's cwd. See AGE-231.
	hardenWorkdirFlag = "--workdir"

	// tunHandoffFD is the fd number the inherited handoff socket lands on in the
	// re-exec'd holder (ExtraFiles[0] => fd 3).
	tunHandoffFD = 3

	// landlockHandoffFD is the fd number an inherited Landlock ruleset lands on
	// in the harden shim. exec.Cmd.ExtraFiles[0] is deterministically dup'd to
	// fd 3 in the immediate child (nsenter), and survives (CLOEXEC cleared) the
	// execve into the shim, so the shim reads the ruleset from fd 3.
	landlockHandoffFD = 3

	// TUNIfName is the TUN interface name created inside the agent's netns.
	TUNIfName = "ajtun0"

	// TUNMTU is the MTU set on the netns TUN. It matches tunnel.Config's default
	// MTU (1420) so the userspace forwarder and the device agree and neither
	// side has to fragment.
	TUNMTU = 1420
)

// TUNAddrCIDR is the address assigned to the TUN inside the agent's netns.
// The gateway answers any destination the agent dials, so the peer address is
// unused; the /16 just gives the agent a routable source address.
//
// Derived from dnsvip, which owns the address plan and reserves this address
// from the VIP pool — hardcoding it here once let the pool hand the same
// address to a hostname. ADR 0034-platform-backend-shared-contract.
var TUNAddrCIDR = dnsvip.AgentV4().String() + "/16"

// MaybeRunReexec MUST be the first statement in main(), before flag parsing.
// If this process was re-exec'd as a namespace holder or a hardened-exec shim,
// it runs that role and never returns (it either os.Exit()s or execve()s). In
// the normal (non-re-exec) case it returns immediately and main() proceeds.
func MaybeRunReexec() {
	if len(os.Args) < 2 {
		return
	}
	switch os.Args[1] {
	case reexecTUNArg:
		runTUNHelper(os.Args[2:]) // never returns
	case reexecHardenArg:
		runHardenExec(os.Args[2:]) // never returns
	}
}

// runTUNHelper is the namespace-holder entrypoint. It runs inside the freshly
// created user+net+mount namespaces (as uid 0 in the userns), so it can open
// and configure a TUN. Args: [ifName, addrCIDR]. On any failure it exits
// non-zero; the parent's RecvFD then fails and the shield falls back to
// netproxy (fail-open). On success it hands the TUN fd to the parent and blocks
// forever to keep the namespaces alive.
func runTUNHelper(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "netns tun-helper: missing ifName/addrCIDR args")
		os.Exit(2)
	}
	ifName, addrCIDR := args[0], args[1]

	// The handoff socket was passed as ExtraFiles[0] => fd tunHandoffFD.
	sockFile := os.NewFile(uintptr(tunHandoffFD), "tun-handoff")
	if sockFile == nil {
		fmt.Fprintln(os.Stderr, "netns tun-helper: no handoff socket on fd 3")
		os.Exit(2)
	}
	conn, err := net.FileConn(sockFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "netns tun-helper: handoff socket: %v\n", err)
		os.Exit(2)
	}
	_ = sockFile.Close() // net.FileConn dup'd it
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		fmt.Fprintln(os.Stderr, "netns tun-helper: handoff socket is not unix")
		os.Exit(2)
	}

	// Open the TUN. This binds the interface to THIS netns (the opener's netns).
	tunFile, resolvedName, err := OpenTUN(ifName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "netns tun-helper: open tun: %v\n", err)
		os.Exit(1)
	}

	// Configure the netns: loopback up, address + default route via the TUN.
	// We hold CAP_NET_ADMIN in this userns-owned netns, so netlink succeeds
	// without host privilege.
	if err := configureTUNInterface(resolvedName, addrCIDR); err != nil {
		fmt.Fprintf(os.Stderr, "netns tun-helper: configure %s: %v\n", resolvedName, err)
		os.Exit(1)
	}

	// Hand the fd to the parent. This doubles as the success signal: if any
	// step above failed we exited before this, so the parent's RecvFD returns
	// an error and the shield falls back to netproxy.
	if err := SendFD(uc, int(tunFile.Fd())); err != nil {
		fmt.Fprintf(os.Stderr, "netns tun-helper: send tun fd: %v\n", err)
		os.Exit(1)
	}

	// Keep the TUN fd open and block until the shield (holding the other end of
	// the handoff socket) closes it. A normal Namespace.Close() and an abnormal
	// shield crash both close that end, so the holder always exits and the kernel
	// tears the namespaces down. This replaces Pdeathsig, whose thread-lifetime
	// semantics are unreliable under Go's runtime — the holder was SIGKILLed
	// mid-session on a slower guest, breaking the follow-on nsenter.
	// See ADR 0103-shield-reexec-argv0.
	var b [1]byte
	_, _ = uc.Read(b[:]) // unblocks on EOF (parent gone) or a stray byte
	os.Exit(0)
}

// configureTUNInterface brings up loopback and the TUN device, assigns the
// netns address, and installs a default route out the TUN so all agent traffic
// is delivered to the userspace forwarder.
func configureTUNInterface(tunName, addrCIDR string) error {
	if lo, err := netlink.LinkByName("lo"); err == nil {
		_ = netlink.LinkSetUp(lo)
	}

	link, err := netlink.LinkByName(tunName)
	if err != nil {
		return fmt.Errorf("lookup %s: %w", tunName, err)
	}

	addr, err := netlink.ParseAddr(addrCIDR)
	if err != nil {
		return fmt.Errorf("parse addr %q: %w", addrCIDR, err)
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("add addr %s: %w", addrCIDR, err)
	}
	if err := netlink.LinkSetMTU(link, TUNMTU); err != nil {
		return fmt.Errorf("set %s mtu %d: %w", tunName, TUNMTU, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("set %s up: %w", tunName, err)
	}

	// Default route out the TUN (point-to-point L3 device, no gateway). The
	// destination must be an explicit 0.0.0.0/0 prefix with link scope: a nil
	// Dst is rejected by vishvananda/netlink's RouteAdd validation ("either
	// Dst.IP, Src.IP or Gw must be set"), and with no gateway the route is
	// on-link (SCOPE_LINK) out the interface.
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Scope:     netlink.SCOPE_LINK,
	}); err != nil {
		return fmt.Errorf("add default route via %s: %w", tunName, err)
	}
	return nil
}

// CreateWithTUN creates unprivileged user+net+mount namespaces whose only
// network path is a TUN device, and returns the namespace plus the open TUN fd
// (owned by the caller). The caller pumps IP packets between the fd and the
// userspace forwarder (see internal/tunnel), and runs the agent inside the
// namespace via AgentCommand.
//
// It returns ErrUnsupported (wrapped) if unprivileged user namespaces are
// disabled, so callers can fall back to netproxy.
func CreateWithTUN(ifName, addrCIDR string) (ns *Namespace, tun *os.File, err error) {
	uid, gid := os.Getuid(), os.Getgid()

	// Handoff socket: a connected AF_UNIX pair. fds[0] stays with the parent,
	// fds[1] is inherited by the holder as ExtraFiles[0] (=> fd 3).
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("netns: socketpair: %w", err)
	}
	parentSock := os.NewFile(uintptr(fds[0]), "tun-handoff-parent")
	childSock := os.NewFile(uintptr(fds[1]), "tun-handoff-child")
	// childSock is closed explicitly right after cmd.Start() below (once the
	// child has inherited it), NOT deferred to function return: the parent must
	// drop its own reference to the child's socket end so that if the holder
	// exits before SendFD (e.g. TUN open/configure failure), RecvFD sees EOF and
	// returns an error instead of blocking forever on a half-open socketpair.
	// closeChild guards against a double close on the early-return error paths.
	childClosed := false
	closeChild := func() {
		if !childClosed {
			_ = childSock.Close()
			childClosed = true
		}
	}
	defer closeChild()

	parentConn, err := net.FileConn(parentSock)
	_ = parentSock.Close() // FileConn dup'd it
	if err != nil {
		return nil, nil, fmt.Errorf("netns: handoff parent conn: %w", err)
	}
	// parentConn stays open for the namespace lifetime: closing it (in
	// Namespace.Close, or implicitly when the shield process dies) is what makes
	// the holder's blocking Read return EOF so it exits. Error paths below close
	// it explicitly; on success the Namespace owns it.
	parentUC, ok := parentConn.(*net.UnixConn)
	if !ok {
		_ = parentConn.Close()
		return nil, nil, fmt.Errorf("netns: handoff conn is not unix")
	}

	exe, err := os.Executable()
	if err != nil {
		exe = "/proc/self/exe"
	}
	cmd := exec.Command(exe, reexecTUNArg, ifName, addrCIDR)
	// Path (exe) execs the real file; argv[0] drives multicall dispatch. Force
	// the shield role so the holder reaches runTUNHelper. See shieldRoleName.
	cmd.Args[0] = shieldRoleName
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{childSock} // => fd 3 in the holder
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: uid, Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: gid, Size: 1},
		},
		GidMappingsEnableSetgroups: false,
		// No Pdeathsig: it fires when the cloning THREAD exits, not the process,
		// so Go retiring that thread SIGKILLed the holder mid-session (breaking
		// the follow-on nsenter on a slower guest). Liveness is the handoff
		// socket instead. See ADR 0103-shield-reexec-argv0.
	}

	if err := cmd.Start(); err != nil {
		_ = parentConn.Close()
		if isClonePermError(err) {
			return nil, nil, fmt.Errorf(
				"%w: unprivileged user namespaces disabled "+
					"(kernel.unprivileged_userns_clone=0 / AppArmor restriction?): %v",
				ErrUnsupported, err,
			)
		}
		return nil, nil, fmt.Errorf("netns: start tun holder: %w", err)
	}

	// The holder has inherited childSock; drop the parent's copy now so RecvFD
	// below unblocks with EOF if the holder dies before SendFD.
	closeChild()

	// Receive the configured TUN fd. If the holder failed to open/configure the
	// TUN it exits before SendFD, so RecvFD returns an error here.
	tunFD, err := RecvFD(parentUC)
	if err != nil {
		_ = parentConn.Close()
		_ = cmd.Process.Kill()
		go func() { _ = cmd.Wait() }()
		return nil, nil, fmt.Errorf("netns: receive tun fd from holder: %w", err)
	}
	tun = os.NewFile(uintptr(tunFD), "/dev/net/tun:"+ifName)

	ns = &Namespace{pid: cmd.Process.Pid, holderConn: parentConn}
	go func() { _ = cmd.Wait() }() // reap after Close() closes the socket / SIGKILLs

	return ns, tun, nil
}

// AgentCommand builds the *exec.Cmd that runs the agent inside this namespace,
// hardened. The caller sets Stdin/Stdout/Stderr and Env and calls Run(); the
// process stays a child of the shield (for signal handling and reaping), just
// like the non-tunnel path.
//
// It execs, via nsenter joining the holder's user+net+mount namespaces, a
// re-exec shim (reexecHardenArg) that applies ApplyHardening (PR_SET_NO_NEW_PRIVS,
// cap-drop, SECBIT_NOROOT, non-dumpable) and then execve's the agent.
//
// landlockFD, when >= 0, is an OPEN Landlock ruleset fd built by the shield.
// Because nsenter must open the holder's nsfs ns files — which Landlock cannot
// cover — the shield cannot restrict itself before nsenter (AGE-166). Instead
// the ruleset fd is inherited by the shim (via ExtraFiles => fd landlockHandoffFD)
// and the shim calls landlock_restrict_self AFTER nsenter, so the agent is
// FS-sandboxed without breaking namespace entry. Pass -1 to skip Landlock (e.g.
// unsupported kernel / fail-open).
// shieldReexecPath returns a path to this binary whose basename is
// shieldRoleName, so a re-exec that cannot set argv[0] independently (nsenter
// execs its target with argv[0]=path) still dispatches back to the shield role.
// It prefers the invocation path (which keeps the installed agentjail-shield
// symlink); os.Executable() resolves that symlink to `agentjail` and would
// misdispatch. The resolved exe is the correct fallback for the standalone
// agentjail-shield dev binary, whose basename already names the role.
func shieldReexecPath() string {
	if a0 := os.Args[0]; filepath.Base(a0) == shieldRoleName {
		if filepath.IsAbs(a0) {
			return a0
		}
		if p, err := exec.LookPath(a0); err == nil {
			return p
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return "/proc/self/exe"
	}
	return exe
}

func (ns *Namespace) AgentCommand(agentPath string, agentArgs []string, landlockFD int) *exec.Cmd {
	// nsenter execs `exe` with argv[0]=exe, so exe's basename must name the
	// shield role for multicall dispatch to reach runHardenExec.
	exe := shieldReexecPath()
	args := []string{
		"--target", strconv.Itoa(ns.pid),
		"--user", "--preserve-credentials",
		"--net", "--mount",
	}

	args = append(args,
		"--",
		exe, reexecHardenArg,
	)

	// Without this the agent lands in the holder's cwd ("/"). Our shim chdirs
	// rather than nsenter --wd (unresolvable cwd, getcwd EACCES) or --wdns
	// (util-linux >= 2.38 only). See AGE-231.
	if wd, werr := os.Getwd(); werr == nil && wd != "" {
		args = append(args, hardenWorkdirFlag, wd)
	}
	if landlockFD >= 0 {
		args = append(args, hardenLandlockFDFlag, strconv.Itoa(landlockHandoffFD))
	}
	args = append(args, "--", agentPath)
	args = append(args, agentArgs...)
	cmd := exec.Command("nsenter", args...)
	if landlockFD >= 0 {
		// Dup'd to fd landlockHandoffFD in nsenter (CLOEXEC cleared), inherited
		// by the shim across nsenter's execve.
		cmd.ExtraFiles = []*os.File{os.NewFile(uintptr(landlockFD), "landlock-ruleset")}
	}
	return cmd
}

// runHardenExec is the hardened-exec shim entrypoint. It runs after nsenter has
// joined the agent's namespaces. Args (after reexecHardenArg):
// [[--landlock-fd N] "--" agentPath agentArgs...]. It hardens the current
// process, applies the inherited Landlock ruleset (if any) now that nsenter is
// done, then execve's the agent.
func runHardenExec(args []string) {
	// Order-independent: this and AgentCommand are edited apart, and a
	// positional parser turns a reordered append into an exec of the flag.
	landlockFD := -1
	workdir := ""
	for len(args) >= 2 {
		switch args[0] {
		case hardenLandlockFDFlag:
			fd, err := strconv.Atoi(args[1])
			if err != nil {
				fmt.Fprintf(os.Stderr, "netns harden-exec: bad %s value %q: %v\n", hardenLandlockFDFlag, args[1], err)
				os.Exit(2)
			}
			landlockFD = fd
			args = args[2:]
		case hardenWorkdirFlag:
			workdir = args[1]
			args = args[2:]
		default:
			goto flagsDone
		}
	}
flagsDone:

	// Strip the leading "--" separator that AgentCommand inserts.
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}

	// After nsenter, before Landlock. See AGE-231.
	if workdir != "" {
		if err := os.Chdir(workdir); err != nil {
			// Non-fatal: degrade to the holder's "/", but say so.
			fmt.Fprintf(os.Stderr, "netns harden-exec: could not enter working directory %s: %v\n"+
				"  the agent will start in / instead\n", workdir, err)
		}
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "netns harden-exec: no agent command given")
		os.Exit(2)
	}

	if err := ApplyHardening(); err != nil {
		fmt.Fprintf(os.Stderr, "netns harden-exec: hardening failed: %v\n", err)
		os.Exit(1)
	}

	// Apply the Landlock ruleset the shield built, now that we are inside the
	// namespaces (so nsenter's nsfs ns-file open is not blocked; AGE-166).
	// ApplyHardening already set PR_SET_NO_NEW_PRIVS (a restrict_self
	// precondition). This is irreversible; the agent inherits it across execve.
	if landlockFD >= 0 {
		if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(landlockFD), 0, 0); errno != 0 {
			fmt.Fprintf(os.Stderr, "netns harden-exec: landlock_restrict_self(fd %d): %v\n", landlockFD, errno)
			os.Exit(1)
		}
		_ = unix.Close(landlockFD)
	}

	if err := syscall.Exec(args[0], args, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "netns harden-exec: exec %s: %v\n", args[0], err)
		os.Exit(127)
	}
}
