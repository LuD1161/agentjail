//go:build linux

// This file implements the unprivileged-userns TUN handoff (ADR 0075,
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
	"strconv"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// reexecTUNArg marks a re-exec of this binary as the namespace holder that
	// opens the TUN inside the new user+net namespace and hands its fd back.
	reexecTUNArg = "__agentjail_netns_tun_helper"

	// reexecHardenArg marks a re-exec that hardens the process (ApplyHardening)
	// then execve's the agent. Used by AgentCommand via nsenter.
	reexecHardenArg = "__agentjail_harden_exec"

	// hardenLandlockFDFlag precedes the fd number of an inherited Landlock
	// ruleset in the harden shim's args. When present, the shim applies that
	// ruleset (landlock_restrict_self) AFTER nsenter has joined the namespaces
	// (AGE-166) — the shield cannot restrict itself before nsenter because
	// nsenter must open the holder's nsfs ns files, which Landlock cannot cover.
	hardenLandlockFDFlag = "--landlock-fd"

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

	// TUNAddrCIDR is the address assigned to the TUN inside the agent's netns.
	// The gateway answers any destination the agent dials, so the peer address
	// is unused; the /16 just gives the agent a routable source address.
	TUNAddrCIDR = "10.78.0.2/16"

	// TUNMTU is the MTU set on the netns TUN. It matches tunnel.Config's default
	// MTU (1420) so the userspace forwarder and the device agree and neither
	// side has to fragment.
	TUNMTU = 1420
)

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

	// Keep the TUN fd open and block forever so the interface and namespaces
	// persist for the session. Pdeathsig (set by the parent) kills us if the
	// shield dies; cleanup also SIGKILLs us via Namespace.Close.
	select {}
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
	defer parentConn.Close()
	parentUC, ok := parentConn.(*net.UnixConn)
	if !ok {
		return nil, nil, fmt.Errorf("netns: handoff conn is not unix")
	}

	exe, err := os.Executable()
	if err != nil {
		exe = "/proc/self/exe"
	}
	cmd := exec.Command(exe, reexecTUNArg, ifName, addrCIDR)
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
		// Tie the holder's lifetime to ours: if the shield dies, the kernel
		// SIGKILLs the holder, tearing down the namespaces (no leak).
		Pdeathsig: syscall.SIGKILL,
	}

	if err := cmd.Start(); err != nil {
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
		_ = cmd.Process.Kill()
		go func() { _ = cmd.Wait() }()
		return nil, nil, fmt.Errorf("netns: receive tun fd from holder: %w", err)
	}
	tun = os.NewFile(uintptr(tunFD), "/dev/net/tun:"+ifName)

	ns = &Namespace{pid: cmd.Process.Pid}
	go func() { _ = cmd.Wait() }() // reap when Close SIGKILLs the holder

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
func (ns *Namespace) AgentCommand(agentPath string, agentArgs []string, landlockFD int) *exec.Cmd {
	exe, err := os.Executable()
	if err != nil {
		exe = "/proc/self/exe"
	}
	args := []string{
		"--target", strconv.Itoa(ns.pid),
		"--user", "--preserve-credentials",
		"--net", "--mount",
		"--",
		exe, reexecHardenArg,
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
	// Optional inherited Landlock ruleset fd, applied AFTER nsenter (AGE-166).
	landlockFD := -1
	if len(args) >= 2 && args[0] == hardenLandlockFDFlag {
		fd, err := strconv.Atoi(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "netns harden-exec: bad %s value %q: %v\n", hardenLandlockFDFlag, args[1], err)
			os.Exit(2)
		}
		landlockFD = fd
		args = args[2:]
	}

	// Strip the leading "--" separator that AgentCommand inserts.
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
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
