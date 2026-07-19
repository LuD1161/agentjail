//go:build linux

// Package netns creates unprivileged Linux network + mount namespaces for
// agent isolation.  The agent runs inside an isolated namespace where the
// only network path is through the WireGuard tunnel to the gateway.
//
// This package complements Landlock (filesystem restrictions) with network
// namespace isolation.  Landlock handles filesystem, namespace handles network.
//
// # Privilege model
//
// Create uses CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS.  CLONE_NEWUSER
// enables unprivileged namespace creation on kernels that allow it
// (sysctl kernel.unprivileged_userns_clone=1, the default on most distros).
// No root or CAP_NET_ADMIN is required for namespace creation itself.
//
// The network path into the namespace is a TUN device created *inside* the
// netns by the namespace owner, who holds CAP_NET_ADMIN there — see
// tunsetup_linux.go (CreateWithTUN). The open TUN fd is handed to the userspace
// gateway over SCM_RIGHTS, so no host CAP_NET_ADMIN and no privileged daemon are
// needed. This replaced the earlier host-veth + privileged-daemon design; see
// ADR 0079.
package netns

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ErrUnsupported is returned on platforms that don't support network namespaces.
var ErrUnsupported = fmt.Errorf("network namespaces not supported on this platform")

// Namespace represents an isolated user + network + mount namespace.
//
// The namespace is created by a short-lived child process that stays alive
// (blocked on sleep) to keep the namespace open.  The child's /proc/PID/ns/*
// entries are the references used by ExecIn.
type Namespace struct {
	// pid of the "holder" child that keeps the namespace alive.
	pid int

	// holderDone, when non-nil, releases the goroutine that forked the holder on
	// a locked OS thread. Pdeathsig is delivered when the *cloning thread* exits,
	// so that thread must live as long as the holder (else the holder is SIGKILLed
	// mid-session). Closed by Close(). See ADR 0103-shield-reexec-argv0.
	holderDone chan struct{}

	// cleanup state
	mu     sync.Mutex
	closed bool
}

// Create creates unprivileged user + network + mount namespaces.
//
// It launches a minimal child process with CLONE_NEWUSER | CLONE_NEWNET |
// CLONE_NEWNS.  The child blocks (via sleep) to keep the namespace alive.
// UID/GID mappings are written so the current user maps to uid/gid 0 inside
// the namespace.
//
// The loopback interface inside the namespace is brought up automatically.
//
// Returns ErrUnsupported if the kernel does not support unprivileged user
// namespaces (EPERM from clone).
func Create() (*Namespace, error) {
	uid := os.Getuid()
	gid := os.Getgid()

	// Launch a holder process: `sleep infinity` inside the new namespaces.
	cmd := exec.Command("sleep", "infinity")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS,
		// Map the current user to root (uid 0) inside the namespace.
		// This is required for mount operations inside CLONE_NEWNS.
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: uid, Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: gid, Size: 1},
		},
		// Disable setgroups(2) inside the namespace -- required by the
		// kernel before writing /proc/PID/gid_map from an unprivileged
		// process (commit 9cc46516).
		GidMappingsEnableSetgroups: false,
	}

	if err := cmd.Start(); err != nil {
		if isClonePermError(err) {
			return nil, fmt.Errorf(
				"%w: unprivileged user namespaces disabled "+
					"(kernel.unprivileged_userns_clone=0?): %v",
				ErrUnsupported, err,
			)
		}
		return nil, fmt.Errorf("namespace holder start: %w", err)
	}

	ns := &Namespace{pid: cmd.Process.Pid}

	// Bring up loopback inside the namespace so 127.0.0.1 works.
	if err := ns.bringUpLoopback(); err != nil {
		// Non-fatal: warn but continue.
		fmt.Fprintf(os.Stderr, "netns: warning: failed to bring up loopback: %v\n", err)
	}

	// Reap the holder asynchronously (it exits when we SIGKILL it in Close).
	go func() { _ = cmd.Wait() }()

	return ns, nil
}

// bringUpLoopback brings up the lo interface inside the namespace.
// It tries the netlink API first (via doInNetNS) and falls back to
// nsenter + ip if setns is not permitted (common in unprivileged user
// namespace environments where the parent cannot enter the child's
// user namespace without CAP_SYS_ADMIN).
func (ns *Namespace) bringUpLoopback() error {
	err := ns.doInNetNS(func() error {
		lo, linkErr := netlink.LinkByName("lo")
		if linkErr != nil {
			return fmt.Errorf("lookup loopback: %w", linkErr)
		}
		return netlink.LinkSetUp(lo)
	})
	if err == nil {
		return nil
	}
	// Fallback: use nsenter + ip for environments where setns is denied.
	slog.Debug("netlink loopback bring-up failed, falling back to nsenter",
		"error", err)
	loCmd := exec.Command("ip", "link", "set", "lo", "up")
	return ns.ExecIn(loCmd)
}

// doInNetNS enters the namespace's user and network namespaces, runs fn,
// then restores the original namespaces.  The current OS thread is locked
// for the duration so goroutine scheduling cannot leak the namespace change
// to other goroutines.
func (ns *Namespace) doInNetNS(fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save originals so we can restore after fn.
	origUser, err := os.Open("/proc/self/ns/user")
	if err != nil {
		return fmt.Errorf("open current user ns: %w", err)
	}
	defer origUser.Close()

	origNet, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return fmt.Errorf("open current netns: %w", err)
	}
	defer origNet.Close()

	// Open the target namespaces.
	targetUser, err := os.Open(fmt.Sprintf("/proc/%d/ns/user", ns.pid))
	if err != nil {
		return fmt.Errorf("open target user ns (pid %d): %w", ns.pid, err)
	}
	defer targetUser.Close()

	targetNet, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", ns.pid))
	if err != nil {
		return fmt.Errorf("open target netns (pid %d): %w", ns.pid, err)
	}
	defer targetNet.Close()

	// Enter user namespace first (required to gain permission to enter
	// the network namespace that belongs to a different user namespace).
	if err := unix.Setns(int(targetUser.Fd()), unix.CLONE_NEWUSER); err != nil {
		return fmt.Errorf("setns to target user ns: %w", err)
	}

	// Enter network namespace.
	if err := unix.Setns(int(targetNet.Fd()), unix.CLONE_NEWNET); err != nil {
		// Restore user namespace before returning.
		_ = unix.Setns(int(origUser.Fd()), unix.CLONE_NEWUSER)
		return fmt.Errorf("setns to target netns: %w", err)
	}

	// Ensure we restore original namespaces even on error.
	defer func() {
		if restoreErr := unix.Setns(int(origNet.Fd()), unix.CLONE_NEWNET); restoreErr != nil {
			slog.Error("failed to restore original netns", "error", restoreErr)
		}
		if restoreErr := unix.Setns(int(origUser.Fd()), unix.CLONE_NEWUSER); restoreErr != nil {
			slog.Error("failed to restore original user ns", "error", restoreErr)
		}
	}()

	return fn()
}

// ExecIn runs a command inside the namespace.
//
// The command inherits the namespace's user, network, and mount isolation
// by entering via /proc/PID/ns/{user,net,mnt} of the holder process.
//
// The command is executed using nsenter(1) which handles the setns(2) calls.
func (ns *Namespace) ExecIn(cmd *exec.Cmd) error {
	ns.mu.Lock()
	if ns.closed {
		ns.mu.Unlock()
		return fmt.Errorf("namespace is closed")
	}
	ns.mu.Unlock()

	nsenter := ns.buildNsenter(cmd)
	nsenter.Stdin = cmd.Stdin
	nsenter.Stdout = cmd.Stdout
	nsenter.Stderr = cmd.Stderr

	return nsenter.Run()
}

// ExecInCombinedOutput is like ExecIn but captures combined stdout+stderr.
func (ns *Namespace) ExecInCombinedOutput(cmd *exec.Cmd) ([]byte, error) {
	ns.mu.Lock()
	if ns.closed {
		ns.mu.Unlock()
		return nil, fmt.Errorf("namespace is closed")
	}
	ns.mu.Unlock()

	nsenter := ns.buildNsenter(cmd)
	nsenter.Stdin = cmd.Stdin

	return nsenter.CombinedOutput()
}

// buildNsenter constructs the nsenter command for entering the namespace.
//
// We use --user --preserve-credentials to enter the user namespace without
// calling setgroups(2), which is denied because we wrote "deny" to
// /proc/PID/setgroups (via GidMappingsEnableSetgroups: false).
// Without --user, nsenter cannot enter --net or --mount (EPERM), because
// those namespaces belong to a different user namespace.
func (ns *Namespace) buildNsenter(cmd *exec.Cmd) *exec.Cmd {
	pidStr := strconv.Itoa(ns.pid)
	args := []string{
		"--target", pidStr,
		"--user", "--preserve-credentials",
		"--net", "--mount",
		"--",
	}
	args = append(args, cmd.Path)
	args = append(args, cmd.Args[1:]...) // Args[0] is the program name

	nsenter := exec.Command("nsenter", args...)
	nsenter.Env = cmd.Env
	nsenter.Dir = cmd.Dir
	return nsenter
}

// PID returns the PID of the holder process.  External tooling can use
// /proc/<PID>/ns/* paths to join the namespace.
func (ns *Namespace) PID() int {
	return ns.pid
}

// Close kills the holder process, causing the kernel to tear down the
// namespaces (assuming no other process has joined them).
func (ns *Namespace) Close() error {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	if ns.closed {
		return nil
	}
	ns.closed = true

	proc, err := os.FindProcess(ns.pid)
	if err != nil {
		return nil // already gone
	}
	// SIGKILL the holder -- it is just `sleep infinity`.
	_ = proc.Signal(syscall.SIGKILL)
	// Release the locked cloning thread (CreateWithTUN); nil for the sleep-based
	// Create path.
	if ns.holderDone != nil {
		close(ns.holderDone)
	}
	return nil
}

// isClonePermError checks if a process start error is due to clone
// permission denied (typically unprivileged user namespaces are disabled).
func isClonePermError(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "operation not permitted") ||
		strings.Contains(s, "permission denied")
}

func init() {
	// Belt-and-suspenders with the build tag.
	if runtime.GOOS != "linux" {
		panic("netns: loaded on non-linux platform")
	}
}
