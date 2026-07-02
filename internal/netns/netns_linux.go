//go:build linux

// Package netns creates unprivileged Linux network + mount namespaces for
// agent isolation. The agent runs inside an isolated namespace where the
// only network path is through the WireGuard tunnel to the gateway.
//
// This package complements Landlock (filesystem restrictions) with network
// namespace isolation. Landlock handles filesystem, namespace handles network.
package netns

import (
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// Veth IP addressing: the host side gets 10.77.0.1/30, the namespace side
// gets 10.77.0.2/30. The /30 subnet provides exactly two usable IPs.
const (
	VethHostIP = "10.77.0.1"
	VethNsIP   = "10.77.0.2"
	VethCIDR   = "/30"
)

// Namespace represents a Linux network namespace with an associated child
// process that holds the namespace alive.
type Namespace struct {
	mu  sync.Mutex
	pid int
	cmd *exec.Cmd
}

// Create creates a new unprivileged network + user + mount namespace.
// The namespace is kept alive by a child process sleeping indefinitely.
func Create() (*Namespace, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cmd := exec.Command("/bin/sleep", "infinity")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{
			ContainerID: 0,
			HostID:      syscall.Getuid(),
			Size:        1,
		}},
		GidMappings: []syscall.SysProcIDMap{{
			ContainerID: 0,
			HostID:      syscall.Getgid(),
			Size:        1,
		}},
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start namespace holder: %w", err)
	}

	ns := &Namespace{
		pid: cmd.Process.Pid,
		cmd: cmd,
	}

	// Bring up loopback inside the namespace.
	if err := nsExec(ns.pid, "ip", "link", "set", "lo", "up"); err != nil {
		_ = ns.Close()
		return nil, fmt.Errorf("bring up loopback: %w", err)
	}

	return ns, nil
}

// PID returns the PID of the namespace holder process.
func (ns *Namespace) PID() int {
	return ns.pid
}

// SetupVeth creates a veth pair linking the host network to the namespace.
// Returns (hostVethName, nsVethName, error).
// Requires CAP_NET_ADMIN in the host network namespace.
func (ns *Namespace) SetupVeth() (string, string, error) {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	hostVeth := "ajail-h" + strconv.Itoa(ns.pid%10000)
	nsVeth := "ajail-n" + strconv.Itoa(ns.pid%10000)

	// Create the veth pair in the host namespace.
	if err := run("ip", "link", "add", hostVeth, "type", "veth", "peer", "name", nsVeth); err != nil {
		return "", "", fmt.Errorf("create veth pair: %w", err)
	}

	// Move nsVeth into the namespace.
	if err := run("ip", "link", "set", nsVeth, "netns", strconv.Itoa(ns.pid)); err != nil {
		_ = run("ip", "link", "delete", hostVeth)
		return "", "", fmt.Errorf("move veth to namespace: %w", err)
	}

	// Configure host side.
	if err := run("ip", "addr", "add", VethHostIP+VethCIDR, "dev", hostVeth); err != nil {
		return "", "", fmt.Errorf("configure host veth: %w", err)
	}
	if err := run("ip", "link", "set", hostVeth, "up"); err != nil {
		return "", "", fmt.Errorf("bring up host veth: %w", err)
	}

	// Configure namespace side.
	if err := nsExec(ns.pid, "ip", "addr", "add", VethNsIP+VethCIDR, "dev", nsVeth); err != nil {
		return "", "", fmt.Errorf("configure ns veth: %w", err)
	}
	if err := nsExec(ns.pid, "ip", "link", "set", nsVeth, "up"); err != nil {
		return "", "", fmt.Errorf("bring up ns veth: %w", err)
	}
	if err := nsExec(ns.pid, "ip", "route", "add", "default", "via", VethHostIP); err != nil {
		return "", "", fmt.Errorf("add default route: %w", err)
	}

	return hostVeth, nsVeth, nil
}

// Close tears down the namespace by killing the holder process.
func (ns *Namespace) Close() error {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	if ns.cmd == nil || ns.cmd.Process == nil {
		return nil
	}

	if err := ns.cmd.Process.Kill(); err != nil {
		return fmt.Errorf("kill namespace holder: %w", err)
	}
	_ = ns.cmd.Wait()
	return nil
}

// run executes a command in the host namespace.
func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, out)
	}
	return nil
}

// nsExec runs a command inside the namespace of the given PID via nsenter.
func nsExec(pid int, name string, args ...string) error {
	nsenterArgs := []string{
		"-t", strconv.Itoa(pid),
		"-n", // network namespace
		"-m", // mount namespace
		name,
	}
	nsenterArgs = append(nsenterArgs, args...)
	return run("nsenter", nsenterArgs...)
}
