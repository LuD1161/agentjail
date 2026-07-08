//go:build linux

package main

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// extractPeerPID returns the PID of the process on the other end of a Unix
// domain socket connection using the Linux SO_PEERCRED socket option.
func extractPeerPID(conn net.Conn) (int, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("extractPeerPID: not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("extractPeerPID: SyscallConn: %w", err)
	}

	var ucred *unix.Ucred
	var sysErr error
	if err := raw.Control(func(fd uintptr) {
		ucred, sysErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, fmt.Errorf("extractPeerPID: Control: %w", err)
	}
	if sysErr != nil {
		return 0, fmt.Errorf("extractPeerPID: getsockopt SO_PEERCRED: %w", sysErr)
	}
	return int(ucred.Pid), nil
}

// extractPeerUID returns the UID of the process on the other end of a Unix
// domain socket connection using the Linux SO_PEERCRED socket option. The
// kernel populates SO_PEERCRED at connect/accept time from the peer's real
// credentials, so this cannot be spoofed by the connecting process.
func extractPeerUID(conn net.Conn) (int, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("extractPeerUID: not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("extractPeerUID: SyscallConn: %w", err)
	}

	var ucred *unix.Ucred
	var sysErr error
	if err := raw.Control(func(fd uintptr) {
		ucred, sysErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, fmt.Errorf("extractPeerUID: Control: %w", err)
	}
	if sysErr != nil {
		return 0, fmt.Errorf("extractPeerUID: getsockopt SO_PEERCRED: %w", sysErr)
	}
	return int(ucred.Uid), nil
}

// resolvePeerCWD resolves the real, kernel-verified current working
// directory of pid via /proc/<pid>/cwd. Unlike a self-reported CWD carried
// in a request payload, this cannot be spoofed by the peer process (only a
// process with ptrace/root privilege over pid could fake it, which is a
// much higher bar than "connect to a Unix socket").
func resolvePeerCWD(pid int) (string, error) {
	link := fmt.Sprintf("/proc/%d/cwd", pid)
	target, err := os.Readlink(link)
	if err != nil {
		return "", fmt.Errorf("resolvePeerCWD: readlink %s: %w", link, err)
	}
	return target, nil
}
