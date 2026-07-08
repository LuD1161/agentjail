//go:build darwin

package main

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// extractPeerPID returns the PID of the process on the other end of a Unix
// domain socket connection using the macOS LOCAL_PEERPID socket option.
func extractPeerPID(conn net.Conn) (int, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("extractPeerPID: not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("extractPeerPID: SyscallConn: %w", err)
	}

	var pid int
	var sysErr error
	if err := raw.Control(func(fd uintptr) {
		pid, sysErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	}); err != nil {
		return 0, fmt.Errorf("extractPeerPID: Control: %w", err)
	}
	if sysErr != nil {
		return 0, fmt.Errorf("extractPeerPID: getsockopt LOCAL_PEERPID: %w", sysErr)
	}
	return pid, nil
}

// extractPeerUID returns the UID of the process on the other end of a Unix
// domain socket connection using the macOS LOCAL_PEERCRED socket option
// (xucred.cr_uid). Populated by the kernel at connect/accept time, so it
// cannot be spoofed by the connecting process.
func extractPeerUID(conn net.Conn) (int, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("extractPeerUID: not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("extractPeerUID: SyscallConn: %w", err)
	}

	var xucred *unix.Xucred
	var sysErr error
	if err := raw.Control(func(fd uintptr) {
		xucred, sysErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, fmt.Errorf("extractPeerUID: Control: %w", err)
	}
	if sysErr != nil {
		return 0, fmt.Errorf("extractPeerUID: getsockopt LOCAL_PEERCRED: %w", sysErr)
	}
	return int(xucred.Uid), nil
}

// resolvePeerCWD is not supported on macOS: there is no /proc-equivalent
// filesystem exposed via the stdlib/x/sys, and resolving another process's
// CWD requires libproc (cgo) which this package avoids. Callers must treat
// a non-nil error as "cannot verify" and fail safe (skip binding / refuse),
// never as "verified match".
func resolvePeerCWD(pid int) (string, error) {
	return "", fmt.Errorf("resolvePeerCWD: not supported on darwin")
}
