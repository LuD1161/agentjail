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
