//go:build linux

package main

import (
	"fmt"
	"net"

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
