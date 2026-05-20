//go:build linux

package peercred

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// getCreds uses SO_PEERCRED which returns struct ucred {pid, uid, gid}
// in a single call. Linux is friendlier than macOS here — one sockopt
// gives us everything.
func getCreds(c *net.UnixConn) (Creds, error) {
	sc, err := c.SyscallConn()
	if err != nil {
		return Creds{}, fmt.Errorf("peercred: syscallconn: %w", err)
	}
	var (
		uc    *unix.Ucred
		opErr error
	)
	cerr := sc.Control(func(fd uintptr) {
		uc, opErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if cerr != nil {
		return Creds{}, fmt.Errorf("peercred: control: %w", cerr)
	}
	if opErr != nil {
		return Creds{}, fmt.Errorf("peercred: getsockopt SO_PEERCRED: %w", opErr)
	}
	return Creds{
		UID: uc.Uid,
		GID: uc.Gid,
		PID: int(uc.Pid),
	}, nil
}
