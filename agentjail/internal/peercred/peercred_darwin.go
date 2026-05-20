//go:build darwin

package peercred

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// localPeerPID is the macOS-specific sockopt name for the immediate
// peer's PID on a Unix-domain socket. Documented in <sys/un.h> as
// value 0x002 (LOCAL_PEERPID), distinct from LOCAL_PEERCRED (0x001).
// golang.org/x/sys/unix exposes it as LOCAL_PEERPID on darwin builds.
const localPeerPID = unix.LOCAL_PEERPID

func getCreds(c *net.UnixConn) (Creds, error) {
	sc, err := c.SyscallConn()
	if err != nil {
		return Creds{}, fmt.Errorf("peercred: syscallconn: %w", err)
	}
	var (
		xu     *unix.Xucred
		peerPID int
		opErr  error
	)
	cerr := sc.Control(func(fd uintptr) {
		// LOCAL_PEERCRED → xucred {uid, ngroups, groups...}. No PID
		// in this struct — that's the whole reason LOCAL_PEERPID
		// exists as a separate sockopt.
		xu, opErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if opErr != nil {
			return
		}
		// LOCAL_PEERPID → the immediate peer's pid_t. Note: SOL_LOCAL,
		// NOT SOL_SOCKET. Mixing them up returns ENOPROTOOPT.
		peerPID, opErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, localPeerPID)
	})
	if cerr != nil {
		return Creds{}, fmt.Errorf("peercred: control: %w", cerr)
	}
	if opErr != nil {
		return Creds{}, fmt.Errorf("peercred: getsockopt: %w", opErr)
	}
	gid := uint32(0)
	if xu.Ngroups > 0 {
		gid = uint32(xu.Groups[0])
	}
	return Creds{
		UID: uint32(xu.Uid),
		GID: gid,
		PID: peerPID,
	}, nil
}
