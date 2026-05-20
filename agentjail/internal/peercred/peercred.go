// Package peercred reads OS peer credentials from a Unix-domain socket
// connection. Returns (uid, gid, pid) so the daemon's auth gate can
// decide whether a privileged op (cred.fetch / cred.poll / cred.resolve)
// was issued by the wrapped agent or by the operator.
//
// macOS needs TWO socket options because LOCAL_PEERCRED returns an
// xucred (uid/gid only, no PID) and LOCAL_PEERPID returns the immediate
// peer's PID separately. We call both — the daemon authenticates peers by
// kernel-provided identity (uid/gid/pid), never by bearer tokens.
//
// Linux returns all three (pid/uid/gid) in one SO_PEERCRED call.
//
// Implementations live in peercred_darwin.go and peercred_linux.go.
package peercred

import (
	"errors"
	"net"
)

// Creds is the resolved peer identity of a Unix-socket connection.
//
// PID is the immediate-peer PID on macOS (from LOCAL_PEERPID,
// sockopt 0x002 on SOL_LOCAL) and the SO_PEERCRED pid on Linux. It is
// NOT the listening socket's PID — that distinction matters because
// LOCAL_PEERCRED and LOCAL_PEERPID return different things on macOS.
type Creds struct {
	UID uint32
	GID uint32
	PID int
}

// ErrUnsupported is returned by Get on platforms we don't implement.
// Callers on the cred-auth hot path should fail-closed when they see
// this — we can't make a same-uid decision without OS support.
var ErrUnsupported = errors.New("peercred: unsupported platform")

// ErrNotUnixConn is returned by Get when c is not a *net.UnixConn. The
// daemon only listens on AF_UNIX, so this shouldn't fire in practice;
// it's defensive against a future TCP debug path that wires the wrong
// listener through.
var ErrNotUnixConn = errors.New("peercred: not a unix-domain connection")

// Get extracts the peer's OS credentials from a connected Unix socket.
// The connection must already be Accept()ed; reading creds is a single
// getsockopt() call on the underlying fd.
func Get(c net.Conn) (Creds, error) {
	u, ok := c.(*net.UnixConn)
	if !ok {
		return Creds{}, ErrNotUnixConn
	}
	return getCreds(u)
}
