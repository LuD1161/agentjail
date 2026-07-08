//go:build linux

package netns

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// SendFD passes a single file descriptor to the peer of a connected unix-domain
// socket using SCM_RIGHTS ancillary data. A one-byte payload accompanies the
// control message so the receiver's read reliably returns the ancillary data.
//
// The kernel duplicates the descriptor into the receiving process; the sender
// retains ownership of fd and remains responsible for closing it.
func SendFD(uc *net.UnixConn, fd int) error {
	rights := unix.UnixRights(fd)
	if _, _, err := uc.WriteMsgUnix([]byte{0}, rights, nil); err != nil {
		return fmt.Errorf("send fd: %w", err)
	}
	return nil
}

// RecvFD receives a single file descriptor sent with SendFD over a connected
// unix-domain socket. It returns a clear error if the peer sent no descriptor.
//
// The returned fd is marked close-on-exec. If the peer sent more than one
// descriptor, the extras are closed to avoid leaking them.
func RecvFD(uc *net.UnixConn) (int, error) {
	payload := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4)) // room for exactly one fd

	_, oobn, _, _, err := uc.ReadMsgUnix(payload, oob)
	if err != nil {
		return -1, fmt.Errorf("recv fd: %w", err)
	}

	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, fmt.Errorf("parse socket control message: %w", err)
	}
	if len(msgs) == 0 {
		return -1, errors.New("recv fd: no control message received (expected one descriptor)")
	}

	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil {
		return -1, fmt.Errorf("parse unix rights: %w", err)
	}
	if len(fds) == 0 {
		return -1, errors.New("recv fd: control message carried no file descriptor")
	}

	// Guard against a peer sending more than we expect: keep the first,
	// close the rest so they don't leak into this process.
	for _, extra := range fds[1:] {
		_ = unix.Close(extra)
	}

	fd := fds[0]
	unix.CloseOnExec(fd)
	return fd, nil
}
