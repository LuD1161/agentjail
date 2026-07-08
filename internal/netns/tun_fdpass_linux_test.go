//go:build linux

package netns

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// netFileUnixConn wraps an *os.File-backed unix socket as a *net.UnixConn.
// net.FileConn dups the descriptor, so the caller retains ownership of f and
// must close it separately.
func netFileUnixConn(f *os.File) (*net.UnixConn, error) {
	c, err := net.FileConn(f)
	if err != nil {
		return nil, err
	}
	uc, ok := c.(*net.UnixConn)
	if !ok {
		c.Close()
		return nil, fmt.Errorf("expected *net.UnixConn, got %T", c)
	}
	return uc, nil
}

// unixSocketPair returns two connected *os.File-backed unix stream sockets
// wrapped so their file descriptors can be used directly. We keep the raw fds
// (rather than net.UnixConn) because RecvFD/SendFD operate on *net.UnixConn;
// callers convert as needed.
func unixSocketPair(t *testing.T) (a, b *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	a = os.NewFile(uintptr(fds[0]), "sockpair-a")
	b = os.NewFile(uintptr(fds[1]), "sockpair-b")
	return a, b
}

func TestSendRecvFD_RoundTrip(t *testing.T) {
	fa, fb := unixSocketPair(t)
	defer fa.Close()
	defer fb.Close()

	// net.FileConn dups the fd, so we must close the originals afterwards.
	ca, err := netFileUnixConn(fa)
	if err != nil {
		t.Fatalf("wrap a: %v", err)
	}
	defer ca.Close()
	cb, err := netFileUnixConn(fb)
	if err != nil {
		t.Fatalf("wrap b: %v", err)
	}
	defer cb.Close()

	// Create a temp file with known content and identity.
	dir := t.TempDir()
	path := filepath.Join(dir, "payload.txt")
	const want = "scm_rights round trip"
	if err := os.WriteFile(path, []byte(want), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	src, err := os.Open(path)
	if err != nil {
		t.Fatalf("open temp file: %v", err)
	}
	defer src.Close()

	var srcStat unix.Stat_t
	if err := unix.Fstat(int(src.Fd()), &srcStat); err != nil {
		t.Fatalf("fstat src: %v", err)
	}

	// Send from a, receive on b.
	if err := SendFD(ca, int(src.Fd())); err != nil {
		t.Fatalf("SendFD: %v", err)
	}
	rfd, err := RecvFD(cb)
	if err != nil {
		t.Fatalf("RecvFD: %v", err)
	}
	// Ownership of rfd is ours now.
	recv := os.NewFile(uintptr(rfd), "received")
	defer recv.Close()

	// The received fd must be a distinct descriptor number...
	if int(recv.Fd()) == int(src.Fd()) {
		t.Fatalf("received fd %d equals source fd; expected a distinct descriptor", rfd)
	}

	// ...that refers to the same underlying file (same dev+inode).
	var recvStat unix.Stat_t
	if err := unix.Fstat(rfd, &recvStat); err != nil {
		t.Fatalf("fstat recv: %v", err)
	}
	if recvStat.Ino != srcStat.Ino || recvStat.Dev != srcStat.Dev {
		t.Fatalf("received fd refers to a different file: got dev=%d ino=%d want dev=%d ino=%d",
			recvStat.Dev, recvStat.Ino, srcStat.Dev, srcStat.Ino)
	}

	// And reading it back yields the known content.
	got := make([]byte, len(want))
	n, err := recv.ReadAt(got, 0)
	if err != nil && n != len(want) {
		t.Fatalf("read back: %v (n=%d)", err, n)
	}
	if string(got[:n]) != want {
		t.Fatalf("content mismatch: got %q want %q", string(got[:n]), want)
	}
}

func TestRecvFD_NoDescriptor(t *testing.T) {
	fa, fb := unixSocketPair(t)
	defer fb.Close()

	ca, err := netFileUnixConn(fa)
	if err != nil {
		t.Fatalf("wrap a: %v", err)
	}
	defer ca.Close()
	cb, err := netFileUnixConn(fb)
	if err != nil {
		t.Fatalf("wrap b: %v", err)
	}
	defer cb.Close()
	fa.Close()

	// Ordinary write with no ancillary data.
	if _, err := ca.Write([]byte{0}); err != nil {
		t.Fatalf("plain write: %v", err)
	}
	if _, err := RecvFD(cb); err == nil {
		t.Fatalf("RecvFD: expected error when no descriptor was sent")
	}
}

func TestOpenTUN(t *testing.T) {
	f, ifName, err := OpenTUN("")
	if err != nil {
		// Gracefully skip when the environment can't create a TUN:
		// no /dev/net/tun, no permission, or running outside a userns.
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENODEV) ||
			errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EACCES) ||
			errors.Is(err, unix.EBUSY) {
			t.Skipf("skipping OpenTUN: %v", err)
		}
		t.Fatalf("OpenTUN: %v", err)
	}
	defer f.Close()

	if ifName == "" {
		t.Fatalf("OpenTUN returned empty interface name")
	}
	if f.Fd() == ^uintptr(0) {
		t.Fatalf("OpenTUN returned an invalid fd for %q", ifName)
	}

	// The fd must be a live descriptor.
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		t.Fatalf("fstat tun fd: %v", err)
	}
	t.Logf("created TUN %q on fd %d", ifName, f.Fd())
}
