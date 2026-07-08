//go:build linux

package netns

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// OpenTUN opens /dev/net/tun and creates (or attaches to) a TUN interface via
// the TUNSETIFF ioctl with flags IFF_TUN|IFF_NO_PI — i.e. a layer-3 device
// carrying raw IP packets with no 4-byte protocol-info prefix. It returns the
// open device *os.File (the packet fd) and the resulting interface name.
//
// Pass an empty name to let the kernel allocate the next free "tunN"; the
// allocated name is read back from the ifreq and returned as ifName.
//
// This is designed to run *inside* an already-created user+network namespace,
// where the caller holds CAP_NET_ADMIN scoped to that netns (as granted by the
// CLONE_NEWUSER|CLONE_NEWNET setup in Create). It therefore needs no host
// privilege: creating a TUN inside an owned netns is an unprivileged operation
// for the namespace owner. The fd can be handed to another process over a unix
// socket with SendFD (see fdpass_linux.go).
func OpenTUN(name string) (f *os.File, ifName string, err error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", fmt.Errorf("open /dev/net/tun: %w", err)
	}

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return nil, "", fmt.Errorf("build ifreq for %q: %w", name, err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)

	// TUNSETIFF writes the resolved interface name back into the ifreq.
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return nil, "", fmt.Errorf("TUNSETIFF %q: %w", name, err)
	}

	ifName = ifr.Name()
	f = os.NewFile(uintptr(fd), "/dev/net/tun:"+ifName)
	return f, ifName, nil
}
