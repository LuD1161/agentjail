//go:build !(aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris)

package sandbox

import "fmt"

func validateSSHAuthSockOnDisk(string) (SSHAuthSock, error) {
	return SSHAuthSock{}, fmt.Errorf("ssh-agent socket validation is unsupported on this platform")
}
