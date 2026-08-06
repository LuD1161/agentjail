//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package sandbox

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// validateSSHAuthSockOnDisk rejects symlink traversal rather than resolving
// it. A second final lstat catches a replacement during the validation walk;
// later same-UID replacement remains an AF_UNIX pathname limitation.
func validateSSHAuthSockOnDisk(path string) (SSHAuthSock, error) {
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	current := string(filepath.Separator)
	for i, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return SSHAuthSock{}, fmt.Errorf("lstat %s: %w", current, err)
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return SSHAuthSock{}, fmt.Errorf("symlink component %s", current)
		}
		if i < len(parts)-1 && !info.IsDir() {
			return SSHAuthSock{}, fmt.Errorf("non-directory parent %s", current)
		}
	}

	before, err := os.Lstat(path)
	if err != nil {
		return SSHAuthSock{}, fmt.Errorf("lstat socket: %w", err)
	}
	if before.Mode()&fs.ModeSocket == 0 {
		return SSHAuthSock{}, fmt.Errorf("not a unix socket")
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return SSHAuthSock{}, fmt.Errorf("socket is not owned by the current user")
	}
	after, err := os.Lstat(path)
	if err != nil {
		return SSHAuthSock{}, fmt.Errorf("recheck socket: %w", err)
	}
	afterStat, ok := after.Sys().(*syscall.Stat_t)
	if !ok || after.Mode()&fs.ModeSocket == 0 || afterStat.Dev != st.Dev || afterStat.Ino != st.Ino {
		return SSHAuthSock{}, fmt.Errorf("socket changed during validation")
	}
	return SSHAuthSock{Path: path}, nil
}
