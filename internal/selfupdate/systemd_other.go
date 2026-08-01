//go:build !linux

package selfupdate

import "fmt"

// SystemdDaemonReload is unavailable on platforms without systemd.
func SystemdDaemonReload() error {
	return fmt.Errorf("systemctl: not available on this platform")
}
