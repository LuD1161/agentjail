//go:build !darwin

package tunnel

import (
	"fmt"

	"golang.zx2c4.com/wireguard/tun"
)

// CreateUTun is not supported on non-Darwin platforms.
func CreateUTun(_ string) (tun.Device, string, error) {
	return nil, "", fmt.Errorf("utun not supported on this platform")
}

// ConfigureUTunRoutes is not supported on non-Darwin platforms.
func ConfigureUTunRoutes(_, _, _ string) error {
	return fmt.Errorf("utun routes not supported on this platform")
}

// CleanupUTunRoutes is a no-op on non-Darwin platforms.
func CleanupUTunRoutes(_ string) {}

// SetDNSServers is not supported on non-Darwin platforms.
func SetDNSServers(_, _ string) error {
	return fmt.Errorf("networksetup not supported on this platform")
}
