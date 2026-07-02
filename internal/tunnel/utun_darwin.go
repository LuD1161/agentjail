//go:build darwin

package tunnel

import (
	"fmt"
	"os/exec"

	"golang.zx2c4.com/wireguard/tun"
)

// DefaultMTU is the default MTU for utun devices.
const DefaultMTU = 1420

// CreateUTun creates a macOS utun device using wireguard-go's native tun
// package. On macOS, tun.CreateTUN allocates the next available utunN
// interface from the kernel (no /dev/net/tun or kernel extension required).
//
// Requires root privileges (must run as LaunchDaemon).
// Returns the tun.Device, the real utun name (e.g. "utun5"), and any error.
func CreateUTun(name string) (tun.Device, string, error) {
	tunDev, err := tun.CreateTUN(name, DefaultMTU)
	if err != nil {
		return nil, "", fmt.Errorf("create utun: %w", err)
	}

	realName, err := tunDev.Name()
	if err != nil {
		tunDev.Close()
		return nil, "", fmt.Errorf("get utun name: %w", err)
	}

	return tunDev, realName, nil
}

// ConfigureUTunRoutes sets up the IP address and default routes on the utun
// interface. Uses ifconfig and route commands (standard on macOS).
// Requires root privileges.
//
// localIP is the agent-side IP on the utun (e.g. "10.78.0.2").
// peerIP is the daemon/gateway IP on the other end (e.g. "10.78.0.1").
//
// Two /1 routes are added instead of a single default route to avoid
// replacing the existing system default route, which would break the daemon's
// own upstream connectivity.
func ConfigureUTunRoutes(utunName, localIP, peerIP string) error {
	// ifconfig utunN inet <localIP> <peerIP> up
	if out, err := exec.Command("ifconfig", utunName, "inet", localIP, peerIP, "up").CombinedOutput(); err != nil {
		return fmt.Errorf("ifconfig %s: %w (output: %s)", utunName, err, out)
	}

	// route add -net 0.0.0.0/1 -interface utunN
	if out, err := exec.Command("route", "add", "-net", "0.0.0.0/1", "-interface", utunName).CombinedOutput(); err != nil {
		return fmt.Errorf("route add 0/1: %w (output: %s)", err, out)
	}

	// route add -net 128.0.0.0/1 -interface utunN
	if out, err := exec.Command("route", "add", "-net", "128.0.0.0/1", "-interface", utunName).CombinedOutput(); err != nil {
		// Best-effort cleanup of the first route before returning.
		exec.Command("route", "delete", "-net", "0.0.0.0/1", "-interface", utunName).Run()
		return fmt.Errorf("route add 128/1: %w (output: %s)", err, out)
	}

	return nil
}

// CleanupUTunRoutes removes the routes added by ConfigureUTunRoutes.
// Best-effort: errors are silently ignored (routes may already be gone if
// the utun device was closed before cleanup).
func CleanupUTunRoutes(utunName string) {
	exec.Command("route", "delete", "-net", "0.0.0.0/1", "-interface", utunName).Run()
	exec.Command("route", "delete", "-net", "128.0.0.0/1", "-interface", utunName).Run()
}

// SetDNSServers configures the DNS servers for the named macOS network service
// (e.g. "Wi-Fi", "Ethernet"). Pass "Empty" as server to restore system
// defaults. Requires admin privileges.
func SetDNSServers(networkService, server string) error {
	out, err := exec.Command("networksetup", "-setdnsservers", networkService, server).CombinedOutput()
	if err != nil {
		return fmt.Errorf("networksetup -setdnsservers %s %s: %w (output: %s)",
			networkService, server, err, out)
	}
	return nil
}
