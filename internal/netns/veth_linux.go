//go:build linux

package netns

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

// Veth IP addressing: the host side gets 10.77.0.1/30, the namespace side
// gets 10.77.0.2/30.  The /30 subnet provides exactly two usable IPs.
// The WireGuard gateway listens on the host side (10.77.0.1).
const (
	VethHostIP = "10.77.0.1"
	VethNsIP   = "10.77.0.2"
	VethCIDR   = "/30" // 10.77.0.0/30 = .1 and .2 usable
)

// SetupVeth creates a veth pair linking the host network to the namespace.
// Returns the host-side and namespace-side interface names.
//
// The host side gets IP 10.77.0.1/30, the namespace side gets 10.77.0.2/30.
// A default route inside the namespace points to 10.77.0.1 (the host).
// The WireGuard gateway listens on the host side.
//
// # Privilege requirements
//
// Veth pair creation requires CAP_NET_ADMIN in the *initial* (host) network
// namespace.  Unprivileged user namespaces only grant capabilities inside
// the new namespace, not on the host side.  This was verified empirically:
//
//	$ unshare --user --net ip link add veth0 type veth peer name veth1
//	RTNETLINK answers: Operation not permitted
//
// TUN/TAP devices also cannot be created unprivileged inside a user namespace:
//
//	$ unshare --user --net ip tuntap add dev tun0 mode tun
//	ioctl(TUNSETIFF): Operation not permitted
//
// Therefore, SetupVeth requires one of:
//
//   - (a) The agentjail-shield binary has CAP_NET_ADMIN (via setcap).
//     This is the recommended approach:
//     sudo setcap cap_net_admin=ep /path/to/agentjail-shield
//
//   - (b) A small setuid helper binary (agentjail-netns-helper) that
//     performs only the veth creation and IP assignment, then drops
//     privileges.  This limits the privilege surface to a minimal,
//     auditable binary.
//
//   - (c) The user runs agentjail-shield as root (not recommended for
//     general use but acceptable in container/CI environments).
//
// If none of the above are available, SetupVeth returns an error describing
// the privilege requirement.  The namespace is still usable for isolation
// (no external network access at all) -- SetupVeth is only needed when the
// agent must reach the WireGuard gateway.
func (ns *Namespace) SetupVeth() (hostIf, nsIf string, err error) {
	hostIf = "ajail0"
	nsIf = "ajail1"

	// Step 1: Create veth pair on the host.
	// This requires CAP_NET_ADMIN in the host network namespace.
	la := netlink.NewLinkAttrs()
	la.Name = hostIf
	veth := &netlink.Veth{LinkAttrs: la, PeerName: nsIf}
	if err := netlink.LinkAdd(veth); err != nil {
		return "", "", fmt.Errorf(
			"veth creation requires CAP_NET_ADMIN on the host. "+
				"Grant it with: sudo setcap cap_net_admin=ep <shield-binary>. "+
				"Error: %w", err,
		)
	}

	// cleanupHost is a helper for best-effort cleanup of the host veth.
	cleanupHost := func() {
		if hostLink, delErr := netlink.LinkByName(hostIf); delErr == nil {
			_ = netlink.LinkDel(hostLink)
		}
	}

	// Step 2: Move the namespace-side interface into the namespace.
	peer, err := netlink.LinkByName(nsIf)
	if err != nil {
		cleanupHost()
		return "", "", fmt.Errorf("lookup peer %s: %w", nsIf, err)
	}
	if err := netlink.LinkSetNsPid(peer, ns.pid); err != nil {
		cleanupHost()
		return "", "", fmt.Errorf("move %s to namespace (pid %d): %w", nsIf, ns.pid, err)
	}

	// Step 3: Configure the host-side interface.
	hostLink, err := netlink.LinkByName(hostIf)
	if err != nil {
		cleanupHost()
		return "", "", fmt.Errorf("lookup host link %s: %w", hostIf, err)
	}
	hostAddr, err := netlink.ParseAddr(VethHostIP + VethCIDR)
	if err != nil {
		cleanupHost()
		return "", "", fmt.Errorf("parse host addr: %w", err)
	}
	if err := netlink.AddrAdd(hostLink, hostAddr); err != nil {
		cleanupHost()
		return "", "", fmt.Errorf("configure host veth %s: add addr: %w", hostIf, err)
	}
	if err := netlink.LinkSetUp(hostLink); err != nil {
		cleanupHost()
		return "", "", fmt.Errorf("configure host veth %s: set up: %w", hostIf, err)
	}

	// Step 4: Configure the namespace-side interface and default route.
	// Enter the namespace using unix.Setns to use netlink from inside.
	if err := ns.configureNsVeth(nsIf); err != nil {
		cleanupHost()
		return "", "", err
	}

	return hostIf, nsIf, nil
}

// configureNsVeth enters the namespace and configures the namespace-side
// veth interface using the netlink API.  It uses doInNetNS (defined in
// netns_linux.go) to enter both the user and network namespaces.
func (ns *Namespace) configureNsVeth(nsIf string) error {
	return ns.doInNetNS(func() error {
		nsLink, err := netlink.LinkByName(nsIf)
		if err != nil {
			return fmt.Errorf("configure ns veth: lookup %s: %w", nsIf, err)
		}

		nsAddr, err := netlink.ParseAddr(VethNsIP + VethCIDR)
		if err != nil {
			return fmt.Errorf("configure ns veth: parse addr: %w", err)
		}
		if err := netlink.AddrAdd(nsLink, nsAddr); err != nil {
			return fmt.Errorf("configure ns veth: add addr to %s: %w", nsIf, err)
		}

		if err := netlink.LinkSetUp(nsLink); err != nil {
			return fmt.Errorf("configure ns veth: set %s up: %w", nsIf, err)
		}

		// Add default route via the host side.
		gw := net.ParseIP(VethHostIP)
		defaultRoute := &netlink.Route{
			Dst: nil, // default route
			Gw:  gw,
		}
		if err := netlink.RouteAdd(defaultRoute); err != nil {
			return fmt.Errorf("configure ns veth: add default route via %s: %w", VethHostIP, err)
		}

		return nil
	})
}
