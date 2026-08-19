//go:build linux

package hostconnector

func platformTransportCapabilities() []TransportCapability {
	return []TransportCapability{
		{
			Isolation: IsolationSameHost,
			State:     StateAvailable,
			Detail:    "netproxy synthetic connector route on host loopback",
		},
		{
			Isolation: IsolationLinuxContainer,
			State:     StateAvailable,
			Detail:    "session-scoped AF_UNIX connector endpoint; trusted container launcher must bind-mount it",
		},
		{
			Isolation: IsolationMicroVM,
			State:     StateUnavailable,
			Detail:    "no production VM launch seam exposes vsock or a shared socket; Firecracker support remains a research fixture",
		},
		{
			Isolation: IsolationMacOSSandbox,
			State:     StateUnavailable,
			Detail:    "macOS Seatbelt transport is unavailable in a Linux build",
		},
		{
			Isolation: IsolationMacOSGuest,
			State:     StateUnavailable,
			Detail:    "macOS guest transport is unavailable in a Linux build",
		},
	}
}
