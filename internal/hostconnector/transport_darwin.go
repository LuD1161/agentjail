//go:build darwin

package hostconnector

func platformTransportCapabilities() []TransportCapability {
	return []TransportCapability{
		{
			Isolation: IsolationSameHost,
			State:     StateAvailable,
			Detail:    "netproxy synthetic connector route on host loopback",
		},
		{
			Isolation: IsolationMacOSSandbox,
			State:     StateAvailable,
			Detail:    "same-host netproxy endpoint; Seatbelt client and connector share the host network namespace",
		},
		{
			Isolation: IsolationLinuxContainer,
			State:     StateUnavailable,
			Detail:    "Linux AF_UNIX container endpoint is unavailable in a macOS build",
		},
		{
			Isolation: IsolationMicroVM,
			State:     StateUnavailable,
			Detail:    "no production VM launch seam exposes vsock or a shared socket",
		},
		{
			Isolation: IsolationMacOSGuest,
			State:     StateUnavailable,
			Detail:    "no macOS VM/container shared connector transport is implemented",
		},
	}
}
