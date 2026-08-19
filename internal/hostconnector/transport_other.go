//go:build !linux && !darwin

package hostconnector

func platformTransportCapabilities() []TransportCapability {
	return []TransportCapability{
		{Isolation: IsolationSameHost, State: StateUnavailable, Detail: "unsupported operating system"},
		{Isolation: IsolationLinuxContainer, State: StateUnavailable, Detail: "unsupported operating system"},
		{Isolation: IsolationMicroVM, State: StateUnavailable, Detail: "unsupported operating system"},
		{Isolation: IsolationMacOSSandbox, State: StateUnavailable, Detail: "unsupported operating system"},
		{Isolation: IsolationMacOSGuest, State: StateUnavailable, Detail: "unsupported operating system"},
	}
}
