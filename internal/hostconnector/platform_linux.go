//go:build linux

package hostconnector

// NewPlatformBackend returns the Linux bridge implementor. The bridge remains
// unavailable until shieldapp supplies a typed isolation-boundary installer.
func NewPlatformBackend() Backend { return unavailableBackend{} }
