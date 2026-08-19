//go:build darwin

package hostconnector

// NewPlatformBackend returns the macOS bridge implementor. The bridge remains
// unavailable until shieldapp supplies a typed isolation-boundary installer.
func NewPlatformBackend() Backend { return unavailableBackend{} }
