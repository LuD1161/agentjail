//go:build !linux && !darwin

package hostconnector

func NewPlatformBackend() Backend { return unavailableBackend{} }
