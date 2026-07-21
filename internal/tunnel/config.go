// Package tunnel provides a WireGuard tunnel gateway that uses gVisor netstack
// to intercept all agent TCP traffic in userspace, detect protocols, evaluate
// policy, and relay or deny connections.
package tunnel

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Config holds the WireGuard tunnel gateway configuration.
type Config struct {
	// PrivateKey is the gateway's WireGuard private key (base64-encoded, 32 bytes).
	PrivateKey string

	// ListenPort is the UDP port the WireGuard endpoint listens on.
	ListenPort int

	// PeerPublicKey is the agent-side WireGuard public key (base64-encoded).
	PeerPublicKey string

	// TunnelAddr is the gateway's address inside the tunnel, e.g. "10.78.0.1/16".
	TunnelAddr string

	// PacksDir is the directory containing policy template YAML files.
	PacksDir string

	// MTU is the tunnel MTU. Zero defaults to 1420.
	MTU int
}

// Validate checks Config fields for correctness.
func (c *Config) Validate() error {
	if c.PrivateKey == "" {
		return errors.New("tunnel: private key is required")
	}
	if err := validateKey(c.PrivateKey, device.NoisePrivateKeySize); err != nil {
		return fmt.Errorf("tunnel: invalid private key: %w", err)
	}

	// 0 is valid: it asks the OS for an ephemeral port. Gateway.ListenPort()
	// reads the actual bound port back from the WireGuard device after Up().
	if c.ListenPort < 0 || c.ListenPort > 65535 {
		return errors.New("tunnel: listen port must be 0-65535")
	}

	if c.PeerPublicKey == "" {
		return errors.New("tunnel: peer public key is required")
	}
	if err := validateKey(c.PeerPublicKey, device.NoisePublicKeySize); err != nil {
		return fmt.Errorf("tunnel: invalid peer public key: %w", err)
	}

	if c.TunnelAddr == "" {
		return errors.New("tunnel: tunnel address is required")
	}
	if _, err := netip.ParsePrefix(c.TunnelAddr); err != nil {
		return fmt.Errorf("tunnel: invalid tunnel address: %w", err)
	}

	return nil
}

// validateKey checks that s is a valid base64-encoded key of the expected size.
func validateKey(s string, size int) error {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("base64 decode: %w", err)
	}
	if len(b) != size {
		return fmt.Errorf("expected %d bytes, got %d", size, len(b))
	}
	return nil
}

// mtu returns the configured MTU or the default (1420).
func (c *Config) mtu() int {
	if c.MTU > 0 {
		return c.MTU
	}
	return device.DefaultMTU
}

// GenerateKeyPair returns a WireGuard private/public key pair as
// base64-encoded strings.
func GenerateKeyPair() (privateKey, publicKey string, err error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", "", fmt.Errorf("generate WG private key: %w", err)
	}
	return key.String(), key.PublicKey().String(), nil
}
