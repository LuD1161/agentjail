//go:build darwin

package shieldapp

import (
	"strings"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
)

// generateSBProfileTunnel generates the Apple Seatbelt (sbpl) profile used
// when the agent is run under --tunnel on macOS (see startTunnelDarwin in
// tunnel_shield_darwin.go). It shares the ordinary profile's filesystem
// renderer, but replaces the network section entirely: instead of restricting
// outbound traffic to port 80/443 (port-only mode) or localhost-only (netproxy mode)
// and finishing with a catch-all (deny network*), it allows broad outbound
// networking with no final deny.
//
// This is deliberate, not a regression: under --tunnel, enforcement moves
// from sbpl to the NETransparentProxyProvider system extension + in-process
// tunnel.Gateway, which intercepts flows at the OS network-extension layer
// (matched by PPID ancestry back to the registered agentjail-shield PID) and
// evaluates them against the netpolicy packs loaded into the gateway. If
// sbpl kept its normal port/host restriction here, the agent's SSH/DB/other
// non-80/443 connection attempts would be denied at the sandbox boundary
// before they ever reached the kernel's flow-interception point, so the
// sysext would never see - and therefore never police - that traffic.
//
// Unlike the rescue original (dns-blackhole-fix tag), this takes no CA-key
// path parameter: the tunnel CA is generated in memory (mitm.GenerateCAInMemory)
// and its private key is never written to disk, so there is no root.key file
// on this or any other path that needs an explicit read-deny. See
// tunnel_shield_darwin.go's startTunnelDarwin.
func generateSBProfileTunnel(cfg *config.PolicyConfig, home string) string {
	return generateSBProfileTunnelWithCapabilities(cfg, home, darwinProfileCapabilities{})
}

func generateSBProfileTunnelWithCapabilities(cfg *config.PolicyConfig, home string, capabilities darwinProfileCapabilities) string {
	var sb strings.Builder

	sb.WriteString("(version 1)\n")
	sb.WriteString("(allow default)\n")
	sb.WriteString("\n")
	appendDarwinFilesystemProfile(&sb, cfg, home, capabilities)

	// --- network egress: broad allow (tunnel mode) ---
	// Every outbound connection attempt must actually leave the process so
	// the NETransparentProxyProvider extension can intercept and police it.
	// There is no port/host restriction and no final (deny network*) --
	// enforcement now lives in the sysext + gateway's netpolicy packs, not
	// sbpl. network-bind/network-inbound are also allowed broadly so the
	// agent can still do ordinary local things (bind an ephemeral UDP port
	// for its own DNS resolution, accept an MCP OAuth redirect callback,
	// etc.) without needing the narrow per-port carve-outs the non-tunnel
	// profile requires.
	sb.WriteString("(allow network-outbound)\n")
	sb.WriteString("(allow network-bind)\n")
	sb.WriteString("(allow network-inbound)\n")

	return sb.String()
}
