//go:build darwin

package shieldapp

import (
	"fmt"
	"strings"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
)

// generateSBProfileTunnel generates the Apple Seatbelt (sbpl) profile used
// when the agent is run under --tunnel on macOS (see startTunnelDarwin in
// tunnel_shield_darwin.go). It keeps every filesystem rule from
// generateSBProfileWithIPs (sensitive-path deny blocks + the allow
// carve-outs for paths/files the agent legitimately needs) unchanged, but
// replaces the network section entirely: instead of restricting outbound
// traffic to port 80/443 (port-only mode) or localhost-only (netproxy mode)
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

	// --- file-write* deny block (same contract as generateSBProfileWithIPs) ---
	sb.WriteString("(deny file-write*\n")
	for _, p := range sensitiveWritePaths(home) {
		fmt.Fprintf(&sb, "    (subpath %q)\n", p)
	}
	if cfg != nil {
		for _, p := range cfg.File.ExtraDeny {
			fmt.Fprintf(&sb, "    (subpath %q)\n", p)
		}
	}
	for _, rx := range sensitiveWriteRegexes() {
		fmt.Fprintf(&sb, "    (regex #\"%s\")\n", rx)
	}
	sb.WriteString(")\n")
	sb.WriteString("\n")

	// --- file-write* allow carve-outs (must appear AFTER the deny block;
	// sbpl is last-match-wins) --- same darwinWriteDenyOverrides guard as
	// generateSBProfileWithIPs: ~/.agentjail stays write-denied even though
	// it is in agentPaths().HomeRW, because it holds agentjail's own
	// enforcement state (policy.yaml, the SQLite DB).
	darwinWriteDenyOverrides := map[string]bool{
		".agentjail": true,
	}
	for _, name := range agentPaths().HomeRW {
		if darwinWriteDenyOverrides[name] {
			continue
		}
		fmt.Fprintf(&sb, "(allow file-write*\n    (subpath %q))\n", home+"/"+name)
	}
	sb.WriteString("\n")

	// --- file-read* deny block (credentials only) ---
	sb.WriteString("(deny file-read*\n")
	for _, p := range sensitiveReadPaths(home) {
		fmt.Fprintf(&sb, "    (subpath %q)\n", p)
	}
	for _, rx := range sensitiveReadRegexes() {
		fmt.Fprintf(&sb, "    (regex #\"%s\")\n", rx)
	}
	sb.WriteString(")\n")
	sb.WriteString("\n")

	// --- file-read* allow carve-outs (system trust stores + keychains) ---
	sb.WriteString("(allow file-read*\n")
	sb.WriteString("    (subpath \"/private/etc/ssl\"))\n")
	sb.WriteString("(allow file-read*\n")
	sb.WriteString("    (subpath \"/System/Library/Keychains\"))\n")
	sb.WriteString("(allow file-read*\n")
	sb.WriteString("    (subpath \"/Library/Keychains\"))\n")
	sb.WriteString("\n")

	// --- per-file read carve-outs from the shared contract (e.g. known_hosts) ---
	for _, g := range PerFileGrants() {
		if !g.PerFile || g.Mode != ReadOnly {
			continue
		}
		fmt.Fprintf(&sb, "(allow file-read*\n    (literal %q))\n", home+"/"+g.Path)
	}
	sb.WriteString("\n")
	appendCredentialMCPReadCapability(&sb, capabilities.CredentialMCPExecutable)

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
