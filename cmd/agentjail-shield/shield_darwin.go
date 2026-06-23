//go:build darwin

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
)

const sandboxExecPath = "/usr/bin/sandbox-exec"

// sensitiveWritePaths returns the baseline set of paths that should be denied
// for writes.  This mirrors the is_sensitive_path predicates in
// agentpolicy/policies/file_policy.rego — both lists must be kept in sync.
//
// Uses the real home directory for ~/ expansion.
func sensitiveWritePaths(home string) []string {
	return []string{
		home + "/.ssh",
		home + "/.aws",
		home + "/.gnupg",
		home + "/.config",
		home + "/.agentjail",
		home + "/.claude",
		home + "/.codex",
		home + "/.cursor",
		home + "/.docker",
		home + "/.kube",
		home + "/.cargo",
		home + "/Library/Keychains",
		home + "/Downloads",
		home + "/Desktop",
		"/etc",
		"/private/etc",
		"/var",
		"/private/var",
	}
}

// sensitiveWriteRegexes returns sbpl regex patterns for file extensions /
// basename patterns that should also be denied for writes.
//
// Note: Apple sandbox-exec uses a non-standard regex engine that does not
// tolerate a literal '-' at the end of a bracket expression (e.g. [a-z0-9_-]).
// Use POSIX character classes ([[:alnum:]]) or omit the hyphen where possible.
func sensitiveWriteRegexes() []string {
	return []string{
		// .env, .env.local, .env.production, etc.
		// Intentionally omits hyphen in char class to stay sandbox-exec-compatible.
		`\.env(\.[a-zA-Z0-9_]+)?$`,
		`(^|/)\.envrc$`,
		`\.(pem|p12|pfx|jks|keystore|key)$`,
		`(^|/)id_(rsa|ed25519|ecdsa|dsa)$`,
		`(^|/)credentials$`,
		`(^|/)secrets$`,
		`(^|/)\.netrc$`,
		// Anchored home-file patterns: exact-match only ($ prevents catching .npmrc.bak).
		// These match only the home-anchored forms; project-local .npmrc is NOT caught
		// because the subpath entries above only block under ~/.docker, ~/.kube, ~/.cargo.
		`/Users/[^/]+/\.npmrc$`,
		`/Users/[^/]+/\.pypirc$`,
		`/Users/[^/]+/\.git-credentials$`,
		// Protect agentjail daemon/shield plists from being overwritten
		`/Users/[^/]+/Library/LaunchAgents/com\.agentjail\.`,
	}
}

// sensitiveReadPaths returns the subset of sensitive paths that should also
// be denied for reads (private keys, credential stores).
func sensitiveReadPaths(home string) []string {
	return []string{
		home + "/.ssh",
		home + "/.aws",
		home + "/.gnupg",
		home + "/.agentjail",
		home + "/.docker",
		home + "/.kube",
		home + "/Library/Keychains",
	}
}

// sensitiveReadRegexes returns sbpl regex patterns denied for reads.
func sensitiveReadRegexes() []string {
	return []string{
		`(^|/)id_(rsa|ed25519|ecdsa|dsa)$`,
		`\.(pem|p12|pfx|jks|keystore|key)$`,
		`(^|/)credentials$`,
		`(^|/)\.netrc$`,
		// Anchored home-file patterns: exact-match only ($ prevents catching .npmrc.bak).
		`/Users/[^/]+/\.npmrc$`,
		`/Users/[^/]+/\.pypirc$`,
		`/Users/[^/]+/\.git-credentials$`,
	}
}

// resolveAllowedHosts resolves each hostname in cfg.Network.AllowedHosts to
// its current IP addresses.  Failures are logged to stderr as warnings and the
// host is skipped — the launch is not aborted.
//
// Returns a deduplicated list of IP address strings (e.g. "140.82.112.6").
// Loopback addresses are not included here; they are always allowed by the
// generated profile regardless.
func resolveAllowedHosts(cfg *config.PolicyConfig) []string {
	if cfg == nil || len(cfg.Network.AllowedHosts) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	var ips []string
	for _, host := range cfg.Network.AllowedHosts {
		addrs, err := net.LookupHost(host)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentjail-shield INFO: could not resolve %s: %v — skipping\n", host, err)
			continue
		}
		for _, addr := range addrs {
			ip := net.ParseIP(addr)
			if ip == nil {
				continue
			}
			// Normalise to string representation; skip loopback (always allowed separately).
			ipStr := ip.String()
			if ip.IsLoopback() {
				continue
			}
			if _, dup := seen[ipStr]; !dup {
				seen[ipStr] = struct{}{}
				ips = append(ips, ipStr)
				fmt.Fprintf(os.Stderr, "agentjail-shield INFO: resolving allowed_hosts: %s → %s\n", host, ipStr)
			}
		}
	}
	return ips
}

// generateSBProfile generates an Apple Seatbelt (sbpl) profile that:
//   - allows everything by default (permissive base)
//   - denies file-write* on baseline sensitive paths
//   - denies file-read* on credential / key paths
//   - denies all network* traffic by default
//   - when withNetproxy=true: allows only localhost outbound (the proxy)
//   - when withNetproxy=false: allows outbound TCP on 443/80 (port-only mode)
//   - always allows DNS (UDP 53) and loopback (127.0.0.1, ::1)
//
// cfg.File.ExtraDeny entries are appended to the write-deny subpath list.
// allowedIPs is informational only (sbpl cannot enforce per-IP); they are
// logged at startup for audit visibility.
func generateSBProfile(cfg *config.PolicyConfig, home string) string {
	return generateSBProfileWithIPs(cfg, home, resolveAllowedHosts(cfg), false)
}

// generateSBProfileWithNetproxy is the version used when netproxy is active.
// It omits the wildcard-443/80 rules; only localhost is allowed outbound so
// all traffic must flow through the proxy.
func generateSBProfileWithNetproxy(cfg *config.PolicyConfig, home string) string {
	return generateSBProfileWithIPs(cfg, home, resolveAllowedHosts(cfg), true)
}

// generateSBProfileWithIPs is the inner generator used by generateSBProfile
// and directly by tests (which supply their own IP list for determinism).
func generateSBProfileWithIPs(cfg *config.PolicyConfig, home string, allowedIPs []string, withNetproxy bool) string {
	var sb strings.Builder

	sb.WriteString("(version 1)\n")
	sb.WriteString("(allow default)\n")
	sb.WriteString("\n")

	// --- file-write* deny block ---
	sb.WriteString("(deny file-write*\n")
	for _, p := range sensitiveWritePaths(home) {
		fmt.Fprintf(&sb, "    (subpath %q)\n", p)
	}
	// ExtraDeny from policy.yaml
	if cfg != nil {
		for _, p := range cfg.File.ExtraDeny {
			fmt.Fprintf(&sb, "    (subpath %q)\n", p)
		}
	}
	for _, rx := range sensitiveWriteRegexes() {
		// sbpl regex syntax: (regex #"pattern") — the pattern is a raw regex,
		// NOT a Go %q-escaped string.  We wrap in #"..." without extra quoting.
		fmt.Fprintf(&sb, "    (regex #\"%s\")\n", rx)
	}
	sb.WriteString(")\n")
	sb.WriteString("\n")

	// --- file-read* deny block (credentials only) ---
	// Important: sbpl uses LAST-MATCH-WINS ordering (not first-match).
	// The carve-out allows for system trust stores appear AFTER this deny block
	// so they take precedence over the broad .pem regex.
	sb.WriteString("(deny file-read*\n")
	for _, p := range sensitiveReadPaths(home) {
		fmt.Fprintf(&sb, "    (subpath %q)\n", p)
	}
	for _, rx := range sensitiveReadRegexes() {
		fmt.Fprintf(&sb, "    (regex #\"%s\")\n", rx)
	}
	sb.WriteString(")\n")
	sb.WriteString("\n")

	// --- file-read* allow carve-outs (must appear AFTER the deny block) ---
	// sbpl uses LAST-MATCH-WINS ordering.  The sensitiveReadRegexes include
	// \.(pem|...) to block private key reads, but that regex also matches
	// macOS system CA bundles (e.g. /etc/ssl/cert.pem → /private/etc/ssl/cert.pem).
	// Without these carve-outs, HTTPS connections inside the sandbox fail
	// because curl/libssl cannot load TLS certificate chains from the system trust store.
	//
	// These allow rules run AFTER the deny, so last-match-wins gives them priority
	// over the broad .pem regex deny for system trust store paths only.
	sb.WriteString("(allow file-read*\n")
	sb.WriteString("    (subpath \"/private/etc/ssl\"))\n")
	sb.WriteString("(allow file-read*\n")
	sb.WriteString("    (subpath \"/System/Library/Keychains\"))\n")
	sb.WriteString("(allow file-read*\n")
	sb.WriteString("    (subpath \"/Library/Keychains\"))\n")
	sb.WriteString("\n")

	// --- network egress block ---
	if withNetproxy {
		// Netproxy mode: agent may only reach localhost (where the proxy lives).
		// All HTTPS traffic must flow through agentjail-netproxy which enforces
		// network.allowed_hosts.  Non-HTTPS-CONNECT clients (raw sockets, gRPC
		// over h2 without proxy support) will fail — safer default than allow.
		//
		// We still need:
		//   * mDNSResponder socket: the proxy itself needs DNS resolution.
		//   * UDP 53: raw DNS resolvers (nslookup, dig).
		//   * localhost: where the proxy is listening.
		//
		// We do NOT emit the wildcard *:443 / *:80 rules.
		if len(allowedIPs) > 0 {
			fmt.Fprintf(os.Stderr, "agentjail-shield INFO: %d IPs resolved for allowed_hosts (enforced via netproxy; sbpl restricts agent to localhost only)\n", len(allowedIPs))
		}
	} else {
		// Port-only mode (--no-netproxy): inform that host-level filtering is absent.
		// Apple Seatbelt (sbpl) limitation: the (remote tcp/udp "HOST:PORT") filter
		// only accepts "*" or "localhost" as the HOST component.  Literal IP
		// addresses are rejected by sandbox-exec.
		// Consequence: sbpl cannot enforce host-level (IP-based) egress filtering.
		if len(allowedIPs) > 0 {
			fmt.Fprintf(os.Stderr, "agentjail-shield INFO: %d IPs resolved for allowed_hosts (informational; sbpl enforces port-based rules only — use netproxy for per-host enforcement)\n", len(allowedIPs))
		}
	}

	// Always allow the mDNSResponder Unix socket — required for DNS on macOS.
	sb.WriteString("(allow network-outbound\n")
	sb.WriteString("    (literal \"/private/var/run/mDNSResponder\"))\n")
	sb.WriteString("\n")

	// Always allow DNS (UDP port 53 to any remote address).
	sb.WriteString("(allow network-outbound\n")
	sb.WriteString("    (remote udp \"*:53\"))\n")
	sb.WriteString("\n")

	// Allow DNS clients (nslookup, dig, etc.) to bind a local UDP port and
	// receive DNS replies.  Without this, only apps using the mDNSResponder
	// socket (curl, Python) can do DNS; raw UDP resolvers fail.
	sb.WriteString("(allow network-bind\n")
	sb.WriteString("    (local udp \"*:*\"))\n")
	sb.WriteString("(allow network-inbound\n")
	sb.WriteString("    (local udp \"*:*\"))\n")
	sb.WriteString("\n")

	// Always allow loopback via IP-name "localhost" (sbpl accepts "localhost" as host).
	// When netproxy is active, the agent uses this to reach agentjail-netproxy.
	sb.WriteString("(allow network-outbound\n")
	sb.WriteString("    (remote ip \"localhost:*\"))\n")
	sb.WriteString("\n")

	if !withNetproxy {
		// Port-only mode: allow outbound TCP on HTTPS (443) and HTTP (80).
		// Note: sbpl cannot distinguish api.github.com from attacker.com at the
		// same port.  This is the documented Tier 1.5 limitation.
		sb.WriteString("(allow network-outbound\n")
		sb.WriteString("    (remote tcp \"*:443\"))\n")
		sb.WriteString("(allow network-outbound\n")
		sb.WriteString("    (remote tcp \"*:80\"))\n")
		sb.WriteString("\n")
	}

	// Default deny for all remaining network traffic.
	// This blocks: C2 on non-standard ports (4444, 8888, etc.), raw IP/ICMP
	// exfil, non-DNS UDP, arbitrary TCP on unlisted ports.
	sb.WriteString("(deny network*)\n")

	return sb.String()
}

// runShield is the macOS implementation of the shield launcher.
//
// When noNetproxy is false (the default):
//  1. Locate agentjail-netproxy binary.
//  2. Start it as a child process on 127.0.0.1:9100.
//  3. Generate an sbpl profile that restricts the agent to localhost-only
//     outbound TCP (no wildcard *:443 / *:80 rules).
//  4. Set HTTPS_PROXY / HTTP_PROXY / ALL_PROXY in the agent's environment.
//  5. exec the agent via sandbox-exec.
//  6. (On exit) SIGTERM the netproxy child (best-effort; shield uses syscall.Exec
//     so cleanup is done via a defer before exec).
//
// When noNetproxy is true: fall back to port-based filtering.
//
// It generates a Seatbelt sbpl profile from the policy config and execs
// /usr/bin/sandbox-exec with -p <inline-profile> <agent-cmd> <args...>.
//
// The sandbox is applied before execve, so the process and all its
// descendants inherit the restrictions — no hook bypass is possible.
func runShield(cfg *config.PolicyConfig, agentPath string, agentArgs []string, profilePrint bool, noNetproxy bool, policyPath string) {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail-shield: could not determine home directory: %v\n", err)
		home = "/Users/unknown"
	}

	var netproxyCmd *exec.Cmd
	withNetproxy := false

	if !noNetproxy {
		netproxyBin, findErr := findNetproxyBinary()
		if findErr != nil {
			fmt.Fprintf(os.Stderr,
				"agentjail-shield WARNING: %v\n"+
					"  Falling back to port-based network filtering (no per-host enforcement).\n"+
					"  Use --no-netproxy to suppress this warning.\n",
				findErr,
			)
		} else {
			cmd, startErr := startNetproxy(netproxyBin, netproxyDefaultAddr, policyPath)
			if startErr != nil {
				fmt.Fprintf(os.Stderr,
					"agentjail-shield WARNING: could not start netproxy: %v\n"+
						"  Falling back to port-based network filtering.\n",
					startErr,
				)
			} else {
				netproxyCmd = cmd
				withNetproxy = true
			}
		}
	}

	// Generate sbpl profile.
	var profile string
	if withNetproxy {
		profile = generateSBProfileWithNetproxy(cfg, home)
	} else {
		profile = generateSBProfile(cfg, home)
	}

	if profilePrint {
		fmt.Fprintf(os.Stderr, "=== agentjail-shield: generated sbpl profile ===\n")
		fmt.Fprint(os.Stderr, profile)
		fmt.Fprintf(os.Stderr, "=================================================\n")
		if netproxyCmd != nil {
			_ = netproxyCmd.Process.Kill()
		}
		os.Exit(0)
	}

	// Kill netproxy child before we exec (syscall.Exec replaces this process,
	// so defer runs here but not after exec).
	if netproxyCmd != nil {
		defer func() {
			_ = netproxyCmd.Process.Signal(syscall.SIGTERM)
		}()
	}

	// Verify sandbox-exec is present.
	if _, statErr := os.Stat(sandboxExecPath); statErr != nil {
		fmt.Fprintf(os.Stderr,
			"agentjail-shield WARNING: %s not found — sandbox enforcement is DISABLED on this system.\n"+
				"  The hook layer (agentjail-hook) still runs on every PreToolUse call.\n"+
				"  Please file an issue at https://github.com/LuD1161/agentjail/issues.\n",
			sandboxExecPath,
		)
		execAgent(cfg, agentPath, agentArgs, withNetproxy)
		return
	}

	// Build the argv for sandbox-exec:
	//   /usr/bin/sandbox-exec -p <profile> <agent-path> [agent-args...]
	argv := make([]string, 0, 3+1+len(agentArgs))
	argv = append(argv, sandboxExecPath)
	argv = append(argv, "-p", profile)
	argv = append(argv, agentPath)
	argv = append(argv, agentArgs...)

	// Build the environment: inherit everything + strip ambient creds + set proxy vars + granted secrets.
	env := stripEnv(os.Environ(), cfg)
	if withNetproxy {
		env = append(env, proxyEnvVars(netproxyDefaultAddr)...)
		fmt.Fprintf(os.Stderr, "agentjail-shield INFO: setting HTTPS_PROXY=http://%s (per-host enforcement via netproxy)\n", netproxyDefaultAddr)
	}
	grantEnvVars, _ := requestSecretGrants(cfg)
	env = append(env, grantEnvVars...)

	// syscall.Exec replaces this process entirely.  If it returns, it failed.
	if err := syscall.Exec(sandboxExecPath, argv, env); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail-shield: exec sandbox-exec failed: %v\n", err)
		os.Exit(1)
	}
}

// execAgent execs the agent directly (no sandbox) — used when sandbox-exec
// is absent (fail-open path).  Env stripping still applies.
func execAgent(cfg *config.PolicyConfig, agentPath string, agentArgs []string, withNetproxy bool) {
	env := stripEnv(os.Environ(), cfg)
	if withNetproxy {
		env = append(env, proxyEnvVars(netproxyDefaultAddr)...)
	}
	grantEnvVars, _ := requestSecretGrants(cfg)
	env = append(env, grantEnvVars...)
	argv := append([]string{agentPath}, agentArgs...)
	if err := syscall.Exec(agentPath, argv, env); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail-shield: exec agent failed: %v\n", err)
		os.Exit(1)
	}
}
