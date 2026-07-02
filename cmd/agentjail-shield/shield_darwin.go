//go:build darwin

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/sandbox"
)

const sandboxExecPath = "/usr/bin/sandbox-exec"

// buildBaseEnv constructs the sandboxed agent's base environment: clean
// allowlist (sandbox.BuildCleanEnv) then defence-in-depth strip
// (sandbox.StripEnv), in that order.
//
// FIX1 (ADR 0039, security): prior to this fix, both runShield and execAgent
// called sandbox.StripEnv directly on hostEnv. StripEnv only removes names
// matching secrets.env_blocklist (a denylist) -- every OTHER host env var,
// including any ad-hoc, non-blocklisted secret a user had exported in their
// shell (e.g. `export MY_SECRET=...`), passed straight through to the
// sandboxed agent. BuildCleanEnv is the primary, allowlist-based defence
// (only known-safe variable names survive); StripEnv now runs as the
// second, defence-in-depth layer -- matching Linux's ordering in
// shield_linux.go. hostEnv is a parameter (not read internally via
// os.Environ()) so tests can inject a synthetic host environment and assert
// an arbitrary secret does not survive.
func buildBaseEnv(hostEnv []string, cfg *config.PolicyConfig) []string {
	env := sandbox.BuildCleanEnv(hostEnv, cfg)
	env = sandbox.StripEnv(env, cfg)
	return env
}

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
		home + "/.codex",
		home + "/.cursor",
		home + "/.docker",
		home + "/.kube",
		home + "/.cargo",
		// NOTE: ~/Library/Keychains is intentionally NOT write-denied here.
		// The shielded agent's own process needs its login keychain writable
		// so Claude Code auth/token-refresh works. NAMED per-OS exception --
		// no Linux analog (Linux Claude creds live in ~/.claude/.credentials.json,
		// already granted). See docs/adr/0037-macos-keychain-access-shielded-agent.md.
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
// FIX4 (ADR 0039): sourced from the shared contract's SensitiveFilePatterns()
// rather than a literal list duplicated in this file -- Linux names the
// filename-regex capability Unsupported (Landlock has no basename
// primitive) instead of faking it.
//
// Note: Apple sandbox-exec uses a non-standard regex engine that does not
// tolerate a literal '-' at the end of a bracket expression (e.g. [a-z0-9_-]).
// Use POSIX character classes ([[:alnum:]]) or omit the hyphen where possible.
func sensitiveWriteRegexes() []string {
	var out []string
	for _, p := range SensitiveFilePatterns() {
		if p.Write {
			out = append(out, p.Regex)
		}
	}
	return out
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
		// NOTE: ~/Library/Keychains is intentionally NOT read-denied here.
		// The shielded agent's own process needs its login keychain readable
		// so Claude Code auth/token-refresh works. NAMED per-OS exception --
		// no Linux analog (Linux Claude creds live in ~/.claude/.credentials.json,
		// already granted). See docs/adr/0037-macos-keychain-access-shielded-agent.md.
	}
}

// sensitiveReadRegexes returns sbpl regex patterns denied for reads.
//
// FIX4 (ADR 0039): sourced from the shared contract's SensitiveFilePatterns()
// -- see sensitiveWriteRegexes above.
func sensitiveReadRegexes() []string {
	var out []string
	for _, p := range SensitiveFilePatterns() {
		if p.Read {
			out = append(out, p.Regex)
		}
	}
	return out
}

// darwinCapabilities reports which shared-contract capabilities the darwin
// backend cannot fully honor, and why (FIX4, ADR 0039). CapFilenamePatternDeny
// is NOT listed here -- darwin fully honors it via sbpl (regex #"...") in
// both deny blocks (sensitiveWriteRegexes/sensitiveReadRegexes, sourced from
// SensitiveFilePatterns()). CapLoopbackScopedBind IS listed: Approach A
// (shipped, see the OAuth callback bind block in generateSBProfileWithIPs)
// binds `(local tcp "*:<port>")`, which is ANY-interface, not loopback-only.
// Approach B was attempted and measured NOT to enforce loopback-only either
// (see TestDarwinLoopbackScopedBindForm_NotEnforced) and
// `(local ip "127.0.0.1:*")` is rejected outright by sandbox-exec's parser
// ("host must be * or localhost"). No sbpl form was found that restricts a
// bind/inbound rule to the loopback interface only.
func darwinCapabilities() BackendCapability {
	return BackendCapability{
		Backend: "darwin",
		Unsupported: map[CapabilityKey]UnsupportedReason{
			CapLoopbackScopedBind: "sbpl (local tcp \"*:<port>\") binds any interface; " +
				"(local ip \"127.0.0.1:*\") is rejected by sandbox-exec (\"host must be * or localhost\") " +
				"and (local tcp \"localhost:*\") was measured to still allow 0.0.0.0 bind -- " +
				"no proven sbpl form restricts bind to loopback only",
		},
	}
}

// resolveAllowedHosts resolves each EXACT hostname in cfg.EffectiveAllowedHosts()
// (the non-removable essentials plus the editable Network.AllowedHosts) to
// its current IP addresses.  Failures are logged to stderr as warnings and the
// host is skipped — the launch is not aborted.
//
// Wildcard entries (e.g. "*.claude.ai", classified via config.ClassifyHost)
// are skipped WITHOUT attempting a lookup: net.LookupHost("*.claude.ai") can
// never succeed as a literal DNS name, so resolving it was pure "skipping"
// log noise on every launch. sbpl cannot enforce wildcard hosts by IP either
// way (this whole function is informational/best-effort for the sbpl layer;
// the real hostname-based enforcement point is netproxy) -- so nothing is
// lost by not attempting the doomed lookup.
//
// Returns a deduplicated list of IP address strings (e.g. "140.82.112.6").
// Loopback addresses are not included here; they are always allowed by the
// generated profile regardless.
func resolveAllowedHosts(cfg *config.PolicyConfig) []string {
	if cfg == nil {
		return nil
	}
	hosts := cfg.EffectiveAllowedHosts()
	if len(hosts) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	var ips []string
	for _, host := range hosts {
		hp := config.ClassifyHost(host)
		if hp.Wildcard {
			continue
		}
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

	// --- file-write* allow carve-outs (must appear AFTER the deny block) ---
	// sbpl uses LAST-MATCH-WINS ordering, so these allows take precedence over
	// the broad deny above for the specific paths the agent needs to write
	// (e.g. ~/.claude/session-env/<uuid>). Sourced from agentPaths().HomeRW so
	// this stays in lockstep with the Linux Landlock allowlist and never
	// re-introduces the write-deny-on-~/.claude regression.
	//
	// darwinWriteDenyOverrides lists HomeRW entries that must stay
	// write-denied on macOS even though Linux grants them read-write —
	// e.g. ~/.agentjail (daemon socket/DB/policy) stays in sensitiveWritePaths
	// above, so it must NOT get an allow carve-out here.
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

	// --- FIX3 (ADR 0039): per-file read carve-outs from the shared contract ---
	// The ~/.ssh subpath deny above (sensitiveReadPaths) blocks the whole
	// tree, including known_hosts, which the agent legitimately needs to
	// read for SSH host-key verification. Emit an explicit (allow
	// file-read* (literal ...)) for every ReadOnly PerFile grant in
	// PerFileGrants() AFTER the deny block (last-match-wins), same pattern as
	// the trust-store carve-outs above. Never emit file-write* here: adding a
	// new host key needs ~/.ssh directory write, which stays denied.
	for _, g := range PerFileGrants() {
		if !g.PerFile || g.Mode != ReadOnly {
			continue
		}
		fmt.Fprintf(&sb, "(allow file-read*\n    (literal %q))\n", home+"/"+g.Path)
	}
	sb.WriteString("\n")

	// AgentPaths.HomeRO / AgentPaths.Runtimes are consumed here only to keep
	// them wired against future drift protection (a future capability test
	// could assert their consumption). They are currently no-ops on darwin:
	// this profile is allow-by-default ((allow default) at the top), so
	// anything not explicitly denied -- including every HomeRO/Runtimes
	// path -- is already readable without an explicit carve-out. Do NOT
	// treat this loop as "enforced" the way the Linux allowlist enforces
	// HomeRO; it exists so a future change to the darwin base policy (e.g.
	// switching away from `(allow default)`) fails loudly instead of
	// silently losing these reads.
	_ = agentPaths().HomeRO
	_ = agentPaths().Runtimes

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
		// Port-only mode: allow outbound TCP on the shared fallback ports
		// (HTTPS 443, HTTP 80). FIX4 (ADR 0039): sourced from the contract's
		// NoNetproxyFallbackPorts() so this stays in lockstep with Linux's
		// --no-netproxy Landlock CONNECT restriction (shield_linux.go).
		// Note: sbpl cannot distinguish api.github.com from attacker.com at the
		// same port.  This is the documented Tier 1.5 limitation.
		for _, port := range NoNetproxyFallbackPorts() {
			fmt.Fprintf(&sb, "(allow network-outbound\n    (remote tcp \"*:%d\"))\n", port)
		}
		sb.WriteString("\n")
	}

	// --- FIX2 (ADR 0039): TCP bind for MCP OAuth redirect callbacks + local
	// IPC ---
	// Approach A (shipped): per resolved OAuth callback port, allow both
	// network-bind and network-inbound on that port. `(local tcp "*:<port>")`
	// binds ANY interface, NOT loopback-only -- sandbox-exec has no proven
	// sbpl form that restricts a bind to 127.0.0.1 only (see
	// shield_darwin_fixes_test.go TestDarwinLoopbackScopedBindForm_NotEnforced
	// and ADR 0039).
	// External inbound connections to these ports are still only reachable if
	// something outside the sandbox routes to the host, which is outside sbpl's
	// threat model; the sandbox boundary here is "the agent process may accept
	// a local OAuth redirect", not "this port is exposed to the network".
	//
	// Same practical limitation as Linux: a brand-new MCP connector's FIRST
	// OAuth flow may pick an unresolved ephemeral port (not yet in
	// ~/.claude/.credentials.json), so the very first auth for a new
	// connector may need one unshielded run.
	if home != "" {
		oauthPorts := resolveOAuthCallbackPorts(home + "/.claude/.credentials.json")
		for _, port := range oauthPorts {
			fmt.Fprintf(&sb, "(allow network-bind\n    (local tcp \"*:%d\"))\n", port)
			fmt.Fprintf(&sb, "(allow network-inbound\n    (local tcp \"*:%d\"))\n", port)
		}
		if len(oauthPorts) > 0 {
			sb.WriteString("\n")
		}
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
func runShield(cfg *config.PolicyConfig, agentPath string, agentArgs []string, profilePrint bool, noNetproxy bool, policyPath string, startTime time.Time, emitter audit.Emitter) {
	ctx := context.Background()
	_ = startTime // TODO: add startup timing + session summary to macOS shield
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
			// Fail-closed default (ADR 0041): netproxy was requested (no
			// --no-netproxy) but its binary could not be located. Aborting
			// here, rather than silently downgrading to port-only egress,
			// keeps "the shield is running" and "network.allowed_hosts is
			// enforced" from silently diverging.
			abortOnNetproxyFailure(ctx, emitter, fmt.Sprintf("could not locate agentjail-netproxy binary: %v", findErr))
		}
		cmd, startErr := startNetproxy(netproxyBin, netproxyDefaultAddr, policyPath)
		if startErr != nil {
			abortOnNetproxyFailure(ctx, emitter, fmt.Sprintf("could not start netproxy: %v", startErr))
		}
		netproxyCmd = cmd
		withNetproxy = true
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
		_ = emitter.Emit(ctx, audit.Event{
			EventType: audit.ShieldFailed,
			Detail:    map[string]string{"error": "sandbox-exec not found"},
			Actor:     "shield",
		})
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

	// Build the environment: clean allowlist + strip defence-in-depth + proxy
	// vars + granted secrets.
	env := buildBaseEnv(os.Environ(), cfg)
	env = append(env, "AGENTJAIL_SHIELDED=1")
	if withNetproxy {
		env = append(env, proxyEnvVars(netproxyDefaultAddr)...)
		fmt.Fprintf(os.Stderr, "agentjail-shield INFO: setting HTTPS_PROXY=http://%s (per-host enforcement via netproxy)\n", netproxyDefaultAddr)
	}
	grantEnvVars, _ := requestSecretGrants(cfg)
	env = append(env, grantEnvVars...)

	// Emit activation before exec — syscall.Exec replaces this process, so
	// this is the last chance to write to the audit log.
	_ = emitter.Emit(ctx, audit.Event{
		EventType: audit.ShieldActivated,
		Actor:     "shield",
	})

	// syscall.Exec replaces this process entirely.  If it returns, it failed.
	if err := syscall.Exec(sandboxExecPath, argv, env); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail-shield: exec sandbox-exec failed: %v\n", err)
		os.Exit(1)
	}
}

// execAgent execs the agent directly (no sandbox) — used when sandbox-exec
// is absent (fail-open path).  Env stripping still applies.
func execAgent(cfg *config.PolicyConfig, agentPath string, agentArgs []string, withNetproxy bool) {
	// FIX1 (ADR 0039): same clean-then-strip ordering as runShield's sandbox
	// path -- the fail-open fallback must not leak a broader environment
	// than the sandboxed path does.
	env := buildBaseEnv(os.Environ(), cfg)
	env = append(env, "AGENTJAIL_SHIELDED=1")
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
