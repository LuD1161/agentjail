//go:build darwin

package shieldapp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/ctlauth"
	"github.com/LuD1161/agentjail/internal/mitm"
	"github.com/LuD1161/agentjail/internal/proxyctl"
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
	env = sandbox.RemoveEnvKeys(env, "GIT_SSH_COMMAND", "AGENTJAIL_SSH_OVERRIDE")
	env = append(env, sandbox.AgentGitSSHEnv(os.Getenv)...)
	return env
}

// sensitiveWritePaths returns the baseline set of paths that should be denied
// for writes.  This mirrors the is_sensitive_path predicates in
// agentpolicy/policies/file_policy.rego — both lists must be kept in sync.
//
// The .ssh/.aws/.gnupg entries are sourced from the shared
// SensitiveMCPCommandDirs() contract (P3) rather than re-listed here, so
// Linux's MCP-command-path check and darwin's deny list can never drift.
//
// Uses the real home directory for ~/ expansion.
func sensitiveWritePaths(home string) []string {
	paths := []string{home + "/.config", home + "/.agentjail"}
	for _, d := range SensitiveMCPCommandDirs() {
		paths = append(paths, home+"/"+d)
	}
	return append(paths, sensitiveWritePathsExtra(home)...)
}

// sensitiveWritePathsExtra lists write-deny paths beyond the shared
// SensitiveMCPCommandDirs contract set -- entries with no Linux analog
// (Landlock's allowlist never grants them in the first place) or that are
// darwin-specific hardening.
func sensitiveWritePathsExtra(home string) []string {
	return []string{
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
//
// The .ssh/.aws/.gnupg entries are sourced from the shared
// SensitiveMCPCommandDirs() contract (P3) -- see sensitiveWritePaths above.
// The ~/.config/{gh,gcloud,containers,...} entries are sourced from the
// shared ConfigCredentialSubdirs() contract (P4): unlike Linux, which grants
// ~/.config child-by-child to exclude these, darwin's ~/.config is not in
// this deny list (it stays readable via (allow default) for legitimate MCP
// configs) so these specific credential-bearing children must be denied
// individually here instead.
// NOTE: ~/Library/Keychains is intentionally NOT read-denied here.
// The shielded agent's own process needs its login keychain readable
// so Claude Code auth/token-refresh works. NAMED per-OS exception --
// no Linux analog (Linux Claude creds live in ~/.claude/.credentials.json,
// already granted). See docs/adr/0037-macos-keychain-access-shielded-agent.md.
func sensitiveReadPaths(home string) []string {
	paths := []string{home + "/.agentjail", home + "/.docker", home + "/.kube"}
	for _, d := range SensitiveMCPCommandDirs() {
		paths = append(paths, home+"/"+d)
	}
	for _, d := range ConfigCredentialSubdirs() {
		paths = append(paths, home+"/.config/"+d)
	}
	return paths
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

// darwinTempDirRegex matches the macOS per-user temp directory shape:
// /var/folders/<xx>/<yyy>/T or its canonical /private/var/folders/<xx>/<yyy>/T
// form. Exactly two opaque path segments between "folders" and "T" -- no
// more (a subpath under T, e.g. .../T/sub) and no fewer (a malformed or
// truncated path).
var darwinTempDirRegex = regexp.MustCompile(`^/(private/)?var/folders/[^/]+/[^/]+/T$`)

// validateDarwinTempDir validates a candidate TMPDIR path against
// darwinTempDirRegex and, on a match, returns BOTH the canonical
// (/private/var/folders/...) and symlink (/var/folders/...) forms -- sbpl
// matches the canonical path, but callers may pass either form, so both must
// be present in the profile.  Deduped if identical.
//
// Returns nil (no carve-out -- fail closed to the pre-fix behavior of
// denying all of /var and /private/var for writes) if t does not match the
// expected shape: TMPDIR unset (os.TempDir() then defaults to /tmp),
// TMPDIR overridden to an arbitrary path (e.g. /Users/me), a malformed
// /var/folders path (e.g. missing the trailing T, or /var/folders alone),
// or a subpath below T (e.g. .../T/sub -- only the T directory itself is
// carved out, never a descendant).
//
// Factored out of darwinUserTempDirs as a pure function (no os.TempDir()
// call) so it can be table-tested without depending on process environment.
func validateDarwinTempDir(t string) []string {
	t = filepath.Clean(t)
	if !darwinTempDirRegex.MatchString(t) {
		return nil
	}
	var canonical, symlink string
	if strings.HasPrefix(t, "/private") {
		canonical = t
		symlink = strings.TrimPrefix(t, "/private")
	} else {
		symlink = t
		canonical = "/private" + t
	}
	if canonical == symlink {
		return []string{canonical}
	}
	return []string{canonical, symlink}
}

// darwinUserTempDirs returns the per-user macOS temp directory (os.TempDir(),
// e.g. /var/folders/xx/yyy/T -- what $TMPDIR points to) in both its
// canonical /private/... form and symlink form, for use as a narrow
// file-write and AF_UNIX bind/connect carve-out (see generateSBProfileWithIPs).
// Returns nil if os.TempDir() does not match the expected per-user T
// directory shape -- see validateDarwinTempDir.
func darwinUserTempDirs() []string {
	return validateDarwinTempDir(os.TempDir())
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
			CapMetadataIPFilter: "sbpl (remote tcp/ip \"HOST:PORT\") rejects literal IP hosts -- only \"*\" and " +
				"\"localhost\" are accepted by sandbox-exec -- so the port-only fallback's *:80/*:443 allow " +
				"rules cannot carve out a deny for 169.254.169.254; mitigated by the launch-time " +
				"decideMetadataEgress guard in main.go instead (ADR 0049)",
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
// Lookups run concurrently (bounded, see dnsResolveConcurrency in
// shield_dnsresolve.go) with a per-host timeout and an overall batch
// deadline, so one slow or unreachable DNS name cannot stall the whole
// shield launch -- previously this loop called net.LookupHost serially with
// no timeout, so a single hanging name blocked every subsequent host and,
// transitively, `/mcp` and general startup.
//
// Returns a deduplicated, sorted list of IP address strings (e.g.
// "140.82.112.6"), so the generated profile is reproducible across runs
// regardless of lookup completion order. Loopback addresses are not
// included here; they are always allowed by the generated profile
// regardless.
func resolveAllowedHosts(cfg *config.PolicyConfig) []string {
	if cfg == nil {
		return nil
	}
	hosts := cfg.EffectiveAllowedHosts()
	if len(hosts) == 0 {
		return nil
	}
	var exact []string
	for _, host := range hosts {
		hp := config.ClassifyHost(host)
		if hp.Wildcard {
			continue
		}
		exact = append(exact, host)
	}
	if len(exact) == 0 {
		return nil
	}

	resolver := &net.Resolver{}
	lookup := func(ctx context.Context, host string) ([]string, error) {
		addrs, err := resolver.LookupHost(ctx, host)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentjail-shield INFO: could not resolve %s: %v — skipping\n", host, err)
		}
		return addrs, err
	}
	onResolved := func(host, ip string) {
		fmt.Fprintf(os.Stderr, "agentjail-shield INFO: resolving allowed_hosts: %s → %s\n", host, ip)
	}
	return resolveHostsToIPs(exact, lookup, onResolved)
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
	//
	// NOTE: ~/.agentjail is no longer in HomeRW (it moved to HomeRO, and its
	// daemon.sock HomeFilesRW grant was dropped as a measured no-op -- see
	// shield_agentpaths.go), so this loop never encounters it today. The override entry is kept as
	// belt-and-suspenders: if ~/.agentjail is ever re-added to HomeRW, the
	// sbpl allow carve-out (last-match-wins) would otherwise override the
	// sensitiveWritePaths deny and silently re-grant the agent write access to
	// agentjail's own enforcement state. Do NOT remove without that guard.
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

	// --- darwin TMPDIR carve-out ---
	// $TMPDIR on macOS is a per-user directory under /var/folders/<xx>/<yyy>/T,
	// which sensitiveWritePathsExtra denies for writes via the broad /var and
	// /private/var subpath entries above (needed to block writes to
	// /private/etc, /private/var/db, etc.). That blanket deny also breaks any
	// tool that writes to TMPDIR (e.g. xcrun). Emit a narrow allow carve-out
	// for exactly the per-user T directory -- never the parent
	// /var/folders/<xx>/<yyy> root or its C (cache) sibling -- in both the
	// canonical /private/... form and the /var/... symlink form (sbpl
	// resolves to the canonical path, so both must be present for the
	// carve-out to apply regardless of which form a caller passes). This
	// must appear AFTER the /var deny block above (last-match-wins).
	// darwinUserTempDirs returns nil (no carve-out, fail closed) if TMPDIR
	// does not match the expected per-user T directory shape.
	for _, dir := range darwinUserTempDirs() {
		fmt.Fprintf(&sb, "(allow file-write*\n    (subpath %q))\n", dir)
	}
	sb.WriteString("\n")

	// --- file-read* deny block (credentials only) ---
	// Important: sbpl uses LAST-MATCH-WINS ordering (not first-match).
	// The carve-out allows for system trust stores appear AFTER this deny block
	// so they take precedence over the broad .pem regex.
	//
	// Precise rule, measured (AGE-216, test/sbpl-probe/) -- "last-match-wins"
	// alone is an incomplete model and misreads the network section below:
	//   - Among rules of the SAME specificity (both filtered, same target), the
	//     LAST one wins. That is what the carve-out pattern here relies on, and
	//     it is why a control-socket deny must be emitted after any allow that
	//     could name the same path.
	//   - An UNFILTERED catch-all (e.g. the trailing `(deny network*)`) does NOT
	//     override an earlier FILTERED allow. That is why the network allow-list
	//     below survives the catch-all instead of being dead rules -- and why the
	//     catch-all cannot be relied on to backstop a deny that some later allow
	//     has already overridden.
	// The two blocks look contradictory (denies first here, catch-all last there)
	// and are both correct, for these two different reasons.
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
		// Port-only mode (default; opt in to per-host enforcement with --netproxy):
		// inform that host-level filtering is absent.
		// Apple Seatbelt (sbpl) limitation: the (remote tcp/udp "HOST:PORT") filter
		// only accepts "*" or "localhost" as the HOST component.  Literal IP
		// addresses are rejected by sandbox-exec.
		// Consequence: sbpl cannot enforce host-level (IP-based) egress filtering.
		if len(allowedIPs) > 0 {
			fmt.Fprintf(os.Stderr, "agentjail-shield INFO: %d IPs resolved for allowed_hosts (informational; sbpl enforces port-based rules only -- pass --netproxy for per-host enforcement)\n", len(allowedIPs))
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

	// Control-socket denies are emitted last, not here: sbpl is last-match-wins
	// among same-specificity rules, so any later allow naming the same path would
	// win. See ADR 0067-control-plane-token-auth.

	// SSH agent socket: allow connect() to the ssh-agent listener so ssh can
	// authenticate via the agent (signing-only) without ever reading a private
	// key -- key files stay blocked by the file-read deny block above. Seatbelt
	// models AF_UNIX connect() as network-outbound, so this must be an explicit
	// allow BEFORE the (deny network*) catch-all. The path is runtime-dynamic
	// (macOS launchd agents live under /private/tmp/com.apple.launchd.*/Listeners);
	// it is read from SSH_AUTH_SOCK, which is passed through via
	// EnvAllowlistBaseline. See internal/sandbox/env.go. Linux needs no
	// equivalent allow: Landlock does not mediate AF_UNIX connect()
	// (ADR 0067-control-plane-token-auth).
	//
	// (path ...) is the canonical exact-match predicate for a unix-socket
	// destination (verified with sandbox-exec). The base is (allow default), so socket(2) creation is already
	// permitted -- unlike a (deny default) profile we do not also need
	// (allow system-socket (socket-domain AF_UNIX)).
	//
	// Fail closed on a control-socket path: such an allow would defeat both the
	// deny below and the (deny network*) catch-all.
	// See ADR 0067-control-plane-token-auth.
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if isControlSocketPath(sock, home) {
			fmt.Fprintf(os.Stderr,
				"agentjail-shield WARNING: SSH_AUTH_SOCK (%s) names an agentjail control socket -- refusing to emit an allow rule for it.\n", sock)
		} else {
			fmt.Fprintf(&sb, "(allow network-outbound\n    (path %q))\n\n", sock)
		}
	}

	// --- AF_UNIX sockets in temp dirs: bind broad, connect narrow ---
	// Seatbelt models AF_UNIX bind() as network-bind and AF_UNIX connect() as
	// network-outbound. Dev tooling (language servers, MCP stdio-over-socket
	// shims, xcrun helpers, etc.) routinely creates a Unix-domain socket under
	// /tmp or $TMPDIR and both binds AND connects to it locally; without an
	// explicit allow here those calls fail under the (deny network*) catch-all
	// below even though no real network egress is involved.
	//
	// Threat model, and why bind and connect get different treatment:
	//   - network-bind (listening on a socket) is allowed broadly across
	//     /tmp, /private/tmp, and the per-user T dir. Merely listening on a
	//     local socket in a shared temp directory does not let the sandboxed
	//     agent reach anything it could not already reach -- nothing outside
	//     the sandbox is obligated to connect to it.
	//   - network-outbound (connect) is allowed ONLY for the per-user T dir
	//     ($TMPDIR, e.g. /var/folders/<xx>/<yyy>/T), never for /tmp or
	//     /private/tmp. /tmp is world-writable: any other local process (or
	//     a malicious binary the agent itself wrote there) could plant a
	//     Unix-domain socket that acts as a proxy/agent shim, and an
	//     unrestricted connect-allow on /tmp would let the sandboxed agent
	//     use that shim to egress network traffic on its behalf, bypassing
	//     the network policy enforced above -- a shim-egress risk. The
	//     per-user T dir is created 0700 by the OS, so only processes
	//     running as the same user can plant a socket there, which is
	//     materially lower (though not zero) risk. Connects to sockets that
	//     live directly in /tmp or /private/tmp stay denied by the
	//     (deny network*) catch-all below.
	// darwinUserTempDirs returns nil (no carve-out) if TMPDIR does not match
	// the expected per-user T directory shape -- see validateDarwinTempDir.
	sb.WriteString("(allow network-bind\n    (subpath \"/private/tmp\"))\n")
	sb.WriteString("(allow network-bind\n    (subpath \"/tmp\"))\n")
	for _, dir := range darwinUserTempDirs() {
		fmt.Fprintf(&sb, "(allow network-bind\n    (subpath %q))\n", dir)
	}
	for _, dir := range darwinUserTempDirs() {
		fmt.Fprintf(&sb, "(allow network-outbound\n    (subpath %q))\n", dir)
	}
	sb.WriteString("\n")

	// Control-plane socket denies. MUST stay last: sbpl is last-match-wins among
	// same-specificity rules, and the unfiltered (deny network*) below does not
	// override an earlier filtered allow, so it cannot backstop these.
	// Defence-in-depth, not the boundary. See ADR 0067-control-plane-token-auth.
	for _, p := range ControlSocketPaths(home) {
		fmt.Fprintf(&sb, "(deny network-outbound\n    (literal %q))\n", p)
	}
	sb.WriteString("\n")

	// Default deny for all remaining network traffic.
	// This blocks: C2 on non-standard ports (4444, 8888, etc.), raw IP/ICMP
	// exfil, non-DNS UDP, arbitrary TCP on unlisted ports.
	sb.WriteString("(deny network*)\n")

	return sb.String()
}

// resolvePathBestEffort canonicalizes s as far as the filesystem allows.
//
// filepath.EvalSymlinks fails outright if the final path component does not
// exist yet -- the common case here, since a control socket is often named
// (e.g. via SSH_AUTH_SOCK, or a not-yet-bound listener path) before anything
// has bound it. A naive fallback to filepath.Clean(s) on that failure leaves
// two gaps this function closes: it does not resolve a symlinked ancestor
// directory (e.g. /tmp -> /private/tmp on macOS) that appears earlier in the
// path than the missing component, and it never canonicalizes at all once
// EvalSymlinks fails once.
//
// Instead, this walks up from s to the deepest EXISTING ancestor directory,
// resolves that ancestor's symlinks, and re-appends the (unresolved)
// remainder -- so a symlinked ancestor is always canonicalized even when the
// leaf does not exist. Falls back to filepath.Clean(s) only if no ancestor
// (down to the filesystem root) can be resolved.
//
// This is a fail-closed security guard (isControlSocketPath below), so it
// errs toward returning a MORE canonical -- not less -- form on any doubt.
func resolvePathBestEffort(s string) string {
	cur := filepath.Clean(s)
	var suffix string
	for {
		if resolved, err := filepath.EvalSymlinks(cur); err == nil {
			if suffix == "" {
				return filepath.Clean(resolved)
			}
			return filepath.Clean(filepath.Join(resolved, suffix))
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			// Reached the filesystem root without resolving anything.
			break
		}
		base := filepath.Base(cur)
		if suffix == "" {
			suffix = base
		} else {
			suffix = filepath.Join(base, suffix)
		}
		cur = parent
	}
	return filepath.Clean(s)
}

// isControlSocketPath reports whether p names an agentjail control-plane
// socket, or lives in the directory that holds them.
//
// Canonicalizes both p and each control-socket path via
// resolvePathBestEffort before comparing, so neither a symlinked ancestor
// (e.g. /tmp vs /private/tmp) nor an unclean path (trailing "..") nor a
// not-yet-bound socket (EvalSymlinks fails on a missing final component) can
// smuggle a control socket past the check. Errs toward "yes, it is a control
// socket" -- a false positive costs one ssh-agent allow, a false negative
// silently widens the control plane.
func isControlSocketPath(p, home string) bool {
	rp := resolvePathBestEffort(p)
	for _, c := range ControlSocketPaths(home) {
		if rp == resolvePathBestEffort(c) || filepath.Clean(p) == filepath.Clean(c) {
			return true
		}
	}
	// Anything inside the control-socket dir counts, even if not yet bound.
	ctlDir := resolvePathBestEffort(proxyctl.ControlSocketDirForHome(home))
	rel, err := filepath.Rel(ctlDir, rp)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
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
func runShield(cfg *config.PolicyConfig, agentPath string, agentArgs []string, profilePrint bool, noNetproxy bool, tunnelMode bool, mitmMode bool, policyPath string, startTime time.Time, emitter audit.Emitter) {
	// --tunnel dispatches entirely to the NETransparentProxyProvider path
	// (tunnel_shield_darwin.go). profilePrint is handled specially: rather
	// than stand up the sysext + gateway just to print a profile, print the
	// broad-allow tunnel profile (see generateSBProfileTunnel's doc comment
	// for why it differs from the non-tunnel profile) and exit, matching the
	// non-tunnel path's early profile-print exit below.
	if tunnelMode {
		if profilePrint {
			home, herr := os.UserHomeDir()
			if herr != nil {
				home = "/Users/unknown"
			}
			fmt.Fprintf(os.Stderr, "=== agentjail-shield: generated sbpl profile (tunnel mode) ===\n")
			fmt.Fprint(os.Stderr, generateSBProfileTunnel(cfg, home))
			fmt.Fprintf(os.Stderr, "=================================================\n")
			os.Exit(0)
		}
		ctx := context.Background()
		startTunnelDarwin(ctx, cfg, agentPath, agentArgs, resolveNetpacksDir(), mitmMode, emitter, func() {
			runShieldNoTunnel(cfg, agentPath, agentArgs, profilePrint, noNetproxy, policyPath, startTime, emitter)
		})
		// startTunnelDarwin either os.Exit's on success/fatal-error, or (on a
		// fail-open setup failure) invokes fallback above, which itself never
		// returns. Reachable only if that contract is violated; see
		// startTunnelDarwin's doc comment.
		return
	}
	runShieldNoTunnel(cfg, agentPath, agentArgs, profilePrint, noNetproxy, policyPath, startTime, emitter)
}

// runShieldNoTunnel is the non-tunnel (default) macOS launch path: sbpl +
// optional netproxy. Split out of runShield so --tunnel can dispatch to
// startTunnelDarwin instead, and so a fail-open tunnel setup failure can fall
// back into exactly this path. See runShield's doc comment above.
func runShieldNoTunnel(cfg *config.PolicyConfig, agentPath string, agentArgs []string, profilePrint bool, noNetproxy bool, policyPath string, startTime time.Time, emitter audit.Emitter) {
	ctx := context.Background()
	_ = startTime // TODO: add startup timing + session summary to macOS shield
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail-shield: could not determine home directory: %v\n", err)
		home = "/Users/unknown"
	}

	var netproxyCmd *exec.Cmd
	var sessionToken proxyctl.Token
	withNetproxy := false
	var netproxyBin string

	if !noNetproxy {
		var findErr error
		netproxyBin, findErr = findNetproxyBinary()
		if findErr != nil {
			// Fail-closed default (ADR 0041): netproxy was explicitly
			// requested (--netproxy) but its binary could not be located.
			// Aborting here, rather than silently downgrading to port-only egress,
			// keeps "the shield is running" and "network.allowed_hosts is
			// enforced" from silently diverging.
			abortOnNetproxyFailure(ctx, emitter, fmt.Sprintf("could not locate agentjail-netproxy binary: %v", findErr))
		}
		withNetproxy = true
	}

	// Generate sbpl profile. This only needs to know netproxy mode is active
	// (it emits the control-socket deny + localhost-only egress); it does not
	// need the proxy to be running yet, so we generate before starting it and
	// avoid spawning a proxy just to print the profile.
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
		os.Exit(0)
	}

	// Start + register this session with the (possibly shared) netproxy now --
	// after the profile-print early-exit, before exec. ensureSessionProxy runs
	// in the shield BEFORE the sandbox is applied via sandbox-exec, so it can
	// reach the control socket; the agent (post-exec) is denied it by the
	// (deny network-outbound (literal <control socket>)) rule in the profile.
	// Incompatible/unverifiable proxy -> fail closed inside ensureSessionProxy.
	if withNetproxy {
		shieldCwd, _ := os.Getwd()
		cmd, tok, startErr := ensureSessionProxy(netproxyBin, netproxyDefaultAddr, fmt.Sprintf("shield-%d", os.Getpid()), shieldCwd, resolveSessionPolicy(ctx, cfg, emitter))
		if startErr != nil {
			abortOnNetproxyFailure(ctx, emitter, fmt.Sprintf("could not start/register netproxy: %v", startErr))
		}
		netproxyCmd = cmd
		sessionToken = tok
	}

	// Kill netproxy child before we exec (syscall.Exec replaces this process,
	// so defer runs here but not after exec). nil when we reused a shared proxy.
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
		execAgent(ctx, cfg, agentPath, agentArgs, withNetproxy, sessionToken, emitter)
		return
	}

	// Build the environment: clean allowlist + strip defence-in-depth + proxy
	// vars + granted secrets.
	env := buildBaseEnv(os.Environ(), cfg)
	if sshOverrideInjected(env) {
		fmt.Fprintln(os.Stderr, "agentjail-shield INFO: injected agent-backed GIT_SSH_COMMAND (pinned IdentityFile blind spot workaround; set AGENTJAIL_NO_SSH_OVERRIDE=1 to opt out)")
	}
	env = AppendShieldedEnv(env, Sandboxed)
	if withNetproxy {
		env = append(env, proxyEnvVars(netproxyDefaultAddr, sessionToken)...)
		fmt.Fprintf(os.Stderr, "agentjail-shield INFO: setting HTTPS_PROXY=http://%s (per-session enforcement via netproxy)\n", netproxyDefaultAddr)
	}
	// Not yet sandboxed here (sbpl applies at syscall.Exec below), so the token
	// is readable at this point -- unlike Linux (ADR 0067).
	darwinCtlToken, _ := ctlauth.Load()
	grantEnvVars, _ := requestSecretGrants(cfg, darwinCtlToken)
	env = append(env, grantEnvVars...)

	// --- Provider capture gateway (A2): a registered provider agent with the
	// gateway enabled can no longer syscall.Exec -- an in-process gateway
	// needs a live parent -- so this spawns the agent as a child and waits,
	// mirroring --tunnel's process model exactly (same armSignalDrain, same
	// exit/signal mapping via startAndWaitChild). Fail-closed: a gateway/store
	// failure here refuses launch rather than falling back to uncaptured; the
	// only opt-out is --no-provider-gateway / network.capture_gateway:false.
	// See ADR 0109-baseurl-capture-gateway, A0-A2.
	sessionID := generateSessionID()
	prov, gwWanted := providerGatewayWanted(cfg, agentPath)
	if gwWanted {
		logger := slog.Default()
		store, storeErr := mitm.NewRequestStore(mitm.DefaultDBPath())
		if storeErr != nil {
			emitGatewayStartFailed(ctx, emitter, sessionID, prov, "store")
			fmt.Fprintf(os.Stderr, "agentjail-shield: capture gateway store open failed for %s: %v -- refusing to launch uncaptured (opt out with --no-provider-gateway)\n", prov.Name, storeErr)
			os.Exit(1)
		}
		rec := newBodyRecording(ctx, sessionID, logger, emitter)
		gwEnv, gwClose, started, gerr := startProviderGateway(ctx, cfg, agentPath, store, rec.store, sessionID, logger, emitter)
		if gerr != nil {
			_ = store.Close()
			fmt.Fprintf(os.Stderr, "agentjail-shield: %v -- refusing to launch uncaptured (opt out with --no-provider-gateway)\n", gerr)
			os.Exit(1)
		}
		if !started {
			// Defensive: providerGatewayWanted said yes but startProviderGateway
			// said no-op -- the two checks must never disagree silently.
			_ = store.Close()
			fmt.Fprintf(os.Stderr, "agentjail-shield: capture gateway unexpectedly did not start for %s -- refusing to launch uncaptured\n", prov.Name)
			os.Exit(1)
		}
		for k, v := range gwEnv {
			env = append(env, k+"="+v)
		}

		_ = emitter.Emit(ctx, audit.Event{
			EventType: audit.ShieldActivated,
			Actor:     "shield",
		})

		argv := append([]string{"-p", profile, agentPath}, agentArgs...)
		child := exec.Command(sandboxExecPath, argv...)
		child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
		child.Env = env

		stopSignalDrain := armSignalDrain(syscall.SIGINT, syscall.SIGTERM)
		exitCode := startAndWaitChild(child, logger)

		// CLEANUP: explicit + inline (NOT deferred -- defers are LIFO and do
		// not run under os.Exit), ordered: (1) stop the signal drain, (2)
		// close the provider gateway, (3) close the RequestStore, (4) signal
		// the netproxy child if one is running, (5) exit with the mapped
		// child status. See A2.
		stopSignalDrain()
		if gwClose != nil {
			_ = gwClose()
		}
		_ = store.Close()
		if netproxyCmd != nil {
			_ = netproxyCmd.Process.Signal(syscall.SIGTERM)
		}
		os.Exit(exitCode)
	}

	// --- No provider / gateway disabled: byte-identical to the pre-A2 path.
	// Build the argv for sandbox-exec:
	//   /usr/bin/sandbox-exec -p <profile> <agent-path> [agent-args...]
	argv := make([]string, 0, 3+1+len(agentArgs))
	argv = append(argv, sandboxExecPath)
	argv = append(argv, "-p", profile)
	argv = append(argv, agentPath)
	argv = append(argv, agentArgs...)

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
func execAgent(ctx context.Context, cfg *config.PolicyConfig, agentPath string, agentArgs []string, withNetproxy bool, sessionToken proxyctl.Token, emitter audit.Emitter) {
	// FIX1 (ADR 0039): same clean-then-strip ordering as runShield's sandbox
	// path -- the fail-open fallback must not leak a broader environment
	// than the sandboxed path does.
	env := buildBaseEnv(os.Environ(), cfg)
	if sshOverrideInjected(env) {
		fmt.Fprintln(os.Stderr, "agentjail-shield INFO: injected agent-backed GIT_SSH_COMMAND (pinned IdentityFile blind spot workaround; set AGENTJAIL_NO_SSH_OVERRIDE=1 to opt out)")
	}
	env = AppendShieldedEnv(env, NotSandboxed)
	if withNetproxy {
		env = append(env, proxyEnvVars(netproxyDefaultAddr, sessionToken)...)
	}
	// Unlike Linux, this process is not yet sandboxed -- the sbpl profile
	// applies at syscall.Exec below -- so the token can be read here (ADR 0067).
	darwinCtlToken, _ := ctlauth.Load()
	grantEnvVars, _ := requestSecretGrants(cfg, darwinCtlToken)
	env = append(env, grantEnvVars...)

	// --- Provider capture gateway (A5): same treatment as the sandboxed
	// spawn-and-wait path (A2), applied here too so capture is not silently
	// lost just because sandbox-exec is unavailable (fail-open path). See
	// ADR 0109-baseurl-capture-gateway.
	sessionID := generateSessionID()
	prov, gwWanted := providerGatewayWanted(cfg, agentPath)
	if gwWanted {
		logger := slog.Default()
		store, storeErr := mitm.NewRequestStore(mitm.DefaultDBPath())
		if storeErr != nil {
			emitGatewayStartFailed(ctx, emitter, sessionID, prov, "store")
			fmt.Fprintf(os.Stderr, "agentjail-shield: capture gateway store open failed for %s: %v -- refusing to launch uncaptured (opt out with --no-provider-gateway)\n", prov.Name, storeErr)
			os.Exit(1)
		}
		rec := newBodyRecording(ctx, sessionID, logger, emitter)
		gwEnv, gwClose, started, gerr := startProviderGateway(ctx, cfg, agentPath, store, rec.store, sessionID, logger, emitter)
		if gerr != nil {
			_ = store.Close()
			fmt.Fprintf(os.Stderr, "agentjail-shield: %v -- refusing to launch uncaptured (opt out with --no-provider-gateway)\n", gerr)
			os.Exit(1)
		}
		if !started {
			_ = store.Close()
			fmt.Fprintf(os.Stderr, "agentjail-shield: capture gateway unexpectedly did not start for %s -- refusing to launch uncaptured\n", prov.Name)
			os.Exit(1)
		}
		for k, v := range gwEnv {
			env = append(env, k+"="+v)
		}

		child := exec.Command(agentPath, agentArgs...)
		child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
		child.Env = env

		stopSignalDrain := armSignalDrain(syscall.SIGINT, syscall.SIGTERM)
		exitCode := startAndWaitChild(child, logger)

		// CLEANUP: explicit + inline, same order as the sandboxed path. See A2/A5.
		stopSignalDrain()
		if gwClose != nil {
			_ = gwClose()
		}
		_ = store.Close()
		os.Exit(exitCode)
	}

	argv := append([]string{agentPath}, agentArgs...)
	if err := syscall.Exec(agentPath, argv, env); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail-shield: exec agent failed: %v\n", err)
		os.Exit(1)
	}
}
