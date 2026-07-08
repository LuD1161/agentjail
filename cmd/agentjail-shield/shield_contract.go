// Package main -- shared, tag-free sandbox contract.
//
// This file is the OS-agnostic source of truth for capabilities both shield
// backends (shield_darwin.go, shield_linux.go) must translate into their own
// enforcement primitive (Apple Seatbelt sbpl vs. Landlock).  Per ADR 0034 /
// ADR 0035: the contract is domain-shaped, typed Go -- never a bag of
// strings -- and backends adapt it, they do not redefine it.
//
// Where a backend genuinely cannot honor a capability (Landlock has no
// filename-regex primitive; neither backend has a proven loopback-only bind
// form), that gap is a NAMED UnsupportedReason, never a silent omission. See
// docs/adr/0039-complete-shared-sandbox-contract.md.
package main

import (
	"encoding/json"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
)

// AccessMode is the access level granted for a PathGrant.
type AccessMode int

const (
	// ReadOnly grants read access only.
	ReadOnly AccessMode = iota
	// ReadWrite grants read and write access.
	ReadWrite
)

func (m AccessMode) String() string {
	if m == ReadWrite {
		return "read-write"
	}
	return "read-only"
}

// PathGrant is a single filesystem access grant the agent legitimately
// needs. PerFile=true means Path is a literal file (sbpl (literal ...) /
// Landlock path-beneath on the file itself); PerFile=false means Path is a
// directory subtree (sbpl (subpath ...) / Landlock path-beneath on the dir).
//
// Path is home-relative (e.g. ".ssh/known_hosts"); callers join it with the
// resolved home directory.
type PathGrant struct {
	Path    string
	Mode    AccessMode
	PerFile bool
}

// PatternDeny is a filename/extension pattern that must be denied, expressed
// as a raw (non-anchored-to-a-regex-engine) regex.  Read and Write indicate
// which access types the pattern applies to.
//
// sbpl (macOS) can enforce this directly via (regex #"...") in both the
// file-write* and file-read* deny blocks.  Landlock (Linux) has no filename/
// basename primitive -- see UnsupportedFilenamePatternDeny.
type PatternDeny struct {
	Regex string
	Read  bool
	Write bool
}

// UnsupportedReason names, precisely, why a backend cannot honor a contract
// capability.  Used instead of silently dropping the capability -- see
// CapabilityKey and BackendCapability below.
type UnsupportedReason string

// CapabilityKey names a contract capability that a backend either honors or
// must name as Unsupported.  Used by the capability/parity test
// (shield_contract_test.go) to assert no capability is silently dropped.
type CapabilityKey string

const (
	// CapFilenamePatternDeny is the "deny by filename/extension regex"
	// capability (SensitiveFilePatterns).
	CapFilenamePatternDeny CapabilityKey = "filename-pattern-deny"
	// CapLoopbackScopedBind is the "restrict a TCP bind/inbound rule to the
	// loopback interface only" capability, as opposed to any-interface.
	CapLoopbackScopedBind CapabilityKey = "loopback-scoped-bind"
	// CapMetadataIPFilter is the "deny egress to a specific destination IP
	// (e.g. the cloud metadata service) while still allowing the fallback
	// ports to everything else" capability. Neither backend's port-only
	// (--no-netproxy) primitive can express this: Landlock net rules
	// (LANDLOCK_RULE_NET_PORT) are port-scoped only with no address
	// component, and sbpl's (remote tcp/ip "HOST:PORT") rejects literal IP
	// hosts (only "*" and "localhost" are accepted -- see
	// shield_darwin_test.go). Both backends name this Unsupported; the
	// mitigation is the launch-time metadata-egress guard in main.go
	// (decideMetadataEgress / probeMetadataReachable), not a network rule.
	// See docs/adr/0049-cloud-metadata-egress-guard.md.
	CapMetadataIPFilter CapabilityKey = "metadata-ip-filter"
)

// BackendCapability summarizes, for one backend, which contract capabilities
// it cannot fully honor and why. A capability absent from Unsupported is
// claimed as fully honored by that backend -- tests hold backends to that
// claim.
type BackendCapability struct {
	Backend     string
	Unsupported map[CapabilityKey]UnsupportedReason
}

// SensitiveFilePatterns is the single, shared list of filename/extension
// regex patterns that must be denied. This was previously duplicated as
// sensitiveWriteRegexes/sensitiveReadRegexes literals inside shield_darwin.go
// (pre-ADR-0039); it now lives here so there is exactly one list to audit.
//
// darwin (shield_darwin.go) renders every entry into the sbpl deny blocks.
// Linux (Landlock) has no filename/basename regex primitive -- this is a
// NAMED non-parity (CapFilenamePatternDeny), enforced instead by the hook
// layer (agentpolicy/policies/file_policy.rego).
//
// Note: Apple sandbox-exec uses a non-standard regex engine that does not
// tolerate a literal '-' at the end of a bracket expression (e.g.
// [a-z0-9_-]). Use POSIX character classes ([[:alnum:]]) or omit the hyphen.
func SensitiveFilePatterns() []PatternDeny {
	return []PatternDeny{
		// .env, .env.local, .env.production, etc. (write only).
		{Regex: `\.env(\.[a-zA-Z0-9_]+)?$`, Write: true},
		{Regex: `(^|/)\.envrc$`, Write: true},
		// Private key / keystore formats (write + read).
		{Regex: `\.(pem|p12|pfx|jks|keystore|key)$`, Write: true, Read: true},
		{Regex: `(^|/)id_(rsa|ed25519|ecdsa|dsa)$`, Write: true, Read: true},
		// credentials/secrets basename deny removed - hook-layer file_policy.rego covers these.
		{Regex: `(^|/)\.netrc$`, Write: true, Read: true},
		// Anchored home-file patterns: exact-match only ($ prevents catching
		// .npmrc.bak). Only the home-anchored forms are matched; project-local
		// copies are not caught by these regexes.
		{Regex: `/Users/[^/]+/\.npmrc$`, Write: true, Read: true},
		{Regex: `/Users/[^/]+/\.pypirc$`, Write: true, Read: true},
		{Regex: `/Users/[^/]+/\.git-credentials$`, Write: true, Read: true},
		// Protect agentjail daemon/shield plists from being overwritten.
		{Regex: `/Users/[^/]+/Library/LaunchAgents/com\.agentjail\.`, Write: true},
	}
}

// NoNetproxyFallbackPorts is the fixed port set both backends restrict TCP
// CONNECT to when netproxy is disabled (--no-netproxy) but the platform can
// still enforce *some* port-level restriction: darwin renders these as
// `(allow network-outbound (remote tcp "*:<port>"))`; Linux restricts
// LANDLOCK_ACCESS_NET_CONNECT_TCP to these ports when the kernel supports
// Landlock network ABI v4+ (6.7+).
func NoNetproxyFallbackPorts() []int {
	return []int{22, 80, 443}
}

// AgentjailSecretsProtectedNames returns the ~/.agentjail child names that
// must NEVER be granted read access to the sandboxed agent: the secrets
// broker's AES-256 master key ("secrets.key") and its encrypted store
// ("secrets/"). ~/.agentjail is otherwise granted read-only to the agent for
// observability (policy.yaml, the audit DB, etc — see AgentPaths.HomeRO in
// shield_agentpaths.go), but a blanket recursive grant over the whole
// subtree would let a sandboxed agent read the master key plus every
// ciphertext blob and decrypt all stored secrets offline (C2).
//
// Linux (Landlock) has no directory-level punch-through deny primitive — an
// allow rule on a directory grants access to its full subtree, so
// shield_linux.go grants ~/.agentjail listing only (LANDLOCK_ACCESS_FS_READ_DIR)
// and then enumerates children individually, skipping the names returned
// here. Darwin (shield_darwin.go) already denies read on the whole
// ~/.agentjail subtree via sensitiveReadPaths, so this list documents the
// invariant for darwin (nothing further to carve out) rather than gating a
// runtime exclusion there.
func AgentjailSecretsProtectedNames() map[string]bool {
	return map[string]bool{
		"secrets.key": true,
		"secrets":     true,
	}
}

// CloudMetadataDenyIP is a single well-known cloud-provider instance
// metadata service (IMDS) address that must never be reachable by the
// sandboxed agent. This is the shared, tag-free source of truth (ADR 0034):
// both shield backends would translate this into their own enforcement
// primitive if either had one (see CapMetadataIPFilter -- today neither
// does in port-only/--no-netproxy mode), and main.go's launch-time guard
// (decideMetadataEgress) consumes it directly.
type CloudMetadataDenyIP struct {
	// IP is the literal IPv4 or IPv6 address (no port, no CIDR).
	IP string
	// Note documents which cloud provider(s) use this address.
	Note string
}

// CloudMetadataDenyIPs returns the well-known cloud IMDS endpoints that must
// never be reachable through the shield's default egress path.
//
//   - 169.254.169.254 is the IMDS address on AWS, GCP, Azure, OpenStack, and
//     Alibaba Cloud (the "link-local metadata IP" convention).
//   - fd00:ec2::254 is AWS's IPv6 IMDS endpoint.
//
// See CloudMetadataDenyCIDR for the broader IPv4 link-local block these
// addresses live in.
func CloudMetadataDenyIPs() []CloudMetadataDenyIP {
	return []CloudMetadataDenyIP{
		{IP: "169.254.169.254", Note: "AWS/GCP/Azure/OpenStack/Alibaba Cloud IMDS (IPv4)"},
		{IP: "fd00:ec2::254", Note: "AWS IMDS (IPv6)"},
	}
}

// CloudMetadataDenyCIDR is the full IPv4 link-local block (RFC 3927) that
// hosts every cloud provider's metadata IP. IsCloudMetadataIP treats any
// address inside this block as a metadata endpoint, not just the exact
// 169.254.169.254 literal, since some providers (e.g. Azure's Wireserver at
// 168.63.129.16 is an exception -- deliberately NOT covered by this CIDR)
// use adjacent link-local addresses for related services.
const CloudMetadataDenyCIDR = "169.254.0.0/16"

// IsCloudMetadataIP reports whether ip (a dotted-quad IPv4 or IPv6 literal,
// as returned by net.Conn.RemoteAddr / net.SplitHostPort) is a known or
// likely cloud-metadata endpoint: an exact match against CloudMetadataDenyIPs
// or any address inside CloudMetadataDenyCIDR. Malformed input returns false
// (fails open on THIS helper only -- callers that need fail-closed behavior
// for unparseable input must check separately; see decideMetadataEgress
// which never receives unparsed input because it consumes a bool).
func IsCloudMetadataIP(ip string) bool {
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	for _, deny := range CloudMetadataDenyIPs() {
		if denyAddr := net.ParseIP(deny.IP); denyAddr != nil && denyAddr.Equal(addr) {
			return true
		}
	}
	_, cidr, err := net.ParseCIDR(CloudMetadataDenyCIDR)
	if err != nil {
		return false
	}
	return cidr.Contains(addr)
}

var knownHostsGrant = PathGrant{Path: ".ssh/known_hosts", Mode: ReadOnly, PerFile: true}

var perFileGrants = []PathGrant{
	knownHostsGrant,
	{Path: ".ssh/config", Mode: ReadOnly, PerFile: true},
	{Path: ".aws/config", Mode: ReadOnly, PerFile: true},
}

// PerFileGrants returns the shared set of individual-file (not directory)
// read-only grants inside otherwise-denied directories. darwin carves out
// explicit allows AFTER the deny block (last-match-wins); Linux adds
// per-inode read grants via Landlock.
func PerFileGrants() []PathGrant {
	return perFileGrants
}

// KnownHostsGrant returns the known_hosts PathGrant directly (convenience
// accessor; equivalent to the sole entry of PerFileGrants() today).
func KnownHostsGrant() PathGrant {
	return knownHostsGrant
}

// resolveMCPServerPaths reads ~/.claude.json and returns the command paths
// of configured MCP servers. Relocated from shield_linux.go (was
// Linux-only) to this tag-free file so both backends can share the same
// resolution logic per ADR 0034; behavior is unchanged (moved, not
// duplicated).
func resolveMCPServerPaths(claudeJSON string) []string {
	data, err := os.ReadFile(claudeJSON)
	if err != nil {
		return nil
	}
	var cfg struct {
		MCPServers map[string]struct {
			Command string `json:"command"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	var paths []string
	for _, s := range cfg.MCPServers {
		if s.Command != "" && filepath.IsAbs(s.Command) {
			paths = append(paths, s.Command)
		}
	}
	return paths
}

// resolveOAuthCallbackPorts reads ~/.claude/.credentials.json and returns the
// localhost ports used by MCP OAuth redirect URIs (e.g.
// http://localhost:52819/callback). Returns deduplicated, valid port numbers
// only. Relocated from shield_linux.go (was Linux-only) to this tag-free
// file so both backends can share the same resolution logic per ADR 0034;
// behavior is unchanged (moved, not duplicated).
func resolveOAuthCallbackPorts(credentialsJSON string) []int {
	data, err := os.ReadFile(credentialsJSON)
	if err != nil {
		return nil
	}
	var creds struct {
		MCPOAuth map[string]struct {
			RedirectURI string `json:"redirectUri"`
		} `json:"mcpOAuth"`
	}
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil
	}
	seen := make(map[int]bool)
	var ports []int
	for _, entry := range creds.MCPOAuth {
		if entry.RedirectURI == "" {
			continue
		}
		u, err := url.Parse(entry.RedirectURI)
		if err != nil || u.Hostname() != "localhost" {
			continue
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil || port <= 0 || port > 65535 {
			continue
		}
		if !seen[port] {
			seen[port] = true
			ports = append(ports, port)
		}
	}
	return ports
}
