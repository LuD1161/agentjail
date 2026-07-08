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
