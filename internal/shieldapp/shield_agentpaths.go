package shieldapp

// AgentPaths is the OS-agnostic source of truth for the filesystem paths
// the sandboxed coding agent (Claude Code) legitimately needs to function.
//
// The two shield backends model access in opposite directions:
//   - shield_linux.go (Landlock) is allowlist-based: it grants access to
//     exactly the paths listed here (plus /tmp, cwd, system dirs).
//   - shield_darwin.go (Apple sbpl) is denylist-based: it denies a broad
//     set of sensitive paths, then carves out explicit allows for the
//     subset of those paths the agent needs to write (e.g. ~/.claude).
//
// Both backends consume agentPaths() so the set of paths the agent is
// granted never drifts between the two platforms. When adding a new path
// the agent needs, add it here first, then wire it into both backends.
type AgentPaths struct {
	// HomeRW lists home-relative directories the agent may read and write.
	HomeRW []string

	// HomeRO lists home-relative directories the agent may only read.
	HomeRO []string

	// HomeFilesRW lists home-relative files (not directories) the agent may
	// read and write.
	HomeFilesRW []string

	// Runtimes lists runtime binary names to resolve on PATH and allow
	// (read-only, execute) their containing directory.
	Runtimes []string
}

// agentPaths returns the canonical AgentPaths contract. This list was
// originally hardcoded in shield_linux.go's applyLandlock; it is now the
// single source of truth for both backends.
func agentPaths() AgentPaths {
	return AgentPaths{
		HomeRW: []string{
			".claude",     // Claude Code config, sessions, plugins
			".claude-mem", // claude-mem MCP plugin database
			".cache",      // Claude CLI cache (node, updates)
			".local",      // Claude binary, tool installs
			".vscode",     // VS Code settings
			".grok",       // Grok Build CLI: auth.json token, leader.sock, session state
		},
		HomeRO: []string{
			".agentjail", // agentjail's OWN state: read/traverse only. The agent
			//                must NOT write policy.yaml, the SQLite DB, or
			//                trusted.yaml -- those gate enforcement, so a writable
			//                grant would let the agent disable its own guardrail
			//                (invariant 0). The hook's connect() to daemon.sock is
			//                unaffected: Landlock is an FS-only LSM and does not
			//                mediate AF_UNIX connect() -- see ADR
			//                0067-control-plane-token-auth (addendum, AGE-216).
			//                READ is NOT blanket-recursive on Linux: read-denied
			//                names are excluded per-child by shield_linux.go's
			//                applyLandlock -- see AgentjailSecretsProtectedNames()
			//                and AgentjailReadDeniedNames() in shield_contract.go.
			//                That read exclusion is the control-plane boundary
			//                (ADR 0067-control-plane-token-auth), not path
			//                separation. macOS already denies read+write on the
			//                whole ~/.agentjail subtree (sensitiveReadPaths/
			//                sensitiveWritePaths in shield_darwin.go).
			".npm-global", // npm global modules (plugins may need this)
			".config",     // XDG config (MCP server configs, etc.)
			".codex",      // codex skills and config
			".nvm",        // Node version manager
			".fnm",        // Fast node manager
			".npm",        // npm cache/config
			".pyenv",      // Python version manager
			".conda",      // Conda environments
			".cargo",      // Rust cargo
			".rustup",     // Rust toolchain
			".sdkman",     // SDKMAN (Java)
			".m2",         // Maven repository
			".gradle",     // Gradle cache
		},
		HomeFilesRW: []string{
			".claude.json",      // OAuth tokens, preferences, feature flags
			".gitconfig",        // git user config
			".gitignore_global", // global gitignore
			".ssh/known_hosts",  // SSH host key verification (not private keys)
			// daemon.sock (source of truth: internal/wire.DefaultSocketPath).
			// This grant is a measured NO-OP for connect(): Landlock does not
			// mediate AF_UNIX connect(), so the hook reaches the daemon with or
			// without it. Retained pending a human decision to drop it -- see
			// ADR 0067-control-plane-token-auth (addendum, AGE-216).
			".agentjail/daemon.sock",
			// daemon-ctl.sock (~/.agentjail/run/daemon-ctl.sock) is deliberately
			// ABSENT, but absence is NOT what makes it safe: on Linux the agent
			// can connect() to it regardless (ctl_connect=ok). Its boundary is
			// the read-denied control token (ADR 0067-control-plane-token-auth).
			// macOS sbpl additionally denies network-outbound to it
			// (shield_darwin.go).
		},
		Runtimes: []string{"node", "bun", "npx", "python3", "python", "deno", "go", "cargo", "ruby"},
	}
}

// SensitiveMCPCommandDirs is the shared set of top-level home directories
// that must NEVER be granted filesystem access as a side effect of
// resolving an MCP server's `command` path from ~/.claude.json.
//
// ~/.claude.json is agent-writable. Without this check, an agent could
// widen its own read access by writing
// {"mcpServers":{"x":{"command":"/home/user/.ssh/anything"}}} -- on next
// launch, shield_linux.go's MCP-path resolution would otherwise grant
// Landlock read access to the resolved top-level directory (~/.ssh),
// leaking private keys. The same attack applies to ~/.aws and ~/.gnupg.
//
// Linux (shield_linux.go, allowlist model) checks this set explicitly
// before granting a resolved MCP command's directory tree -- see
// isSensitiveMCPTarget. macOS (shield_darwin.go, denylist model) already
// denies reads under these same directories unconditionally via
// sensitiveReadPaths, so it is protected by construction; sensitiveReadPaths
// derives its literal entries from this list so the two never drift.
func SensitiveMCPCommandDirs() []string {
	return []string{".ssh", ".aws", ".gnupg"}
}

// ConfigCredentialSubdirs lists subdirectories of ~/.config that hold CLI
// credential material (OAuth/PAT tokens, service-account keys, registry
// auth) even though ~/.config itself is granted read-only so legitimate MCP
// server config files remain reachable (see AgentPaths.HomeRO above).
//
// Both shield backends deny read access to these specific subdirectories
// while leaving the rest of ~/.config readable:
//   - Linux (shield_linux.go) grants ~/.config child-by-child, skipping
//     these names, since Landlock path-beneath grants are purely additive
//     (there is no "deny within an allow" primitive to carve a hole out of
//     a directory once its subtree is granted).
//   - macOS (shield_darwin.go) is denylist-based ((allow default) plus
//     explicit denies), so these are added as literal file-read* denies
//     that take precedence over the broad allow.
func ConfigCredentialSubdirs() []string {
	return []string{
		"gh",         // GitHub CLI: hosts.yml holds OAuth/PAT tokens
		"gcloud",     // gcloud CLI: access tokens, application-default credentials
		"containers", // podman/buildah/skopeo: auth.json holds registry credentials
		"git",        // some git credential helpers store plaintext tokens here
	}
}
