package main

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
			".local",      // Claude binary, gryph audit DB, tool installs
			".vscode",     // VS Code settings
		},
		HomeRO: []string{
			".agentjail",  // agentjail's OWN state: read/traverse only. The agent
			//                must NOT write policy.yaml, the SQLite DB, or (Phase 2)
			//                trusted.yaml -- those gate enforcement, so a writable
			//                grant would let the agent disable its own guardrail
			//                (invariant 0). The hook's connect() to daemon.sock is
			//                preserved by the narrow HomeFilesRW grant below: on
			//                Linux, Landlock mediates AF_UNIX connect() through the
			//                filesystem hook (needs write on the socket inode), so a
			//                blanket read-only grant alone would EACCES the hook and
			//                silently fail-open ALL policy enforcement. macOS denies
			//                ~/.agentjail read+write via sensitiveWritePaths/
			//                sensitiveReadPaths but still permits the socket connect
			//                (allow-default network), so this read-only entry is a
			//                Linux-effective narrowing with no macOS change.
			".npm-global", // npm global modules (plugins may need this)
			".config",     // XDG config (MCP server configs, etc.)
			".openclaw",   // openclaw skills and config
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
			// daemon.sock (source of truth: internal/wire.DefaultSocketPath):
			// single-file WRITE grant so the sandboxed hook can connect() to the
			// agentjail daemon while ~/.agentjail itself stays read-only above.
			// On Linux, AF_UNIX connect() needs write on the socket inode; a
			// single-file grant covers exactly the socket, not policy.yaml/DB.
			// Skipped harmlessly if the daemon is not running at launch (same
			// effective result as a daemon-down session: hook fails open).
			".agentjail/daemon.sock",
		},
		Runtimes: []string{"node", "bun", "npx", "python3", "python", "deno", "go", "cargo", "ruby"},
	}
}
