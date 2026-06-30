// Package main is agentjail-shield. This file contains the env construction
// logic that builds a clean environment for the agent process.
//
// The primary defence is allowlist-based: buildCleanEnv starts with an empty
// environment and copies only variables from a known-safe baseline plus any
// extras listed in the policy's env_passthrough list.  stripEnv runs as a
// second, defence-in-depth layer that catches anything the allowlist
// accidentally included.
//
// Shared between macOS and Linux (no build constraint).

package main

import (
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
)

// envAllowlistBaseline is the set of env var names that are safe for any
// agent to inherit.  These are the minimum variables needed for a working
// shell, TLS, proxy, editor, and common language toolchains.
//
// Credential-bearing variables (API keys, tokens, passwords) are NOT in
// this list — they must go through the secrets broker.
var envAllowlistBaseline = map[string]bool{
	// Core POSIX / shell
	"PATH":    true,
	"HOME":    true,
	"USER":    true,
	"SHELL":   true,
	"TERM":    true,
	"TZ":      true,
	"LANG":    true,
	"LC_ALL":  true,
	"TMPDIR":  true,

	// Display / Wayland / X11
	"DISPLAY":          true,
	"WAYLAND_DISPLAY":  true,
	"XDG_RUNTIME_DIR":  true,

	// TLS / proxy
	"SSL_CERT_FILE":       true,
	"SSL_CERT_DIR":        true,
	"NODE_EXTRA_CA_CERTS": true,
	"CURL_CA_BUNDLE":      true,
	"REQUESTS_CA_BUNDLE":  true,
	"GIT_SSL_CAINFO":      true,
	"HTTPS_PROXY":         true,
	"HTTP_PROXY":          true,
	"NO_PROXY":            true,
	"https_proxy":         true,
	"http_proxy":          true,
	"no_proxy":            true,

	// agentjail internal
	"AGENTJAIL_SHIELDED": true,
	"AGENTJAIL_SECRETS":  true,
	"AGENTJAIL_SESSION":  true,

	// Agent tooling
	"DISABLE_AUTOUPDATER": true,
	"CLAUDECODE":          true,
	"AI_AGENT":            true,
	"COREPACK_ENABLE_AUTO_PIN": true,

	// Process / session context
	"PWD":     true,
	"OLDPWD":  true,
	"LOGNAME": true,
	"SHLVL":   true,
	"SSH_TTY": true,
	"COLORTERM": true,
	"TERM_PROGRAM":         true,
	"TERM_PROGRAM_VERSION": true,

	// Editor / pager
	"EDITOR":   true,
	"VISUAL":   true,
	"PAGER":    true,
	"LESS":     true,
	"LESSOPEN": true,

	// Git identity (not credentials)
	"GIT_AUTHOR_NAME":     true,
	"GIT_AUTHOR_EMAIL":    true,
	"GIT_COMMITTER_NAME":  true,
	"GIT_COMMITTER_EMAIL": true,
	"GIT_EDITOR":          true,

	// Language toolchain roots (paths, not secrets)
	"GOPATH":      true,
	"GOROOT":      true,
	"CARGO_HOME":  true,
	"RUSTUP_HOME": true,
	"NVM_DIR":     true,
	"VOLTA_HOME":  true,
	"PYENV_ROOT":  true,
}

// envDenylist blocks dangerous injection vectors. These are stripped even
// if they match a safe prefix or appear in the policy passthrough list.
// These are non-overridable even if listed in the policy passthrough.
var envDenylist = map[string]bool{
	// Linker injection
	"LD_PRELOAD":            true,
	"LD_LIBRARY_PATH":       true,
	"LD_AUDIT":              true,
	"DYLD_INSERT_LIBRARIES": true,
	"DYLD_LIBRARY_PATH":     true,

	// Shell injection
	"BASH_ENV":       true,
	"ENV":            true,
	"PROMPT_COMMAND": true,
	"IFS":            true,
	"CDPATH":         true,
	"GLOBIGNORE":     true,

	// Language runtime injection
	"PYTHONSTARTUP":         true,
	"PYTHONPATH":            true,
	"NODE_OPTIONS":          true,
	"NODE_PATH":             true,
	"PERL5OPT":              true,
	"PERL5LIB":              true,
	"RUBYOPT":               true,
	"RUBYLIB":               true,
	"GEM_PATH":              true,
	"GEM_HOME":              true,
	"JAVA_TOOL_OPTIONS":     true,
	"_JAVA_OPTIONS":         true,
	"DOTNET_STARTUP_HOOKS":  true,
	"GOFLAGS":               true,
}

// envDenyPrefixes blocks any env var starting with these prefixes.
var envDenyPrefixes = []string{
	"LD_",
	"DYLD_",
	"BASH_FUNC_",
	"OP_SESSION_",
}

// isDenied returns true if the variable name is on the denylist or matches
// a denied prefix.
func isDenied(name string) bool {
	if envDenylist[name] {
		return true
	}
	for _, pfx := range envDenyPrefixes {
		if strings.HasPrefix(name, pfx) {
			return true
		}
	}
	return false
}

// buildCleanEnv constructs a clean environment for the agent by starting
// with an empty slice and copying only allowlisted variables from hostEnv.
//
// The allowlist is the union of envAllowlistBaseline and any variable names
// listed in cfg.Secrets.EnvPassthrough.
//
// This is the primary defence against credential leakage: any env var NOT
// in the allowlist is silently dropped.  stripEnv runs afterward as a
// second layer.
func buildCleanEnv(hostEnv []string, cfg *config.PolicyConfig) []string {
	// Build the effective allowlist: baseline + policy passthrough.
	allowed := make(map[string]bool, len(envAllowlistBaseline))
	for k, v := range envAllowlistBaseline {
		allowed[k] = v
	}
	if cfg != nil {
		for _, name := range cfg.Secrets.EnvPassthrough {
			allowed[name] = true
		}
	}

	// Index hostEnv by name for O(1) lookup.
	hostMap := make(map[string]string, len(hostEnv))
	for _, kv := range hostEnv {
		name := envVarName(kv)
		hostMap[name] = kv
	}

	// Prefixes that are safe to pass through (non-credential env families).
	safePrefixes := []string{
		"CLAUDE_CODE_", // Claude Code session metadata
		"CLAUDE_",      // Claude agent config (CLAUDE_EFFORT, etc.)
		"LC_",          // Locale variants
		"XDG_",         // XDG base directory spec
	}

	// Copy only allowlisted variables that exist in the host env.
	result := make([]string, 0, len(allowed))
	for name := range allowed {
		if isDenied(name) {
			continue
		}
		if kv, ok := hostMap[name]; ok {
			result = append(result, kv)
		}
	}
	// Also copy any var matching a safe prefix (unless already copied).
	copied := make(map[string]bool, len(result))
	for _, kv := range result {
		copied[envVarName(kv)] = true
	}
	for name, kv := range hostMap {
		if copied[name] || isDenied(name) {
			continue
		}
		for _, pfx := range safePrefixes {
			if strings.HasPrefix(name, pfx) {
				result = append(result, kv)
				break
			}
		}
	}

	// Logged at debug level only; the spinner provides user-facing feedback.
	_ = len(result) // suppress unused

	return result
}

// secretsSocketPath returns the path to the agentjail-secrets Unix socket.
func secretsSocketPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/agentjail-secrets.sock"
	}
	return filepath.Join(home, ".agentjail", "secrets.sock")
}

// secretsBrokerRunning returns true if the agentjail-secrets broker is
// listening on its Unix socket.  Best-effort: if the check fails for any
// reason, returns false.
func secretsBrokerRunning() bool {
	conn, err := net.DialTimeout("unix", secretsSocketPath(), 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// stripEnv removes env vars matching the blocklist from env, returning a
// new env slice.  If secrets.StripOnLaunch is false, env is returned
// unchanged.
//
// This is the defence-in-depth layer that runs AFTER buildCleanEnv.  It
// catches any credential-bearing variable that the allowlist baseline
// accidentally included.
//
// The blocklist supports glob patterns (path.Match semantics):
//   - "AWS_ACCESS_KEY_ID" — exact match
//   - "*_SECRET_ACCESS_KEY" — matches any var ending in _SECRET_ACCESS_KEY
//   - "*_API_KEY" — matches any var ending in _API_KEY
//
// If the agentjail-secrets broker is running, a placeholder env var
// (AGENTJAIL_SECRETS=1) is added to signal that scoped creds are available
// via the broker.
func stripEnv(env []string, cfg *config.PolicyConfig) []string {
	if cfg == nil {
		return env
	}
	if cfg.Secrets.StripOnLaunch != nil && !*cfg.Secrets.StripOnLaunch {
		return env
	}

	blocklist := cfg.Secrets.EnvBlocklist
	if len(blocklist) == 0 {
		blocklist = config.Default().Secrets.EnvBlocklist
	}

	result := make([]string, 0, len(env))
	stripped := 0
	for _, kv := range env {
		key := envVarName(kv)
		if matchesBlocklist(key, blocklist) {
			stripped++
			continue
		}
		result = append(result, kv)
	}

	if stripped > 0 {
		fmt.Fprintf(os.Stderr, "agentjail-shield INFO: stripped %d env var(s) matching secrets.env_blocklist\n", stripped)
	}

	// If the secrets broker is running, signal it to the agent.
	if secretsBrokerRunning() {
		result = append(result, "AGENTJAIL_SECRETS=1")
		fmt.Fprintln(os.Stderr, "agentjail-shield INFO: agentjail-secrets broker detected — scoped creds available via broker")
	}

	return result
}

// envVarName extracts the key from a "KEY=VALUE" env string.
func envVarName(kv string) string {
	if idx := strings.IndexByte(kv, '='); idx >= 0 {
		return kv[:idx]
	}
	return kv
}

// matchesBlocklist returns true if key matches any pattern in blocklist.
// Patterns use path.Match glob semantics (case-sensitive).
func matchesBlocklist(key string, blocklist []string) bool {
	for _, pattern := range blocklist {
		if matched, err := path.Match(pattern, key); err == nil && matched {
			return true
		}
	}
	return false
}
