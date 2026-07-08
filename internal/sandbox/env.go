// Package sandbox contains the OS-sandbox domain logic for agentjail-shield.
//
// This file holds the env construction logic that builds a clean environment
// for the agent process.
//
// The primary defence is allowlist-based: BuildCleanEnv starts with an empty
// environment and copies only variables from a known-safe baseline plus any
// extras listed in the policy's env_passthrough list.  StripEnv runs as a
// second, defence-in-depth layer that catches anything the allowlist
// accidentally included.
//
// Shared between macOS and Linux (no build constraint).
package sandbox

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

// EnvAllowlistBaseline is the set of env var names that are safe for any
// agent to inherit.  These are the minimum variables needed for a working
// shell, TLS, proxy, editor, and common language toolchains.
//
// Credential-bearing variables (API keys, tokens, passwords) are NOT in
// this list — they must go through the secrets broker.
var EnvAllowlistBaseline = map[string]bool{
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
	"SSH_TTY":       true,
	"SSH_AUTH_SOCK": true,
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

// EnvDenylist blocks dangerous injection vectors. These are stripped even
// if they match a safe prefix or appear in the policy passthrough list.
// These are non-overridable even if listed in the policy passthrough.
var EnvDenylist = map[string]bool{
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

// EnvDenyPrefixes blocks any env var starting with these prefixes.
var EnvDenyPrefixes = []string{
	"LD_",
	"DYLD_",
	"BASH_FUNC_",
	"OP_SESSION_",
}

// IsDenied returns true if the variable name is on the denylist or matches
// a denied prefix.
func IsDenied(name string) bool {
	if EnvDenylist[name] {
		return true
	}
	for _, pfx := range EnvDenyPrefixes {
		if strings.HasPrefix(name, pfx) {
			return true
		}
	}
	return false
}

// BuildCleanEnv constructs a clean environment for the agent by starting
// with an empty slice and copying only allowlisted variables from hostEnv.
//
// The allowlist is the union of EnvAllowlistBaseline and any variable names
// listed in cfg.Secrets.EnvPassthrough.
//
// This is the primary defence against credential leakage: any env var NOT
// in the allowlist is silently dropped.  StripEnv runs afterward as a
// second layer.
func BuildCleanEnv(hostEnv []string, cfg *config.PolicyConfig) []string {
	// Build the effective allowlist: baseline + policy passthrough.
	allowed := make(map[string]bool, len(EnvAllowlistBaseline))
	for k, v := range EnvAllowlistBaseline {
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
		name := EnvVarName(kv)
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
		if IsDenied(name) {
			continue
		}
		if kv, ok := hostMap[name]; ok {
			result = append(result, kv)
		}
	}
	// Also copy any var matching a safe prefix (unless already copied).
	copied := make(map[string]bool, len(result))
	for _, kv := range result {
		copied[EnvVarName(kv)] = true
	}
	for name, kv := range hostMap {
		if copied[name] || IsDenied(name) {
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

// SecretsSocketPath returns the path to the agentjail-secrets Unix socket.
func SecretsSocketPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/agentjail-secrets.sock"
	}
	return filepath.Join(home, ".agentjail", "secrets.sock")
}

// SecretsBrokerRunning returns true if the agentjail-secrets broker is
// listening on its Unix socket.  Best-effort: if the check fails for any
// reason, returns false.
func SecretsBrokerRunning() bool {
	conn, err := net.DialTimeout("unix", SecretsSocketPath(), 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// StripEnv removes env vars matching the blocklist from env, returning a
// new env slice.  If secrets.StripOnLaunch is false, env is returned
// unchanged.
//
// This is the defence-in-depth layer that runs AFTER BuildCleanEnv.  It
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
func StripEnv(env []string, cfg *config.PolicyConfig) []string {
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
		key := EnvVarName(kv)
		if MatchesBlocklist(key, blocklist) {
			stripped++
			continue
		}
		result = append(result, kv)
	}

	if stripped > 0 {
		fmt.Fprintf(os.Stderr, "agentjail-shield INFO: stripped %d env var(s) matching secrets.env_blocklist\n", stripped)
	}

	// If the secrets broker is running, signal it to the agent.
	if SecretsBrokerRunning() {
		result = append(result, "AGENTJAIL_SECRETS=1")
		fmt.Fprintln(os.Stderr, "agentjail-shield INFO: agentjail-secrets broker detected — scoped creds available via broker")
	}

	return result
}

// EnvVarName extracts the key from a "KEY=VALUE" env string.
func EnvVarName(kv string) string {
	if idx := strings.IndexByte(kv, '='); idx >= 0 {
		return kv[:idx]
	}
	return kv
}

// RemoveEnvKeys returns a new slice with any "KEY=VALUE" entry whose key
// matches one of keys removed.  Used to dedupe an assembled env before
// appending a value that must appear exactly once (e.g. GIT_SSH_COMMAND).
func RemoveEnvKeys(env []string, keys ...string) []string {
	if len(keys) == 0 {
		return env
	}
	drop := make(map[string]bool, len(keys))
	for _, k := range keys {
		drop[k] = true
	}
	result := make([]string, 0, len(env))
	for _, kv := range env {
		if drop[EnvVarName(kv)] {
			continue
		}
		result = append(result, kv)
	}
	return result
}

// AgentGitSSHEnv decides the final GIT_SSH_COMMAND (and, when the agentjail
// override is injected, a companion marker) to append to the sandboxed
// agent's environment.  It is a pure function of getenv (typically
// os.Getenv) so it is fully unit-testable and has no side effects.
//
// Background (ADR 0056): under the shield, on-disk private key reads are
// denied by design.  When ssh-agent has the key loaded (Readiness == Ready)
// but the user's ~/.ssh/config pins an IdentityFile (usually paired with
// IdentitiesOnly yes), OpenSSH reads the pinned file FIRST, the shield
// EPERMs the read, and ssh gives up before ever trying the agent. Since a
// global `url."git@github.com:".insteadOf https://github.com/` rewrite can
// route even HTTPS-looking clones over ssh, this silently breaks git under
// the shield. The empirically verified fix is to force agent-backed auth
// via GIT_SSH_COMMAND.
//
// Decision order:
//  1. If the host has a non-empty GIT_SSH_COMMAND, preserve it verbatim
//     (the user's choice wins; git is not auto-handled, no marker).
//  2. Else if AGENTJAIL_NO_SSH_OVERRIDE is truthy, inject nothing (opt-out).
//  3. Else if SSH_AUTH_SOCK is empty or contains a control character
//     (including newline), inject nothing (fail-closed).
//  4. Else inject the agentjail override plus the AGENTJAIL_SSH_OVERRIDE=1
//     marker.
//
// The injected value is the exact recipe verified live under the shield
// against a real pinned-IdentityFile config: "ssh -o IdentitiesOnly=no -o
// IdentityFile=none -o IdentityAgent=<quoted sock>". Do not simplify this:
//   - IdentityFile=none alone is insufficient - OpenSSH APPENDS command-line
//     IdentityFile entries rather than replacing the config-file pin.
//   - IdentityAgent alone is insufficient too - when the config has
//     IdentitiesOnly yes, OpenSSH only offers agent keys whose public half
//     matches a CONFIGURED IdentityFile, so an agent holding a DIFFERENT key
//     than the pinned one never gets offered (the common real case).
//   - IdentitiesOnly=no is the decisive option: it lifts that restriction so
//     the agent's real key is offered. TRADEOFF (see ADR 0056): this offers
//     ALL agent keys to the server for every shielded git ssh op while the
//     override is active - not only broken pinned cases - overriding a
//     deliberate user IdentitiesOnly yes (key-fingerprint exposure, possible
//     auth with a broader agent-resident key, MaxAuthTries). Accepted because
//     on-disk key auth is unavailable under the shield anyway; opt out with
//     AGENTJAIL_NO_SSH_OVERRIDE.
//
// AGENTJAIL_SSH_OVERRIDE is deliberately NOT in EnvAllowlistBaseline: a
// host-supplied value would spoof the marker and must never survive
// BuildCleanEnv. The marker only ever appears here, appended by the shield
// after StripEnv has already run.
func AgentGitSSHEnv(getenv func(string) string) []string {
	if userCmd := getenv("GIT_SSH_COMMAND"); userCmd != "" {
		return []string{"GIT_SSH_COMMAND=" + userCmd}
	}

	if isTruthyEnvFlag(getenv("AGENTJAIL_NO_SSH_OVERRIDE")) {
		return nil
	}

	sock := getenv("SSH_AUTH_SOCK")
	if sock == "" || hasControlChar(sock) {
		return nil
	}

	return []string{
		"GIT_SSH_COMMAND=ssh -o IdentitiesOnly=no -o IdentityFile=none -o IdentityAgent=" + shellSingleQuote(sock),
		"AGENTJAIL_SSH_OVERRIDE=1",
	}
}

// isTruthyEnvFlag reports whether an env var value should be treated as
// "set" for boolean opt-out flags: non-empty and not "0" or "false"
// (case-insensitive).
func isTruthyEnvFlag(v string) bool {
	if v == "" {
		return false
	}
	switch strings.ToLower(v) {
	case "0", "false":
		return false
	default:
		return true
	}
}

// hasControlChar reports whether s contains any ASCII control character
// (byte < 0x20), including newlines. Used to fail closed on a malformed
// SSH_AUTH_SOCK value rather than build an unsafe shell command string.
func hasControlChar(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 {
			return true
		}
	}
	return false
}

// shellSingleQuote wraps s in POSIX single quotes, escaping any embedded
// single quote as '\'' (close quote, escaped literal quote, reopen quote).
// This makes s safe to embed in a shell command string such as the ssh -o
// IdentityAgent=<sock> value, even if s contains spaces or shell
// metacharacters.
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// MatchesBlocklist returns true if key matches any pattern in blocklist.
// Patterns use path.Match glob semantics (case-sensitive).
func MatchesBlocklist(key string, blocklist []string) bool {
	for _, pattern := range blocklist {
		if matched, err := path.Match(pattern, key); err == nil && matched {
			return true
		}
	}
	return false
}
