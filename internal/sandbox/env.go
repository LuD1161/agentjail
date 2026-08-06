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
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
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
	"PATH":   true,
	"HOME":   true,
	"USER":   true,
	"SHELL":  true,
	"TERM":   true,
	"TZ":     true,
	"LANG":   true,
	"LC_ALL": true,
	"TMPDIR": true,

	// Display / Wayland / X11
	"DISPLAY":         true,
	"WAYLAND_DISPLAY": true,
	"XDG_RUNTIME_DIR": true,

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
	"DISABLE_AUTOUPDATER":      true,
	"CLAUDECODE":               true,
	"AI_AGENT":                 true,
	"COREPACK_ENABLE_AUTO_PIN": true,

	// Process / session context
	"PWD":                  true,
	"OLDPWD":               true,
	"LOGNAME":              true,
	"SHLVL":                true,
	"SSH_TTY":              true,
	"COLORTERM":            true,
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
	"PYTHONSTARTUP":        true,
	"PYTHONPATH":           true,
	"NODE_OPTIONS":         true,
	"NODE_PATH":            true,
	"PERL5OPT":             true,
	"PERL5LIB":             true,
	"RUBYOPT":              true,
	"RUBYLIB":              true,
	"GEM_PATH":             true,
	"GEM_HOME":             true,
	"JAVA_TOOL_OPTIONS":    true,
	"_JAVA_OPTIONS":        true,
	"DOTNET_STARTUP_HOOKS": true,
	"GOFLAGS":              true,
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
	return SecretsSocketPathForHome(home)
}

// SecretsSocketPathForHome returns the agentjail-secrets Unix socket path for
// an explicit home, at ~/.agentjail/secrets.sock.
//
// Note this is NOT under ~/.agentjail/run/, where the netproxy and daemon
// control sockets live (proxyctl/grantctl ControlSocketPathForHome).
//
// The ForHome variant exists so callers that generate a sandbox profile for a
// known home -- rather than the current process's -- resolve the same path the
// broker will actually bind. Mirrors proxyctl/grantctl.ControlSocketPathForHome.
func SecretsSocketPathForHome(home string) string {
	return filepath.Join(home, ".agentjail", "secrets.sock")
}

// SecretsBrokerRunning returns true if the agentjail-secrets broker is
// listening on its Unix socket.  Best-effort: if the check fails for any
// reason, returns false.
func SecretsBrokerRunning() bool {
	return brokerReachable(SecretsSocketPath(), 200*time.Millisecond)
}

// Service identifiers for the on-demand secrets broker (ADR 0058). Both name a
// loaded-but-not-running definition installed by `agentjail install`, that
// EnsureSecretsBroker starts on demand — there is NO socket activation (that
// would need cgo, which the CGO_ENABLED=0 release build forbids).
const (
	SecretsBrokerLaunchdLabel  = "com.agentjail.secrets"
	SecretsBrokerSystemdUnit   = "agentjail-secrets.service"
	secretsBrokerBinary        = "agentjail-secrets"
	secretsBrokerStartDeadline = 3 * time.Second
)

// EnsureSecretsBroker brings the secrets broker up on demand if it is not
// already listening (ADR 0058, client-triggered start). It asks the OS service
// manager to start the loaded-but-not-running job (launchctl kickstart /
// systemctl --user start), falling back to a detached exec of agentjail-secrets
// when no service manager is reachable, then waits a bounded time for the
// socket. Returns nil once the socket is reachable, or an error describing why
// the broker could not be started. Safe to call when the broker is already up
// (fast no-op).
func EnsureSecretsBroker(socketPath string) error {
	if socketPath == "" {
		socketPath = SecretsSocketPath()
	}
	if brokerReachable(socketPath, 200*time.Millisecond) {
		return nil
	}

	svcErr := startSecretsBrokerService()
	if svcErr != nil {
		if execErr := startSecretsBrokerDetached(); execErr != nil {
			return fmt.Errorf("start secrets broker: service manager: %v; detached exec: %w", svcErr, execErr)
		}
	}

	deadline := time.Now().Add(secretsBrokerStartDeadline)
	for time.Now().Before(deadline) {
		if brokerReachable(socketPath, 200*time.Millisecond) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("secrets broker did not begin listening on %s within %s", socketPath, secretsBrokerStartDeadline)
}

// brokerReachable reports whether a Unix socket accepts a connection within the
// timeout. Shared by SecretsBrokerRunning and EnsureSecretsBroker.
func brokerReachable(socketPath string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("unix", socketPath, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// startSecretsBrokerService asks the OS service manager to start the
// loaded-but-not-running broker job. Returns an error if no service manager is
// available (or the start command fails), so the caller can fall back to a
// detached exec.
func startSecretsBrokerService() error {
	switch runtime.GOOS {
	case "darwin":
		target := fmt.Sprintf("gui/%d/%s", os.Getuid(), SecretsBrokerLaunchdLabel)
		return exec.Command("launchctl", "kickstart", target).Run()
	case "linux":
		return exec.Command("systemctl", "--user", "start", SecretsBrokerSystemdUnit).Run()
	default:
		return fmt.Errorf("no service manager for GOOS %q", runtime.GOOS)
	}
}

// startSecretsBrokerDetached execs `agentjail-secrets serve` in its own session
// (setsid) as a last resort when no service manager is reachable. The broker
// self-exits on idle (ADR 0058), so a detached process is not a permanent leak.
func startSecretsBrokerDetached() error {
	bin, err := exec.LookPath(secretsBrokerBinary)
	if err != nil {
		self, selfErr := os.Executable()
		if selfErr != nil {
			return fmt.Errorf("locate %s: %w", secretsBrokerBinary, err)
		}
		cand := filepath.Join(filepath.Dir(self), secretsBrokerBinary)
		if _, statErr := os.Stat(cand); statErr != nil {
			return fmt.Errorf("locate %s: %w", secretsBrokerBinary, err)
		}
		bin = cand
	}
	cmd := exec.Command(bin, "serve", "--idle-timeout=15m")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0); err == nil {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, devnull, devnull
	}
	return cmd.Start()
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
// Retain all three OpenSSH options when bypassing a pinned IdentityFile.
// See ADR 0056-ssh-agent-pinned-identityfile-blindspot.
func AgentGitSSHEnv(getenv func(string) string, sshAuthSock SSHAuthSock) []string {
	if sshAuthSock.Path == "" {
		return nil
	}
	if userCmd := getenv("GIT_SSH_COMMAND"); userCmd != "" {
		return []string{"GIT_SSH_COMMAND=" + userCmd}
	}

	if isTruthyEnvFlag(getenv("AGENTJAIL_NO_SSH_OVERRIDE")) {
		return nil
	}

	return []string{
		"GIT_SSH_COMMAND=ssh -o IdentitiesOnly=no -o IdentityFile=none -o IdentityAgent=" + shellSingleQuote(sshAuthSock.Path),
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
// single quote as '\” (close quote, escaped literal quote, reopen quote).
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
