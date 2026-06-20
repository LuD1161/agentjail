// Package main is agentjail-shield. This file contains the env stripping
// logic that removes ambient credentials from the agent's environment
// before exec'ing it.  Shared between macOS and Linux (no build constraint).

package main

import (
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
)

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
	conn, err := net.DialTimeout("unix", secretsSocketPath(), 200*1000*1000)
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
