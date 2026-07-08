// Package sshagent detects whether ssh-agent is usable so callers can warn a
// user whose private key isn't loaded into it.
//
// The shield blocks direct reads of private-key files by design (ADR 0001) —
// SSH access under agentjail MUST go through ssh-agent forwarding. If the
// key isn't loaded into the agent, ssh fails with a cryptic
// "Permission denied (publickey)" error that gives no hint about the real
// cause. This package probes agent reachability and identity count so a
// caller can surface a clear diagnosis and the correct remediation
// (ssh-add) — never a recommendation to grant the key file itself.
package sshagent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Readiness is the ssh-agent state relevant to key-based auth.
type Readiness int

const (
	// ReadinessNoAgent means SSH_AUTH_SOCK is unset or the agent is
	// unreachable (or the probe could not conclusively determine state).
	ReadinessNoAgent Readiness = iota
	// ReadinessNoKeys means the agent is reachable but has zero identities
	// loaded.
	ReadinessNoKeys
	// ReadinessReady means the agent has at least one identity loaded.
	ReadinessReady
)

// Status is the probed ssh-agent + on-disk-key state.
type Status struct {
	Readiness  Readiness
	KeysOnDisk bool     // true if >=1 private key file is present under ~/.ssh
	SockPath   string   // value of SSH_AUTH_SOCK (may be empty)
	KeyPaths   []string // detected on-disk private key paths (for remediation)
}

// Prober probes ssh-agent readiness. The function fields are injectable
// seams so tests can run without a real ssh-agent or filesystem.
type Prober struct {
	// RunSSHAdd runs `ssh-add -l` (or equivalent) and returns its exit
	// code. Exit 0 means the agent has identities loaded, exit 1 means
	// the agent is reachable but has none, and anything else (exit 2,
	// a start error, or a context error) means the agent is unreachable.
	RunSSHAdd func(ctx context.Context) (exitCode int, err error)

	// ListKeyFiles returns the on-disk private key paths under ~/.ssh
	// used for remediation messaging.
	ListKeyFiles func() []string

	// Getenv reads an environment variable. Defaults to os.Getenv.
	Getenv func(string) string
}

// DefaultProber returns a Prober wired to the real ssh-add binary,
// filesystem, and environment.
func DefaultProber() *Prober {
	return &Prober{
		RunSSHAdd:    runSSHAddReal,
		ListKeyFiles: listKeyFilesReal,
		Getenv:       os.Getenv,
	}
}

// Probe returns the ssh-agent + on-disk-key Status.
func (p *Prober) Probe(ctx context.Context) Status {
	st := Status{
		SockPath: p.Getenv("SSH_AUTH_SOCK"),
		KeyPaths: p.ListKeyFiles(),
	}
	st.KeysOnDisk = len(st.KeyPaths) > 0

	if st.SockPath == "" {
		st.Readiness = ReadinessNoAgent
		return st
	}

	exitCode, err := p.RunSSHAdd(ctx)
	if err != nil {
		// Conservative: never claim Ready on error (binary missing,
		// context timeout, etc.).
		st.Readiness = ReadinessNoAgent
		return st
	}
	switch exitCode {
	case 0:
		st.Readiness = ReadinessReady
	case 1:
		st.Readiness = ReadinessNoKeys
	default:
		st.Readiness = ReadinessNoAgent
	}
	return st
}

// NeedsRemediation reports whether the user has a private key on disk that
// isn't usable via the agent — i.e. ssh will fail and the fix is ssh-add,
// not granting file access.
func (s Status) NeedsRemediation() bool {
	return s.KeysOnDisk && s.Readiness != ReadinessReady
}

// Remediation returns a human-readable ssh-add command for the given GOOS.
// Returns "" if the status does not need remediation.
func (s Status) Remediation(goos string) string {
	if !s.NeedsRemediation() {
		return ""
	}

	key := chooseKey(s.KeyPaths)

	if goos == "darwin" {
		return "ssh-add --apple-use-keychain " + key
	}
	return `eval "$(ssh-agent -s)" && ssh-add ` + key
}

// chooseKey picks a display name for the key to reference in remediation
// text.
func chooseKey(keyPaths []string) string {
	if len(keyPaths) == 1 {
		return displayPath(keyPaths[0])
	}
	for _, k := range keyPaths {
		if filepath.Base(k) == "id_ed25519" {
			return displayPath(k)
		}
	}
	return "~/.ssh/<your-key>"
}

// displayPath renders a key path as ~/.ssh/<base> for display purposes.
func displayPath(path string) string {
	return filepath.Join("~", ".ssh", filepath.Base(path))
}

// Probe is a package-level convenience that uses DefaultProber.
func Probe(ctx context.Context) Status {
	return DefaultProber().Probe(ctx)
}

// runSSHAddReal runs `ssh-add -l` and extracts its exit code. A start error
// (e.g. the ssh-add binary is missing) or a context error is returned as an
// error so the caller treats it as ReadinessNoAgent.
func runSSHAddReal(ctx context.Context) (int, error) {
	cmd := exec.CommandContext(ctx, "ssh-add", "-l")
	err := cmd.Run()
	if err == nil {
		return 0, nil
	}
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	var exitErr *exec.ExitError
	if ok := isExitError(err, &exitErr); ok {
		return exitErr.ExitCode(), nil
	}
	// Start error (binary missing, permission denied, etc.).
	return 0, err
}

// isExitError is a small helper so we don't need errors.As at the call
// site twice.
func isExitError(err error, target **exec.ExitError) bool {
	ee, ok := err.(*exec.ExitError)
	if !ok {
		return false
	}
	*target = ee
	return true
}

// listKeyFilesReal globs ~/.ssh/id_* for private key files, excluding
// public keys (*.pub).
func listKeyFilesReal() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	matches, err := filepath.Glob(filepath.Join(home, ".ssh", "id_*"))
	if err != nil {
		return nil
	}
	keys := make([]string, 0, len(matches))
	for _, m := range matches {
		if strings.HasSuffix(m, ".pub") {
			continue
		}
		keys = append(keys, m)
	}
	return keys
}
