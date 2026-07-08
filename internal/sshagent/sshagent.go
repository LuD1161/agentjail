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
	"errors"
	"io/fs"
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

	// PinnedIdentityPaths holds the on-disk IdentityFile paths that the
	// user's ssh config pins via `IdentitiesOnly yes` + `IdentityFile ...`.
	// Populated by a conservative line-scan of ReadSSHConfig() during
	// Probe (see parsePinnedIdentityPaths) - it does NOT resolve Host,
	// Match, or Include blocks, so it can both miss real pins (inside an
	// Include) and include ones that a real ssh_config parse would not
	// apply to the current invocation. It is advisory only: a false
	// positive costs one extra stderr line, never an allow/deny change.
	PinnedIdentityPaths []string
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

	// ReadSSHConfig returns the contents of the user's ssh config file
	// (~/.ssh/config). Defaults to reading that file, returning "" on
	// any error (missing file, denied read, etc.) - a read failure means
	// "no pinned config detected," never a crash.
	ReadSSHConfig func() string

	// PathExists reports whether path exists on disk. Defaults to
	// os.Stat, treating fs.ErrPermission as "exists": the hook runs
	// under the shield, where statting a file under ~/.ssh can EPERM
	// even though the file is there - and a permission-denied file is
	// exactly the case ssh will also hit and the shield will block, so
	// it must still count as pinned. A plain "not found" (ENOENT) means
	// the config line is stale and returns false.
	PathExists func(path string) bool
}

// DefaultProber returns a Prober wired to the real ssh-add binary,
// filesystem, and environment.
func DefaultProber() *Prober {
	return &Prober{
		RunSSHAdd:     runSSHAddReal,
		ListKeyFiles:  listKeyFilesReal,
		Getenv:        os.Getenv,
		ReadSSHConfig: readSSHConfigReal,
		PathExists:    pathExistsReal,
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

	st.PinnedIdentityPaths = p.probePinnedIdentityPaths()
	return st
}

// probePinnedIdentityPaths reads the user's ssh config (if a seam is
// configured) and applies the pinned-IdentityFile heuristic. Missing seams
// (ReadSSHConfig/PathExists left nil, as in older callers/tests that only
// exercise agent readiness) are treated as "no config to scan" rather than
// a panic.
func (p *Prober) probePinnedIdentityPaths() []string {
	if p.ReadSSHConfig == nil || p.PathExists == nil {
		return nil
	}
	config := p.ReadSSHConfig()
	if config == "" {
		return nil
	}
	home := ""
	if p.Getenv != nil {
		home = p.Getenv("HOME")
	}
	if home == "" {
		if h, err := os.UserHomeDir(); err == nil {
			home = h
		}
	}
	if home == "" {
		return nil
	}
	return parsePinnedIdentityPaths(config, home, p.PathExists)
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

// PinnedIdentity reports whether the ssh config pins an on-disk
// IdentityFile via `IdentitiesOnly yes`.
func (s Status) PinnedIdentity() bool {
	return len(s.PinnedIdentityPaths) > 0
}

// PinnedBlindSpot reports the case existing remediation misses entirely:
// the agent has a key loaded (Readiness == ReadinessReady, so
// NeedsRemediation is false) but the ssh config pins an on-disk
// IdentityFile that the shield blocks. ssh reads the pinned file first,
// the shield denies it, and ssh gives up before falling back to the
// agent - "Permission denied (publickey)" with no hint that the agent
// was ready and would have worked. Deliberately NOT gated on KeysOnDisk /
// the id_* glob: a pinned deploy key (e.g. ~/.ssh/github_deploy) that
// ListKeyFiles never sees still hits this trap.
func (s Status) PinnedBlindSpot() bool {
	return s.Readiness == ReadinessReady && s.PinnedIdentity()
}

// PinnedRemediation returns guidance for the pinned-IdentityFile blind
// spot. It always routes auth through the agent - via the same
// IdentitiesOnly=no + IdentityFile=none + IdentityAgent recipe the shield
// injects for git - and never suggests granting access to the key file
// itself. IdentitiesOnly=no is the decisive option: with IdentitiesOnly
// yes in the config, OpenSSH only offers agent keys matching a configured
// IdentityFile, so an agent key that differs from the pinned one is never
// offered. Returns "" when the status is not a pinned blind spot.
func (s Status) PinnedRemediation(goos string) string {
	if !s.PinnedBlindSpot() {
		return ""
	}
	_ = goos // recipe is the same shape on every OS; kept for API symmetry with Remediation.
	return "ssh config pins an IdentityFile the shield blocks, even though ssh-agent has a key loaded. " +
		"For a one-off command: GIT_SSH_COMMAND='ssh -o IdentitiesOnly=no -o IdentityFile=none -o IdentityAgent=$SSH_AUTH_SOCK' <your-git-or-ssh-command>. " +
		"Or remove `IdentitiesOnly yes` from your ssh config so the agent is used as a fallback. " +
		"The shield already applies this override automatically for git unless AGENTJAIL_NO_SSH_OVERRIDE is set."
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

// readSSHConfigReal reads the user's ~/.ssh/config file. Returns "" on any
// error (missing file, denied read under the shield, no home dir, etc.) -
// callers treat that identically to "no pinned config."
func readSSHConfigReal() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(home, ".ssh", "config"))
	if err != nil {
		return ""
	}
	return string(data)
}

// pathExistsReal reports whether path exists, treating a permission-denied
// stat as "exists." See the PathExists field doc for why: under the
// shield, statting a file under ~/.ssh can EPERM even though the file is
// present, and that EPERM is exactly the case ssh will also hit.
func pathExistsReal(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if errors.Is(err, fs.ErrPermission) {
		return true
	}
	return false
}

// parsePinnedIdentityPaths applies the pinned-IdentityFile heuristic to raw
// ssh config text. This is a conservative line-scan, NOT a full ssh_config
// parser: it does not resolve Host/Match blocks (so it can't tell whether
// a given stanza applies to the current destination) and does not follow
// Include directives. It is intentionally over-inclusive rather than
// under-inclusive, since the only cost of a false positive is one extra
// advisory line, never a change to allow/deny.
//
// The heuristic: collect every uncommented `IdentityFile <path>` value.
// If (and only if) an uncommented `IdentitiesOnly yes` appears anywhere in
// the file, keep the collected values that (a) expand to a path under
// ~/.ssh and (b) satisfy pathExists. Without IdentitiesOnly yes, ssh falls
// back to the agent on its own, so an IdentityFile alone is not a blind
// spot.
func parsePinnedIdentityPaths(config string, home string, pathExists func(string) bool) []string {
	if pathExists == nil {
		return nil
	}
	var identitiesOnly bool
	var candidates []string

	for _, line := range strings.Split(config, "\n") {
		keyword, value, ok := splitSSHConfigLine(line)
		if !ok {
			continue
		}
		switch strings.ToLower(keyword) {
		case "identitiesonly":
			if strings.EqualFold(value, "yes") {
				identitiesOnly = true
			}
		case "identityfile":
			candidates = append(candidates, value)
		}
	}

	if !identitiesOnly {
		return nil
	}

	sshDir := filepath.Join(home, ".ssh")
	var result []string
	for _, c := range candidates {
		expanded := expandHomePath(c, home)
		if !underDir(expanded, sshDir) {
			continue
		}
		if !pathExists(expanded) {
			continue
		}
		result = append(result, expanded)
	}
	return result
}

// splitSSHConfigLine splits one ssh_config line into keyword/value,
// ignoring blank lines and comments (first non-space char '#'). OpenSSH
// accepts both `Keyword value` and `Keyword=value` (with optional spaces
// around '='); this handles both conservatively.
func splitSSHConfigLine(line string) (keyword, value string, ok bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", "", false
	}
	idx := strings.IndexAny(trimmed, " \t=")
	if idx < 0 {
		return "", "", false
	}
	keyword = trimmed[:idx]
	rest := strings.TrimSpace(trimmed[idx+1:])
	rest = strings.TrimPrefix(rest, "=")
	rest = strings.TrimSpace(rest)
	rest = strings.Trim(rest, `"`)
	if keyword == "" || rest == "" {
		return "", "", false
	}
	return keyword, rest, true
}

// expandHomePath expands a leading "~" or "~/" to home. Paths that don't
// start with "~" are returned unchanged (already absolute, or relative to
// the ssh config's own directory - either way, not something we can
// confidently place under ~/.ssh, so underDir will exclude it).
func expandHomePath(path string, home string) string {
	if path == "~" {
		return home
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(home, path[2:])
	}
	return path
}

// underDir reports whether path is dir itself or a descendant of dir.
func underDir(path string, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	if rel == "." {
		return false // dir itself is not a file we'd stat as an IdentityFile
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
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
