// Package ctlauth authenticates callers on agentjail's control sockets.
//
// The token proves "I am a process outside the sandbox" — a property neither the
// socket path nor SO_PEERCRED can establish on Linux. It rests entirely on the
// agent being unable to READ the token file (shieldapp.AgentjailReadDeniedNames).
// See ADR 0067 for why that is the available lever.
package ctlauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// TokenFileName is the ~/.agentjail child holding the control-plane token. It
// MUST stay in shieldapp.AgentjailReadDeniedNames — that exclusion is the whole
// boundary (ADR 0067).
const TokenFileName = "control.token"

// tokenBytes is the raw entropy behind the token, hex-encoded on disk.
const tokenBytes = 32

// ErrNoToken reports that no token file exists. Clients get this when the
// control plane has never started; servers never should, since they create it.
var ErrNoToken = errors.New("control token not found")

// TokenPath returns the absolute path of the control-plane token file. Falls
// back to /tmp when home is unresolvable, mirroring wire.DefaultSocketPath.
func TokenPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join("/tmp", "agentjail-"+TokenFileName)
	}
	return TokenPathForHome(home)
}

// TokenPathForHome is TokenPath with an explicit home.
func TokenPathForHome(home string) string {
	return filepath.Join(home, ".agentjail", TokenFileName)
}

// Ensure returns the control token, creating it if absent. Servers call this at
// startup: the daemon, netproxy, and the secrets broker all do, concurrently.
// Concurrent starters converge on one value instead of clobbering live clients'
// token (ADR 0067).
func Ensure() (string, error) {
	return ensureAt(TokenPath())
}

// ensureAt publishes the token with write-then-link rather than O_EXCL on the
// final path.
//
// O_EXCL alone is not enough here, despite excluding a second creator: it makes
// the file visible EMPTY, before the write lands. A concurrent Ensure then sees
// EEXIST, reads an empty file, and fails — so the loser of the race errors out
// instead of adopting the winner's token. The secrets broker fails closed on a
// token error (ADR 0067), so that race can refuse to serve the control plane at
// startup, exactly when all three servers come up together.
//
// link() publishes a fully-written file in one atomic step and fails with
// EEXIST if someone else got there first, which is the property O_EXCL was
// reached for. The loser then reads a file that is complete by construction.
func ensureAt(path string) (string, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("ctlauth: mkdir %s: %w", dir, err)
	}

	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("ctlauth: generate token: %w", err)
	}
	tok := hex.EncodeToString(raw)

	tmp, err := os.CreateTemp(dir, ".control.token-*")
	if err != nil {
		return "", fmt.Errorf("ctlauth: create temp token in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // no-op once linked and unlinked below

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("ctlauth: chmod temp token: %w", err)
	}
	if _, err := tmp.WriteString(tok); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("ctlauth: write temp token: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("ctlauth: close temp token: %w", err)
	}

	if err := os.Link(tmpPath, path); err != nil {
		if os.IsExist(err) {
			// Someone won the race (or a previous run wrote it). Use theirs —
			// complete by construction, since it was linked only after writing.
			return loadAt(path)
		}
		return "", fmt.Errorf("ctlauth: link token into %s: %w", path, err)
	}
	return tok, nil
}

// Load reads the control token. Clients (CLI, shield) call this. The shield must
// call it BEFORE applying Landlock — see ADR 0067.
func Load() (string, error) {
	return loadAt(TokenPath())
}

// LoadForHome is Load with an explicit home directory.
func LoadForHome(home string) (string, error) {
	return loadAt(TokenPathForHome(home))
}

func loadAt(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrNoToken
		}
		return "", fmt.Errorf("ctlauth: read %s: %w", path, err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", fmt.Errorf("ctlauth: %s is empty", path)
	}
	return tok, nil
}

// Valid reports whether got matches want, in constant time (the caller is
// hostile by assumption and can retry a local socket freely). An empty want
// fails closed.
func Valid(got, want string) bool {
	if want == "" || got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
