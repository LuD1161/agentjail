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
// startup. O_EXCL so concurrent starters converge on one value instead of
// clobbering live clients' token (ADR 0067).
func Ensure() (string, error) {
	return ensureAt(TokenPath())
}

func ensureAt(path string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("ctlauth: mkdir %s: %w", filepath.Dir(path), err)
	}

	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("ctlauth: generate token: %w", err)
	}
	tok := hex.EncodeToString(raw)

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			// Someone won the race (or a previous run wrote it). Use theirs.
			return loadAt(path)
		}
		return "", fmt.Errorf("ctlauth: create %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(tok); err != nil {
		return "", fmt.Errorf("ctlauth: write %s: %w", path, err)
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
