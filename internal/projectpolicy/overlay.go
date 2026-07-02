// Package projectpolicy resolves per-folder `./.agentjail/policy.yaml` overlays
// under a direnv-style trust gate.
//
// A project overlay lets a repo widen its own egress (e.g. add an internal DB
// host) via a checked-in file. Because that file is attacker-controllable (you
// clone the repo), it is IGNORED until the user explicitly trusts the directory
// with `agentjail trust`. Trust records the file's content hash; editing the
// file after trusting it revokes trust until re-approved. The overlay merge is
// additive-only (config.MergeProjectOverlay), so even a trusted overlay can only
// widen allow-lists, never weaken a global restriction.
//
// The trust store (~/.agentjail/trusted.yaml) is tamper-proof against the agent
// only because agentjail-shield makes ~/.agentjail agent-unwritable (ADR 0042
// invariant 0): the agent cannot add itself to the trust list.
package projectpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
)

const (
	// ProjectDirName is the per-project agentjail directory.
	ProjectDirName = ".agentjail"
	// ProjectPolicyFile is the overlay filename inside ProjectDirName.
	ProjectPolicyFile = "policy.yaml"
	// TrustFileName is the trust store filename inside the user's ~/.agentjail.
	TrustFileName = "trusted.yaml"
)

// Overlay is a discovered project overlay file and its content hash.
type Overlay struct {
	// Dir is the project directory that contains ProjectDirName/ProjectPolicyFile.
	Dir string
	// Path is the absolute path to the overlay policy.yaml.
	Path string
	// Content is the raw file bytes.
	Content []byte
	// ContentHash is the lowercase hex sha256 of Content; trust is keyed on it
	// so an edit after trusting revokes trust.
	ContentHash string
}

func newOverlay(dir, path string, content []byte) *Overlay {
	return &Overlay{
		Dir:         dir,
		Path:        path,
		Content:     content,
		ContentHash: HashContent(content),
	}
}

// HashContent returns the lowercase hex sha256 of content -- the value trust is
// keyed on. Exported so callers (e.g. `agentjail trust list`) can recompute a
// file's hash to check whether a trusted overlay still matches.
func HashContent(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// FindOverlay searches for a project overlay starting at startDir and walking
// upward. It ascends only within a git repository (stopping at the git root);
// if startDir is not inside a repo, only startDir itself is checked. The user's
// home directory is never treated as a project (that is the GLOBAL
// ~/.agentjail/policy.yaml, not an overlay). Returns (nil, nil) if none found.
func FindOverlay(startDir, homeDir string) (*Overlay, error) {
	start := filepath.Clean(startDir)
	home := filepath.Clean(homeDir)
	ceiling := gitRoot(start) // "" if not inside a repo

	dir := start
	for {
		if dir != home {
			candidate := filepath.Join(dir, ProjectDirName, ProjectPolicyFile)
			data, err := os.ReadFile(candidate)
			if err == nil {
				return newOverlay(dir, candidate, data), nil
			}
			if !os.IsNotExist(err) {
				return nil, err
			}
		}
		// Not in a repo -> only startDir. In a repo -> stop at the git root.
		if ceiling == "" || dir == ceiling {
			return nil, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil, nil // filesystem root
		}
		dir = parent
	}
}

// gitRoot returns the nearest ancestor of dir (inclusive) that contains a .git
// entry, or "" if none is found before the filesystem root.
func gitRoot(dir string) string {
	d := filepath.Clean(dir)
	for {
		if _, err := os.Stat(filepath.Join(d, ".git")); err == nil {
			return d
		}
		parent := filepath.Dir(d)
		if parent == d {
			return ""
		}
		d = parent
	}
}
