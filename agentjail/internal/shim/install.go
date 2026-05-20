package shim

import (
	"fmt"
	"os"
	"path/filepath"
)

// DefaultTools is the set of binaries we hard-link the shim under by default.
// Conservative for v1; users can add more by symlinking manually.
var DefaultTools = []string{
	"git", "npm", "npx", "node", "sh", "bash", "zsh",
	"rm", "mv", "cp", "ls", "cat", "curl", "wget",
	"find", "ssh", "scp",
	"python", "python3", "pip", "pip3",
	"chmod", "chown", "ln", "mkdir", "rmdir", "touch",
	"ripgrep", "rg", "fd", "jq", "sed", "awk", "grep",
	"make", "go", "cargo", "rustc",
}

func DefaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".agentjail", "shims"), nil
}

// Install populates the shim directory with symlinks pointing at the agentjail-shim binary.
// shimBin is the absolute path to the compiled shim.
func Install(shimBin string) (string, error) {
	dir, err := DefaultDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	for _, t := range DefaultTools {
		dest := filepath.Join(dir, t)
		_ = os.Remove(dest)
		if err := os.Symlink(shimBin, dest); err != nil {
			return "", fmt.Errorf("symlink %s: %w", t, err)
		}
	}
	return dir, nil
}

// FindShimBinary tries common locations relative to the agentjail executable.
func FindShimBinary() (string, error) {
	if p := os.Getenv("AGENTJAIL_SHIM_BIN"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	candidates := []string{
		filepath.Join(filepath.Dir(exe), "agentjail-shim"),
		filepath.Join(filepath.Dir(exe), "..", "libexec", "agentjail-shim"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			abs, _ := filepath.Abs(c)
			return abs, nil
		}
	}
	return "", fmt.Errorf("agentjail-shim binary not found (set AGENTJAIL_SHIM_BIN or place it next to agentjail)")
}

// IsInstalled returns true if the shim directory exists with at least one symlink.
func IsInstalled() (string, bool) {
	dir, err := DefaultDir()
	if err != nil {
		return "", false
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return dir, false
	}
	for _, e := range entries {
		if e.Type()&os.ModeSymlink != 0 {
			return dir, true
		}
	}
	return dir, false
}
