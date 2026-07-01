// projects.go — discover known project directories from the agentjail store.
package mcpclient

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/LuD1161/agentjail/internal/store"
)

// KnownProjectDirs returns unique project directories from the agentjail
// sessions table. These are projects where agents have actually run.
// When possible, CWDs are resolved to git repository roots so that
// subdirectory sessions are grouped under their project root.
func KnownProjectDirs(s store.ReadOnlyStore) []string {
	if s == nil {
		return nil
	}
	cwds, err := s.ListDistinctCWDs(context.Background())
	if err != nil {
		return nil
	}

	seen := make(map[string]struct{})
	for _, cwd := range cwds {
		root := gitRoot(cwd)
		if root != "" {
			cwd = root
		}
		seen[cwd] = struct{}{}
	}

	dirs := make([]string, 0, len(seen))
	for d := range seen {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	return dirs
}

// gitRoot returns the git repository root for a directory, or "" if it is not
// inside a git repo or the directory does not exist.
func gitRoot(dir string) string {
	if _, err := os.Stat(dir); err != nil {
		return ""
	}
	d := filepath.Clean(dir)
	for {
		if fi, err := os.Stat(filepath.Join(d, ".git")); err == nil && fi.IsDir() {
			return d
		}
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
		d = parent
	}
	cmd := exec.Command("git", "-C", dir, "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
