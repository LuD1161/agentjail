// projects.go — discover known project directories from the agentjail audit database.
package mcpclient

import (
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	_ "modernc.org/sqlite"
)

// KnownProjectDirs returns unique project directories from the agentjail
// sessions table. These are projects where agents have actually run.
// If the database does not exist or cannot be read, it returns nil.
// When possible, CWDs are resolved to git repository roots so that
// subdirectory sessions are grouped under their project root.
func KnownProjectDirs(dbPath string) []string {
	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		return nil
	}
	defer db.Close()

	rows, err := db.Query("SELECT DISTINCT cwd FROM sessions WHERE cwd IS NOT NULL AND cwd != '' ORDER BY cwd")
	if err != nil {
		return nil
	}
	defer rows.Close()

	seen := make(map[string]struct{})
	for rows.Next() {
		var cwd string
		if err := rows.Scan(&cwd); err != nil {
			continue
		}
		// Try to resolve to git root; fall back to the raw CWD.
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
	// Quick check: does the directory exist?
	if _, err := os.Stat(dir); err != nil {
		return ""
	}
	// Walk up looking for .git to avoid spawning a subprocess.
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
	// Fallback: ask git.
	cmd := exec.Command("git", "-C", dir, "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
