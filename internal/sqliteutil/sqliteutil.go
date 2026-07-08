// Package sqliteutil holds the small helpers shared by AgentJail's
// SQLite-backed stores (internal/store and internal/mitm): DSN path escaping,
// DB-file chmod, and query-limit clamping.
//
// These three helpers were duplicated verbatim in both stores; they are
// extracted here (AGE-106) so a fix reaches both by construction. The package
// is deliberately tiny and dependency-free — it wraps stdlib only.
package sqliteutil

import (
	"os"
	"strings"
)

// dsnPathReplacer escapes the characters that the modernc.org/sqlite DSN
// parser would otherwise interpret when a filesystem path is embedded in a
// "file:<path>?..." URI: '%' (escape introducer), '?' (query separator), and
// '#' (fragment separator).
var dsnPathReplacer = strings.NewReplacer("%", "%25", "?", "%3F", "#", "%23")

// EscapeDSNPath escapes a filesystem path for safe inclusion in a SQLite
// "file:<path>?..." DSN.
func EscapeDSNPath(path string) string {
	return dsnPathReplacer.Replace(path)
}

// ChmodDBFiles chmods the DB file and its -wal/-shm sidecars to mode. Sidecar
// chmod is best-effort (they may not exist yet); only the DB-file chmod error
// is returned. The parent directory's 0700 mode is the primary protection —
// this is defense-in-depth and meets the 0600 acceptance on the DB file.
func ChmodDBFiles(path string, mode os.FileMode) error {
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(path + suffix); err == nil {
			_ = os.Chmod(path+suffix, mode)
		}
	}
	return nil
}

// ClampLimit clamps a caller-supplied query LIMIT to a sane range: values <= 0
// fall back to def, and values above max are capped at max. The def/max bounds
// are passed in because each store picks its own (the decision store defaults
// to 100, the network store to 50).
func ClampLimit(n, def, max int) int {
	if n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}
