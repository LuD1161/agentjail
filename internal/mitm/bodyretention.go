package mitm

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// SweepBodies deletes body files under dir whose mtime is older than maxAge,
// then removes any session dir left empty. now is injected so the age test is
// deterministic. See ADR 0092-persist-request-bodies (D2).
//
// The body tree is same-uid writable (ADR 0076 S-C1), so every entry is
// untrusted: symlinked session dirs are refused, never followed, and no path
// outside dir is ever removed. A single bad entry is logged and skipped so it
// cannot leave newer files un-swept. Returns the count removed and the first
// error seen (best-effort).
func SweepBodies(dir string, maxAge time.Duration, now time.Time) (removed int, err error) {
	cutoff := now.Add(-maxAge)
	entries, rderr := os.ReadDir(dir)
	if rderr != nil {
		if errors.Is(rderr, os.ErrNotExist) {
			return 0, nil // no store yet is not an error
		}
		return 0, fmt.Errorf("mitm/bodyretention: read %s: %w", dir, rderr)
	}

	var firstErr error
	note := func(e error) {
		slog.Warn("body retention: skipping entry", "err", e)
		if firstErr == nil {
			firstErr = e
		}
	}

	for _, e := range entries {
		sessionDir, ok := childUnder(dir, e.Name())
		if !ok {
			note(fmt.Errorf("mitm/bodyretention: refusing path %q", e.Name()))
			continue
		}
		fi, lerr := os.Lstat(sessionDir)
		if lerr != nil {
			note(lerr)
			continue
		}
		// A symlinked session dir would re-point deletes outside the tree.
		if fi.Mode()&os.ModeSymlink != 0 {
			note(fmt.Errorf("mitm/bodyretention: symlinked session dir %q", e.Name()))
			continue
		}
		if !fi.IsDir() {
			continue // stray file at the root; not ours to age out
		}
		n, serr := sweepSession(sessionDir, cutoff)
		removed += n
		if serr != nil {
			note(serr)
		}
	}
	return removed, firstErr
}

// sweepSession deletes aged-out files in one session dir and removes the dir if
// it is left empty. Each file is Lstat'd; symlinks are never followed.
func sweepSession(sessionDir string, cutoff time.Time) (removed int, err error) {
	files, rderr := os.ReadDir(sessionDir)
	if rderr != nil {
		return 0, rderr
	}
	var firstErr error
	remaining := 0
	for _, f := range files {
		p, ok := childUnder(sessionDir, f.Name())
		if !ok {
			remaining++
			if firstErr == nil {
				firstErr = fmt.Errorf("mitm/bodyretention: refusing path %q", f.Name())
			}
			continue
		}
		fi, lerr := os.Lstat(p)
		if lerr != nil {
			remaining++
			if firstErr == nil {
				firstErr = lerr
			}
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 || fi.IsDir() {
			remaining++ // don't follow symlinks; nested dirs are not our layout
			continue
		}
		if fi.ModTime().After(cutoff) {
			remaining++
			continue
		}
		if rmerr := os.Remove(p); rmerr != nil {
			remaining++
			if firstErr == nil {
				firstErr = rmerr
			}
			continue
		}
		removed++
	}
	if remaining == 0 {
		if rmerr := os.Remove(sessionDir); rmerr != nil && firstErr == nil {
			firstErr = rmerr
		}
	}
	return removed, firstErr
}

// childUnder joins name onto parent and confirms the result stays a direct
// child of parent, so a crafted name cannot walk out of the tree.
func childUnder(parent, name string) (string, bool) {
	p := filepath.Join(parent, name)
	if filepath.Dir(p) != filepath.Clean(parent) {
		return "", false
	}
	return p, true
}
