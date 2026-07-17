package mitm

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// touchBody writes a body file and stamps its mtime. Guards ADR 0092 D2 age
// selection with a fixed clock rather than wall time.
func touchBody(t *testing.T, dir, session, name string, mtime time.Time) string {
	t.Helper()
	sd := filepath.Join(dir, session)
	if err := os.MkdirAll(sd, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(sd, name)
	if err := os.WriteFile(p, []byte("body"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSweepBodies_AgeAndEmptyDirs(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	maxAge := 24 * time.Hour

	// (a) older than maxAge -> deleted; its session ends up empty -> (c) removed.
	old := touchBody(t, dir, "aaaa", "0.body", now.Add(-48*time.Hour))
	// (b) newer than maxAge -> survives; its session dir is kept.
	fresh := touchBody(t, dir, "bbbb", "1.body", now.Add(-1*time.Hour))
	// (c) a session holding both: the old file goes, the dir stays for the fresh one.
	oldInMixed := touchBody(t, dir, "cccc", "2.body", now.Add(-72*time.Hour))
	freshInMixed := touchBody(t, dir, "cccc", "3.body", now.Add(-30*time.Minute))

	removed, err := SweepBodies(dir, maxAge, now)
	if err != nil {
		t.Fatalf("sweep err: %v", err)
	}
	if removed != 2 {
		t.Fatalf("removed = %d, want 2", removed)
	}
	if _, err := os.Lstat(old); !os.IsNotExist(err) {
		t.Errorf("old file should be deleted, lstat err = %v", err)
	}
	if _, err := os.Lstat(oldInMixed); !os.IsNotExist(err) {
		t.Errorf("old file in mixed dir should be deleted, lstat err = %v", err)
	}
	if _, err := os.Lstat(fresh); err != nil {
		t.Errorf("fresh file should survive: %v", err)
	}
	if _, err := os.Lstat(freshInMixed); err != nil {
		t.Errorf("fresh file in mixed dir should survive: %v", err)
	}
	// (c) empty session dir removed; non-empty ones kept.
	if _, err := os.Lstat(filepath.Join(dir, "aaaa")); !os.IsNotExist(err) {
		t.Errorf("emptied session dir should be removed, lstat err = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "bbbb")); err != nil {
		t.Errorf("session dir with a fresh file should be kept: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "cccc")); err != nil {
		t.Errorf("mixed session dir should be kept: %v", err)
	}
}

// (d) A symlinked session dir pointing outside the tree is refused, and nothing
// it points to is touched. Guards ADR 0076 S-C1.
func TestSweepBodies_RefusesSymlinkedSessionDir(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)

	// A victim file outside the tree, older than any window.
	victim := filepath.Join(outside, "victim.body")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(victim, now.Add(-9999*time.Hour), now.Add(-9999*time.Hour)); err != nil {
		t.Fatal(err)
	}

	// A session "dir" that is really a symlink to outside.
	link := filepath.Join(dir, "evil")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}

	removed, err := SweepBodies(dir, time.Hour, now)
	if err == nil {
		t.Fatalf("expected refusal error for symlinked session dir")
	}
	if removed != 0 {
		t.Fatalf("removed = %d, want 0", removed)
	}
	if _, verr := os.Lstat(victim); verr != nil {
		t.Errorf("file outside the tree must be untouched: %v", verr)
	}
	if _, lerr := os.Lstat(link); lerr != nil {
		t.Errorf("symlink itself must not be removed: %v", lerr)
	}
}

// A missing store reads as absent, not an error.
func TestSweepBodies_MissingDir(t *testing.T) {
	removed, err := SweepBodies(filepath.Join(t.TempDir(), "nope"), time.Hour, time.Now())
	if err != nil || removed != 0 {
		t.Fatalf("missing dir: removed=%d err=%v", removed, err)
	}
}
