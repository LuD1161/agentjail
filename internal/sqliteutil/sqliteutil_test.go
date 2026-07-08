package sqliteutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEscapeDSNPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/home/u/.agentjail/db.sqlite", "/home/u/.agentjail/db.sqlite"},
		{"/tmp/weird?name#1.db", "/tmp/weird%3Fname%231.db"},
		{"/tmp/100%done.db", "/tmp/100%25done.db"},
	}
	for _, c := range cases {
		if got := EscapeDSNPath(c.in); got != c.want {
			t.Errorf("EscapeDSNPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestClampLimit(t *testing.T) {
	cases := []struct {
		n, def, max, want int
	}{
		{0, 100, 10000, 100},
		{-5, 50, 10000, 50},
		{25, 100, 10000, 25},
		{99999, 100, 10000, 10000},
	}
	for _, c := range cases {
		if got := ClampLimit(c.n, c.def, c.max); got != c.want {
			t.Errorf("ClampLimit(%d, %d, %d) = %d, want %d", c.n, c.def, c.max, got, c.want)
		}
	}
}

func TestChmodDBFiles(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "test.db")
	for _, p := range []string{db, db + "-wal", db + "-shm"} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := ChmodDBFiles(db, 0o600); err != nil {
		t.Fatalf("ChmodDBFiles: %v", err)
	}
	for _, p := range []string{db, db + "-wal", db + "-shm"} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %o, want 600", p, fi.Mode().Perm())
		}
	}

	// Missing DB file must surface an error.
	if err := ChmodDBFiles(filepath.Join(dir, "nope.db"), 0o600); err == nil {
		t.Error("expected error chmod-ing a missing DB file")
	}
}
