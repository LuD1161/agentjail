package keyring

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
)

// stageKEKHome points the file store at a temp XDG_CONFIG_HOME: the real
// ~/.config/agentjail is the user's own key and is never touched by tests.
func stageKEKHome(t *testing.T) string {
	t.Helper()
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	return filepath.Join(xdg, kekDirName)
}

// permissiveUmask proves the asserted modes are not just today's umask.
func permissiveUmask(t *testing.T) {
	t.Helper()
	old := syscall.Umask(0)
	t.Cleanup(func() { syscall.Umask(old) })
}

// Guards persistence: the point of the file KEK over MemoryStore.
func TestFileStoreWrapUnwrapSurvivesReopen(t *testing.T) {
	stageKEKHome(t)
	dek := []byte("0123456789abcdef0123456789abcdef")
	aad := []byte("session/body-1")

	s, err := OpenFileStore()
	if err != nil {
		t.Fatalf("OpenFileStore: %v", err)
	}
	if s.Name() != "file-kek" || s.Tier() != TierFileKEK {
		t.Fatalf("name/tier = %q/%q", s.Name(), s.Tier())
	}
	id, wrapped, err := New(s).Wrap(dek, aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	reopened, err := OpenFileStore()
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, err := New(reopened).Unwrap(id, wrapped, aad)
	if err != nil {
		t.Fatalf("Unwrap after reopen: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("dek round-trip mismatch")
	}
	if _, err := New(reopened).Unwrap(id, wrapped, []byte("other")); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("wrong aad = %v, want ErrUnwrap", err)
	}
}

func TestFileStoreModes(t *testing.T) {
	permissiveUmask(t)
	dir := stageKEKHome(t)

	s, err := OpenFileStore()
	if err != nil {
		t.Fatalf("OpenFileStore: %v", err)
	}
	if _, _, err := New(s).Wrap([]byte("dek"), nil); err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	di, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode = %#o, want 0700", di.Mode().Perm())
	}
	fi, err := os.Stat(filepath.Join(dir, "kek"))
	if err != nil {
		t.Fatalf("stat kek: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("kek mode = %#o, want 0600", fi.Mode().Perm())
	}
}

func TestFileStoreRefusesSymlink(t *testing.T) {
	dir := stageKEKHome(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	elsewhere := filepath.Join(t.TempDir(), "elsewhere-kek")
	if err := os.WriteFile(elsewhere, []byte(`{"items":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(dir, "kek")); err != nil {
		t.Fatal(err)
	}

	if _, err := OpenFileStore(); !errors.Is(err, ErrKEKFileSymlink) {
		t.Fatalf("OpenFileStore = %v, want ErrKEKFileSymlink", err)
	}
}

func TestFileStoreRefusesSymlinkedDir(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	target := filepath.Join(t.TempDir(), "real")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(xdg, kekDirName)); err != nil {
		t.Fatal(err)
	}

	if _, err := OpenFileStore(); !errors.Is(err, ErrKEKFileSymlink) {
		t.Fatalf("OpenFileStore = %v, want ErrKEKFileSymlink", err)
	}
}

func TestFileStoreRefusesWorldReadableKEK(t *testing.T) {
	dir := stageKEKHome(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "kek")
	if err := os.WriteFile(path, []byte(`{"items":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := OpenFileStore(); !errors.Is(err, ErrKEKFilePerms) {
		t.Fatalf("OpenFileStore = %v, want ErrKEKFilePerms", err)
	}
}

// Guards that two daemons starting together do not produce two KEKs.
func TestFileStoreConcurrentMintConverges(t *testing.T) {
	stageKEKHome(t)
	const racers = 8

	ids := make([]string, racers)
	errs := make([]error, racers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			s, err := OpenFileStore()
			if err != nil {
				errs[i] = err
				return
			}
			ids[i], _, errs[i] = New(s).Wrap([]byte("dek"), nil)
		}()
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("racer %d: %v", i, err)
		}
	}
	for i, id := range ids {
		if id != ids[0] {
			t.Fatalf("racer %d minted KEK %s, racer 0 minted %s: mint did not converge", i, id, ids[0])
		}
	}

	s, err := OpenFileStore()
	if err != nil {
		t.Fatal(err)
	}
	cur, err := s.Get(CurrentAccount())
	if err != nil {
		t.Fatalf("get current: %v", err)
	}
	if string(cur) != ids[0] {
		t.Fatalf("current = %s, want %s", cur, ids[0])
	}
}

func TestKEKFilePathHonoursXDG(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	p, err := KEKFilePath()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(xdg, "agentjail", "kek"); p != want {
		t.Fatalf("KEKFilePath = %q, want %q", p, want)
	}
}
