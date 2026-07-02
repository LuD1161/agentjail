package selfupdate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAcquireUpdateLock_Success(t *testing.T) {
	dir := t.TempDir()
	fl, err := AcquireUpdateLock(dir)
	if err != nil {
		t.Fatalf("AcquireUpdateLock: %v", err)
	}
	defer ReleaseUpdateLock(fl)
	lockPath := filepath.Join(dir, "update.lock")
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("lock file not created: %v", err)
	}
}

func TestAcquireUpdateLock_Contention(t *testing.T) {
	dir := t.TempDir()
	fl1, err := AcquireUpdateLock(dir)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	defer ReleaseUpdateLock(fl1)
	_, err = AcquireUpdateLock(dir)
	if err == nil {
		t.Fatal("expected error on contention, got nil")
	}
}

func TestReleaseUpdateLock_ReAcquire(t *testing.T) {
	dir := t.TempDir()
	fl, err := AcquireUpdateLock(dir)
	if err != nil {
		t.Fatalf("lock: %v", err)
	}
	if err := ReleaseUpdateLock(fl); err != nil {
		t.Fatalf("release: %v", err)
	}
	fl2, err := AcquireUpdateLock(dir)
	if err != nil {
		t.Fatalf("re-acquire: %v", err)
	}
	ReleaseUpdateLock(fl2)
}

func TestReleaseUpdateLock_Nil(t *testing.T) {
	if err := ReleaseUpdateLock(nil); err != nil {
		t.Fatalf("ReleaseUpdateLock(nil): %v", err)
	}
}
