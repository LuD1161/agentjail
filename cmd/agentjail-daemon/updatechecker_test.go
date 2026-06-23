package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/selfupdate"
)

type mockFetcher struct {
	version string
	err     error
}

func (m *mockFetcher) FetchLatestVersion(_ context.Context, _ string) (string, error) {
	return m.version, m.err
}

type mockNotifier struct {
	called  bool
	title   string
	message string
	err     error
}

func (m *mockNotifier) Send(_ context.Context, title, message string) error {
	m.called = true
	m.title = title
	m.message = message
	return m.err
}

func newTestChecker(t *testing.T, fetcher Fetcher, notifier Notifier, isBrew bool) (*UpdateChecker, string) {
	t.Helper()
	dir := t.TempDir()
	return &UpdateChecker{
		Version:  "v0.1.0",
		BasePath: dir,
		Fetcher:  fetcher,
		Notifier: notifier,
		ExeResolver: func() (string, bool) {
			return "/usr/local/bin/agentjail", isBrew
		},
		JitterFunc: func(_ time.Duration) time.Duration { return 0 },
	}, dir
}

func TestUpdateChecker_NotifiesOnNewVersion(t *testing.T) {
	fetcher := &mockFetcher{version: "v0.2.0"}
	notifier := &mockNotifier{}
	uc, _ := newTestChecker(t, fetcher, notifier, false)

	if err := uc.checkOnce(context.Background()); err != nil {
		t.Fatalf("checkOnce returned error: %v", err)
	}

	if !notifier.called {
		t.Fatal("expected notifier.Send to be called, but it was not")
	}
	if notifier.title != "agentjail" {
		t.Errorf("expected title %q, got %q", "agentjail", notifier.title)
	}
	if !strings.Contains(notifier.message, "agentjail update") {
		t.Errorf("expected message to contain %q, got %q", "agentjail update", notifier.message)
	}
}

func TestUpdateChecker_SkipsWhenSameVersion(t *testing.T) {
	fetcher := &mockFetcher{version: "v0.1.0"}
	notifier := &mockNotifier{}
	uc, _ := newTestChecker(t, fetcher, notifier, false)

	if err := uc.checkOnce(context.Background()); err != nil {
		t.Fatalf("checkOnce returned error: %v", err)
	}

	if notifier.called {
		t.Fatal("expected notifier.Send NOT to be called for same version, but it was")
	}
}

func TestUpdateChecker_ThrottleSkipsSameVersion(t *testing.T) {
	fetcher := &mockFetcher{version: "v0.2.0"}
	notifier := &mockNotifier{}
	uc, dir := newTestChecker(t, fetcher, notifier, false)

	// Pre-write the throttle file indicating we already notified for v0.2.0.
	throttlePath := filepath.Join(dir, "update-notified.version")
	if err := os.WriteFile(throttlePath, []byte("v0.2.0"), 0o600); err != nil {
		t.Fatalf("write throttle file: %v", err)
	}

	if err := uc.checkOnce(context.Background()); err != nil {
		t.Fatalf("checkOnce returned error: %v", err)
	}

	if notifier.called {
		t.Fatal("expected notifier.Send NOT to be called (throttled), but it was")
	}
}

func TestUpdateChecker_BrewMessage(t *testing.T) {
	fetcher := &mockFetcher{version: "v0.2.0"}
	notifier := &mockNotifier{}
	uc, _ := newTestChecker(t, fetcher, notifier, true) // isBrew = true

	if err := uc.checkOnce(context.Background()); err != nil {
		t.Fatalf("checkOnce returned error: %v", err)
	}

	if !notifier.called {
		t.Fatal("expected notifier.Send to be called, but it was not")
	}
	if !strings.Contains(notifier.message, "brew upgrade") {
		t.Errorf("expected message to contain %q for brew install, got %q", "brew upgrade", notifier.message)
	}
}

func TestUpdateChecker_ShutdownOnContextCancel(t *testing.T) {
	fetcher := &mockFetcher{version: "v0.1.0"}
	notifier := &mockNotifier{}
	uc, _ := newTestChecker(t, fetcher, notifier, false)
	// Use a non-zero jitter so Run blocks on the timer, not on checkOnce.
	uc.JitterFunc = func(_ time.Duration) time.Duration { return 10 * time.Minute }

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	done := make(chan struct{})
	go func() {
		uc.Run(ctx)
		close(done)
	}()

	select {
	case <-done:
		// good
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s after context cancellation")
	}
}

// newAutoUpdateChecker builds an UpdateChecker with AutoUpdate=true and a
// signing key set so the gate conditions can be tested without a real network.
func newAutoUpdateChecker(t *testing.T, isBrew bool, goos string) (*UpdateChecker, *mockNotifier) {
	t.Helper()
	dir := t.TempDir()
	notifier := &mockNotifier{}
	uc := &UpdateChecker{
		Version:  "v0.1.0",
		BasePath: dir,
		Fetcher:  &mockFetcher{version: "v0.2.0"},
		Notifier: notifier,
		ExeResolver: func() (string, bool) {
			return "/usr/local/bin/agentjail", isBrew
		},
		JitterFunc: func(_ time.Duration) time.Duration { return 0 },
		AutoUpdate: true,
		InstallDir: dir,
		PlistPath:  filepath.Join(dir, "com.agentjail.daemon.plist"),
		GOOS:       goos,
		GOARCH:     "arm64",
	}
	return uc, notifier
}

func TestUpdateChecker_AutoUpdate_SkipsWhenDisabled(t *testing.T) {
	// AutoUpdate=false: performAutoUpdate should never be called.
	// We verify this indirectly: with a real signing key set and darwin GOOS,
	// if performAutoUpdate were called it would attempt a download and either
	// panic or return an error via the notifier. With AutoUpdate=false checkOnce
	// must return nil and the notifier must not receive an auto-update failure.

	origKey := selfupdate.SigningPubKey
	selfupdate.SigningPubKey = "RWQfakekeyfortest"
	t.Cleanup(func() { selfupdate.SigningPubKey = origKey })

	uc, notifier := newAutoUpdateChecker(t, false, "darwin")
	uc.AutoUpdate = false

	exitCalled := false
	origExit := osExitFn
	osExitFn = func(code int) { exitCalled = true }
	t.Cleanup(func() { osExitFn = origExit })

	if err := uc.checkOnce(context.Background()); err != nil {
		t.Fatalf("checkOnce returned error: %v", err)
	}
	if exitCalled {
		t.Fatal("osExitFn was called but AutoUpdate=false; performAutoUpdate should have been skipped")
	}
	// Notifier may be called for the regular update notification, but not for an
	// auto-update failure message.
	if notifier.called && strings.Contains(notifier.message, "Auto-update failed") {
		t.Errorf("unexpected auto-update failure message: %q", notifier.message)
	}
}

func TestUpdateChecker_AutoUpdate_SkipsBrew(t *testing.T) {
	origKey := selfupdate.SigningPubKey
	selfupdate.SigningPubKey = "RWQfakekeyfortest"
	t.Cleanup(func() { selfupdate.SigningPubKey = origKey })

	uc, notifier := newAutoUpdateChecker(t, true /* isBrew */, "darwin")

	exitCalled := false
	origExit := osExitFn
	osExitFn = func(code int) { exitCalled = true }
	t.Cleanup(func() { osExitFn = origExit })

	if err := uc.checkOnce(context.Background()); err != nil {
		t.Fatalf("checkOnce returned error: %v", err)
	}
	if exitCalled {
		t.Fatal("osExitFn was called for a Homebrew installation; auto-update should be skipped")
	}
	if notifier.called && strings.Contains(notifier.message, "Auto-update failed") {
		t.Errorf("unexpected auto-update failure message: %q", notifier.message)
	}
}

func TestUpdateChecker_AutoUpdate_SkipsNonDarwin(t *testing.T) {
	origKey := selfupdate.SigningPubKey
	selfupdate.SigningPubKey = "RWQfakekeyfortest"
	t.Cleanup(func() { selfupdate.SigningPubKey = origKey })

	uc, notifier := newAutoUpdateChecker(t, false, "linux")

	exitCalled := false
	origExit := osExitFn
	osExitFn = func(code int) { exitCalled = true }
	t.Cleanup(func() { osExitFn = origExit })

	if err := uc.checkOnce(context.Background()); err != nil {
		t.Fatalf("checkOnce returned error: %v", err)
	}
	if exitCalled {
		t.Fatal("osExitFn was called on non-darwin; auto-update should be skipped")
	}
	if notifier.called && strings.Contains(notifier.message, "Auto-update failed") {
		t.Errorf("unexpected auto-update failure message: %q", notifier.message)
	}
}

func TestUpdateChecker_ThrottleFilePermissions(t *testing.T) {
	fetcher := &mockFetcher{version: "v0.2.0"}
	notifier := &mockNotifier{}
	uc, dir := newTestChecker(t, fetcher, notifier, false)

	if err := uc.checkOnce(context.Background()); err != nil {
		t.Fatalf("checkOnce returned error: %v", err)
	}

	if !notifier.called {
		t.Fatal("expected notifier.Send to be called")
	}

	throttlePath := filepath.Join(dir, "update-notified.version")
	info, err := os.Stat(throttlePath)
	if err != nil {
		t.Fatalf("stat throttle file: %v", err)
	}

	got := info.Mode().Perm()
	if got != 0o600 {
		t.Errorf("expected throttle file perms 0600, got %04o", got)
	}
}
