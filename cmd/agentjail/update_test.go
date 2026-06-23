package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/selfupdate"
)

// fakeRelease is used to build mock version-check API responses in tests.
type fakeRelease struct {
	TagName string `json:"tag_name"`
}

// ── helpers ──────────────────────────────────────────────────────────────────

// disableSignatureVerification clears selfupdate.SigningPubKey for the duration
// of the test so mock servers don't need to serve .minisig files.
func disableSignatureVerification(t *testing.T) {
	t.Helper()
	saved := selfupdate.SigningPubKey
	selfupdate.SigningPubKey = ""
	t.Cleanup(func() { selfupdate.SigningPubKey = saved })
}

// makeFakeTarball creates a minimal .tar.gz in destDir containing the given
// binaries (each file contains its own name as content).
// Returns (tarballPath, sha256hex, tarballName).
func makeFakeTarball(t *testing.T, destDir, name string, binaries []string) (string, string, string) {
	t.Helper()
	tarballPath := filepath.Join(destDir, name)
	f, err := os.Create(tarballPath)
	if err != nil {
		t.Fatalf("create tarball: %v", err)
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	for _, bin := range binaries {
		content := []byte("fake-binary:" + bin)
		hdr := &tar.Header{
			Name:     bin,
			Typeflag: tar.TypeReg,
			Size:     int64(len(content)),
			Mode:     0o755,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header: %v", err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatalf("tar write: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("file close: %v", err)
	}

	// Compute SHA256.
	raw, err := os.ReadFile(tarballPath)
	if err != nil {
		t.Fatalf("read tarball: %v", err)
	}
	sum := sha256.Sum256(raw)
	return tarballPath, hex.EncodeToString(sum[:]), name
}

// makeSHA256SumsFile writes a SHA256SUMS file (two-space format) for the given
// (hash, filename) pairs.
func makeSHA256SumsFile(t *testing.T, destDir string, entries map[string]string) string {
	t.Helper()
	var sb strings.Builder
	for filename, hash := range entries {
		fmt.Fprintf(&sb, "%s  %s\n", hash, filename)
	}
	sumsPath := filepath.Join(destDir, "SHA256SUMS")
	if err := os.WriteFile(sumsPath, []byte(sb.String()), 0o644); err != nil {
		t.Fatalf("write SHA256SUMS: %v", err)
	}
	return sumsPath
}

// setCheckerURL overrides defaultChecker.PrimaryURL for the duration of the
// test.
func setCheckerURL(t *testing.T, url string) {
	t.Helper()
	orig := defaultChecker.PrimaryURL
	defaultChecker.PrimaryURL = url
	t.Cleanup(func() { defaultChecker.PrimaryURL = orig })
}

// setCheckerFallbackURL overrides defaultChecker.FallbackURL for the duration
// of the test.
func setCheckerFallbackURL(t *testing.T, url string) {
	t.Helper()
	orig := defaultChecker.FallbackURL
	defaultChecker.FallbackURL = url
	t.Cleanup(func() { defaultChecker.FallbackURL = orig })
}

// ── TTY refusal tests ─────────────────────────────────────────────────────────

// TestRunUpdate_RefusesWithoutTTY verifies that runUpdate returns 1 and prints
// the refusal message when there is no interactive TTY.
func TestRunUpdate_RefusesWithoutTTY(t *testing.T) {
	// Verify /dev/tty is unavailable — otherwise this test is not applicable.
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err == nil {
		tty.Close()
		t.Skip("test running in an interactive terminal; TTY-refusal test not applicable")
	}

	// Capture stderr.
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	code := runUpdate(nil)

	w.Close()
	os.Stderr = oldStderr
	var buf bytes.Buffer
	buf.ReadFrom(r)
	stderr := buf.String()

	if code != 1 {
		t.Errorf("runUpdate() = %d, want 1 (should refuse without TTY)", code)
	}
	if !strings.Contains(stderr, "REFUSED") {
		t.Errorf("runUpdate stderr should contain 'REFUSED', got: %q", stderr)
	}
	if !strings.Contains(stderr, "no interactive terminal") {
		t.Errorf("runUpdate stderr should mention 'no interactive terminal', got: %q", stderr)
	}
}

// ── performUpdate version gating tests ───────────────────────────────────────

// TestPerformUpdate_AlreadyUpToDate verifies that when current == latest,
// performUpdate prints "already up to date" and returns 0 without downloading.
func TestPerformUpdate_AlreadyUpToDate(t *testing.T) {
	// Serve a fake GitHub releases API with the same version as current.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(fakeRelease{TagName: "v1.0.0"})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	setCheckerURL(t, srv.URL)

	origVersion := version
	version = "v1.0.0"
	defer func() { version = origVersion }()

	installDir := t.TempDir()

	// Capture stdout.
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	code := performUpdate(installDir, "linux", "amd64", false)

	w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	buf.ReadFrom(r)
	stdout := buf.String()

	if code != 0 {
		t.Errorf("performUpdate() = %d, want 0 (already up to date)", code)
	}
	if !strings.Contains(stdout, "already up to date") {
		t.Errorf("performUpdate stdout should say 'already up to date', got: %q", stdout)
	}
}

// TestPerformUpdate_DevVersionSkips verifies that a non-semver current version
// ("dev") skips the update without error.
func TestPerformUpdate_DevVersionSkips(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(fakeRelease{TagName: "v1.0.0"})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	setCheckerURL(t, srv.URL)

	origVersion := version
	version = "dev"
	defer func() { version = origVersion }()

	installDir := t.TempDir()
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	code := performUpdate(installDir, "linux", "amd64", false)

	w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	buf.ReadFrom(r)
	stdout := buf.String()

	if code != 0 {
		t.Errorf("performUpdate() = %d, want 0 (dev version skip)", code)
	}
	if !strings.Contains(stdout, "development version") {
		t.Errorf("performUpdate stdout should mention 'development version', got: %q", stdout)
	}
}

// TestPerformUpdate_FetchFails verifies that a network error exits with code 1.
func TestPerformUpdate_FetchFails(t *testing.T) {
	// Point at a server that always returns 500.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	setCheckerURL(t, srv.URL)
	setCheckerFallbackURL(t, srv.URL)

	origVersion := version
	version = "v1.0.0"
	defer func() { version = origVersion }()

	installDir := t.TempDir()
	code := performUpdate(installDir, "linux", "amd64", false)
	if code != 1 {
		t.Errorf("performUpdate() = %d, want 1 (version fetch failure)", code)
	}
}

// TestPerformUpdate_SHA256Mismatch verifies that a tampered tarball is rejected.
func TestPerformUpdate_SHA256Mismatch(t *testing.T) {
	disableSignatureVerification(t)
	srcDir := t.TempDir()
	installDir := t.TempDir()

	tarball := "agentjail-v2.0.0-linux-amd64.tar.gz"
	// Create a valid tarball.
	tarballPath, _, _ := makeFakeTarball(t, srcDir, tarball, []string{"agentjail"})
	tarballBytes, _ := os.ReadFile(tarballPath)

	// Create SHA256SUMS with a WRONG hash.
	wrongHash := strings.Repeat("0", 64)
	sumsContent := fmt.Sprintf("%s  %s\n", wrongHash, tarball)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.HasSuffix(path, "SHA256SUMS") {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(sumsContent))
		} else if strings.HasSuffix(path, tarball) {
			w.WriteHeader(200)
			_, _ = w.Write(tarballBytes)
		} else if strings.HasSuffix(path, "releases/latest") {
			b, _ := json.Marshal(fakeRelease{TagName: "v2.0.0"})
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			_, _ = w.Write(b)
		} else {
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	// Override the version check URL and the update URL base.
	setCheckerURL(t, srv.URL+"/releases/latest")

	// Patch updateURLBase by overriding version so the tarball name matches.
	origVersion := version
	version = "v1.0.0"
	defer func() { version = origVersion }()

	// Override the URL helper used by performUpdate.
	origUpdateURLBaseFn := updateURLBaseFn
	updateURLBaseFn = func(ver string) string { return srv.URL }
	defer func() { updateURLBaseFn = origUpdateURLBaseFn }()

	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	code := performUpdate(installDir, "linux", "amd64", false)

	w.Close()
	os.Stderr = oldStderr
	var buf bytes.Buffer
	buf.ReadFrom(r)
	stderr := buf.String()

	if code != 1 {
		t.Errorf("performUpdate() = %d, want 1 (SHA256 mismatch)", code)
	}
	if !strings.Contains(stderr, "SHA256") && !strings.Contains(stderr, "mismatch") && !strings.Contains(stderr, "hash") {
		t.Errorf("performUpdate stderr should mention hash failure, got: %q", stderr)
	}
}

// TestPerformUpdate_AtomicSwap verifies end-to-end binary replacement with a
// mock HTTP server serving the tarball, valid SHA256SUMS, and the version API.
func TestPerformUpdate_AtomicSwap(t *testing.T) {
	disableSignatureVerification(t)
	srcDir := t.TempDir()
	installDir := t.TempDir()

	// Create a fake v2.0.0 tarball containing all expected binaries.
	bins := []string{"agentjail", "agentjail-hook", "agentjail-daemon"}
	tarball := "agentjail-v2.0.0-linux-amd64.tar.gz"
	tarballPath, hashHex, _ := makeFakeTarball(t, srcDir, tarball, bins)
	tarballBytes, _ := os.ReadFile(tarballPath)
	sumsContent := fmt.Sprintf("%s  %s\n", hashHex, tarball)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "SHA256SUMS"):
			w.WriteHeader(200)
			_, _ = w.Write([]byte(sumsContent))
		case strings.HasSuffix(path, tarball):
			w.WriteHeader(200)
			_, _ = w.Write(tarballBytes)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	// Fake version server.
	verSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(fakeRelease{TagName: "v2.0.0"})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(b)
	}))
	defer verSrv.Close()

	setCheckerURL(t, verSrv.URL)

	origVersion := version
	version = "v1.0.0"
	defer func() { version = origVersion }()

	origURLFn := updateURLBaseFn
	updateURLBaseFn = func(ver string) string { return srv.URL }
	defer func() { updateURLBaseFn = origURLFn }()

	code := performUpdate(installDir, "linux", "amd64", false)
	if code != 0 {
		t.Fatalf("performUpdate() = %d, want 0", code)
	}

	// All three binaries should be present and have the expected content.
	for _, bin := range bins {
		dst := filepath.Join(installDir, bin)
		fi, err := os.Stat(dst)
		if err != nil {
			t.Errorf("binary %s not installed: %v", bin, err)
			continue
		}
		if fi.Mode().Perm() != 0o755 {
			t.Errorf("binary %s mode = %04o, want 0755", bin, fi.Mode().Perm())
		}
		content, _ := os.ReadFile(dst)
		if string(content) != "fake-binary:"+bin {
			t.Errorf("binary %s content = %q, want %q", bin, content, "fake-binary:"+bin)
		}
	}
}

// ── --force flag tests ────────────────────────────────────────────────────────

// TestPerformUpdate_ForceReinstall verifies that --force reinstalls the same version.
func TestPerformUpdate_ForceReinstall(t *testing.T) {
	disableSignatureVerification(t)
	srcDir := t.TempDir()
	installDir := t.TempDir()

	bins := []string{"agentjail", "agentjail-hook"}
	tarball := "agentjail-v1.0.0-linux-amd64.tar.gz"
	tarballPath, hashHex, _ := makeFakeTarball(t, srcDir, tarball, bins)
	tarballBytes, _ := os.ReadFile(tarballPath)
	sumsContent := fmt.Sprintf("%s  %s\n", hashHex, tarball)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "SHA256SUMS"):
			w.WriteHeader(200)
			_, _ = w.Write([]byte(sumsContent))
		case strings.HasSuffix(path, tarball):
			w.WriteHeader(200)
			_, _ = w.Write(tarballBytes)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	// Same version reported by the fake version server.
	verSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(fakeRelease{TagName: "v1.0.0"})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(b)
	}))
	defer verSrv.Close()

	setCheckerURL(t, verSrv.URL)

	origVersion := version
	version = "v1.0.0"
	defer func() { version = origVersion }()

	origURLFn := updateURLBaseFn
	updateURLBaseFn = func(ver string) string { return srv.URL }
	defer func() { updateURLBaseFn = origURLFn }()

	// With force=true, same version should be reinstalled (exit 0).
	code := performUpdate(installDir, "linux", "amd64", true)
	if code != 0 {
		t.Fatalf("performUpdate(force=true) = %d, want 0 (same version reinstall)", code)
	}
	for _, bin := range bins {
		if _, err := os.Stat(filepath.Join(installDir, bin)); err != nil {
			t.Errorf("binary %s not installed after force reinstall: %v", bin, err)
		}
	}
}

// TestPerformUpdate_DowngradeRefused verifies downgrade is refused even with --force.
func TestPerformUpdate_DowngradeRefused(t *testing.T) {
	// Latest reported is older than current.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(fakeRelease{TagName: "v1.0.0"})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	setCheckerURL(t, srv.URL)

	origVersion := version
	version = "v2.0.0" // current is newer
	defer func() { version = origVersion }()

	installDir := t.TempDir()

	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	// With force=true, downgrade should still be refused (exit 0 = "refused, not an error").
	code := performUpdate(installDir, "linux", "amd64", true)

	w.Close()
	os.Stderr = oldStderr
	var buf bytes.Buffer
	buf.ReadFrom(r)
	stderr := buf.String()

	if code != 0 {
		t.Errorf("performUpdate(force=true, downgrade) = %d, want 0 (refused cleanly)", code)
	}
	if !strings.Contains(stderr, "downgrade not supported") {
		t.Errorf("stderr should mention 'downgrade not supported', got: %q", stderr)
	}
}

// ── backup/rollback tests ─────────────────────────────────────────────────────

// TestPerformUpdate_RollbackOnSwapFailure verifies that when an atomic swap
// fails mid-way, already-swapped binaries are restored from backup.
func TestPerformUpdate_RollbackOnSwapFailure(t *testing.T) {
	disableSignatureVerification(t)
	srcDir := t.TempDir()
	installDir := t.TempDir()

	// Only include a subset of binaries in the tarball.
	bins := []string{"agentjail"}
	tarball := "agentjail-v2.0.0-linux-amd64.tar.gz"
	tarballPath, hashHex, _ := makeFakeTarball(t, srcDir, tarball, bins)
	tarballBytes, _ := os.ReadFile(tarballPath)
	sumsContent := fmt.Sprintf("%s  %s\n", hashHex, tarball)

	// Pre-install an "old" binary so there is something to roll back to.
	oldContent := []byte("old-binary:agentjail")
	if err := os.WriteFile(filepath.Join(installDir, "agentjail"), oldContent, 0o755); err != nil {
		t.Fatalf("pre-install agentjail: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "SHA256SUMS"):
			w.WriteHeader(200)
			_, _ = w.Write([]byte(sumsContent))
		case strings.HasSuffix(path, tarball):
			w.WriteHeader(200)
			_, _ = w.Write(tarballBytes)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	verSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(fakeRelease{TagName: "v2.0.0"})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(b)
	}))
	defer verSrv.Close()

	setCheckerURL(t, verSrv.URL)

	origVersion := version
	version = "v1.0.0"
	defer func() { version = origVersion }()

	origURLFn := updateURLBaseFn
	updateURLBaseFn = func(ver string) string { return srv.URL }
	defer func() { updateURLBaseFn = origURLFn }()

	code := performUpdate(installDir, "linux", "amd64", false)
	if code != 0 {
		t.Fatalf("performUpdate() = %d, want 0", code)
	}
	got, _ := os.ReadFile(filepath.Join(installDir, "agentjail"))
	if string(got) != "fake-binary:agentjail" {
		t.Errorf("agentjail content after update = %q, want %q", got, "fake-binary:agentjail")
	}
}

// ── resolveExecutablePath tests ───────────────────────────────────────────────

func TestResolveExecutablePath_ReturnsNonEmpty(t *testing.T) {
	path, _ := selfupdate.ResolveExecutablePath()
	if path == "" {
		t.Error("ResolveExecutablePath returned empty path")
	}
}

func TestResolveExecutablePath_DetectsHomebrew(t *testing.T) {
	// The test binary runs from a temp dir, not a Homebrew Cellar, so it
	// must NOT be detected as brew-managed.
	_, brew := selfupdate.ResolveExecutablePath()
	if brew {
		t.Error("test binary should not be detected as brew-managed")
	}
}

// ── featureName includes "update" ─────────────────────────────────────────────

func TestFeatureName_Update(t *testing.T) {
	got := featureName("update")
	if got != "update" {
		t.Errorf("featureName(\"update\") = %q, want \"update\"", got)
	}
}
