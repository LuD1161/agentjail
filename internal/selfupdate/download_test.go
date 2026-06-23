package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── helpers ──────────────────────────────────────────────────────────────────

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

// ── VerifyTarball tests ───────────────────────────────────────────────────────

// TestVerifyTarball_OK verifies that a correct hash passes.
func TestVerifyTarball_OK(t *testing.T) {
	dir := t.TempDir()
	content := []byte("tarball content")
	tarballPath := filepath.Join(dir, "test.tar.gz")
	if err := os.WriteFile(tarballPath, content, 0o644); err != nil {
		t.Fatalf("write tarball: %v", err)
	}
	sum := sha256.Sum256(content)
	hashHex := hex.EncodeToString(sum[:])

	entries := map[string]string{"test.tar.gz": hashHex}
	sumsPath := makeSHA256SumsFile(t, dir, entries)

	if err := VerifyTarball(tarballPath, "test.tar.gz", sumsPath); err != nil {
		t.Errorf("VerifyTarball: unexpected error: %v", err)
	}
}

// TestVerifyTarball_Mismatch verifies that a wrong hash is rejected.
func TestVerifyTarball_Mismatch(t *testing.T) {
	dir := t.TempDir()
	content := []byte("tarball content")
	tarballPath := filepath.Join(dir, "test.tar.gz")
	if err := os.WriteFile(tarballPath, content, 0o644); err != nil {
		t.Fatalf("write tarball: %v", err)
	}

	// Wrong hash.
	entries := map[string]string{"test.tar.gz": strings.Repeat("a", 64)}
	sumsPath := makeSHA256SumsFile(t, dir, entries)

	err := VerifyTarball(tarballPath, "test.tar.gz", sumsPath)
	if err == nil {
		t.Fatal("VerifyTarball: expected error on mismatch, got nil")
	}
	// updater.VerifyHash returns "hash mismatch" phrasing.
	if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("VerifyTarball: error should mention mismatch, got: %v", err)
	}
}

// TestVerifyTarball_MissingEntry verifies that a missing entry in SHA256SUMS
// returns an error.
func TestVerifyTarball_MissingEntry(t *testing.T) {
	dir := t.TempDir()
	content := []byte("tarball content")
	tarballPath := filepath.Join(dir, "test.tar.gz")
	if err := os.WriteFile(tarballPath, content, 0o644); err != nil {
		t.Fatalf("write tarball: %v", err)
	}

	// SHA256SUMS for a different file — not for test.tar.gz.
	entries := map[string]string{"other.tar.gz": strings.Repeat("b", 64)}
	sumsPath := makeSHA256SumsFile(t, dir, entries)

	err := VerifyTarball(tarballPath, "test.tar.gz", sumsPath)
	if err == nil {
		t.Fatal("VerifyTarball: expected error for missing entry, got nil")
	}
	// updater.VerifyHash returns "no entry for" phrasing.
	if !strings.Contains(err.Error(), "no entry") {
		t.Errorf("VerifyTarball: expected 'no entry' error, got: %v", err)
	}
}

// ── ExtractTarball / extractTarGzReader tests ─────────────────────────────────

// TestExtractTarball_ExtractsBinaries verifies that binaries in the tarball
// are extracted to destDir.
func TestExtractTarball_ExtractsBinaries(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	bins := []string{"agentjail", "agentjail-hook"}
	tarballPath, _, _ := makeFakeTarball(t, srcDir, "test.tar.gz", bins)

	if err := ExtractTarball(tarballPath, dstDir); err != nil {
		t.Fatalf("ExtractTarball: %v", err)
	}

	for _, bin := range bins {
		dst := filepath.Join(dstDir, bin)
		if _, err := os.Stat(dst); err != nil {
			t.Errorf("binary %s not extracted: %v", bin, err)
		}
		got, _ := os.ReadFile(dst)
		if string(got) != "fake-binary:"+bin {
			t.Errorf("binary %s content = %q, want %q", bin, got, "fake-binary:"+bin)
		}
	}
}

// TestExtractTarball_SkipsDirectories verifies that directory entries are
// skipped gracefully.
func TestExtractTarball_SkipsDirectories(t *testing.T) {
	dstDir := t.TempDir()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	// Add a directory entry.
	_ = tw.WriteHeader(&tar.Header{Name: "somedir/", Typeflag: tar.TypeDir, Mode: 0o755})
	// Add a regular file.
	content := []byte("hello")
	_ = tw.WriteHeader(&tar.Header{Name: "somedir/file.txt", Typeflag: tar.TypeReg, Size: int64(len(content)), Mode: 0o644})
	_, _ = tw.Write(content)
	tw.Close()
	gw.Close()

	if err := extractTarGzReader(&buf, dstDir); err != nil {
		t.Fatalf("extractTarGzReader: %v", err)
	}

	// "file.txt" should be extracted (base name stripped from "somedir/file.txt").
	if _, err := os.Stat(filepath.Join(dstDir, "file.txt")); err != nil {
		t.Errorf("file.txt should have been extracted: %v", err)
	}
	// "somedir" dir should NOT be created (we skip TypeDir entries).
	if _, err := os.Stat(filepath.Join(dstDir, "somedir")); err == nil {
		t.Error("somedir should not have been created")
	}
}

// ── TarballName / UpdateURLBase tests ────────────────────────────────────────

func TestTarballName(t *testing.T) {
	cases := []struct {
		ver, goos, goarch string
		want              string
	}{
		{"v1.2.3", "darwin", "arm64", "agentjail-v1.2.3-darwin-arm64.tar.gz"},
		{"v1.2.3", "linux", "amd64", "agentjail-v1.2.3-linux-amd64.tar.gz"},
	}
	for _, tc := range cases {
		got := TarballName(tc.ver, tc.goos, tc.goarch)
		if got != tc.want {
			t.Errorf("TarballName(%q,%q,%q) = %q, want %q", tc.ver, tc.goos, tc.goarch, got, tc.want)
		}
	}
}

func TestUpdateURLBase(t *testing.T) {
	got := UpdateURLBase("v1.2.3")
	want := "https://releases.agentjail.io/download/v1.2.3"
	if got != want {
		t.Errorf("UpdateURLBase(v1.2.3) = %q, want %q", got, want)
	}
}

func TestUpdateURLBaseFallback(t *testing.T) {
	got := UpdateURLBaseFallback("v1.2.3")
	want := "https://github.com/LuD1161/agentjail/releases/download/v1.2.3"
	if got != want {
		t.Errorf("UpdateURLBaseFallback(v1.2.3) = %q, want %q", got, want)
	}
}

// ── DownloadFile tests ────────────────────────────────────────────────────────

// TestDownloadFile_LimitExceeded verifies that a download exceeding MaxDownloadBytes
// is rejected.
func TestDownloadFile_LimitExceeded(t *testing.T) {
	// Serve slightly more than MaxDownloadBytes bytes.
	oversize := int(MaxDownloadBytes) + 1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		chunk := make([]byte, 4096)
		written := 0
		for written < oversize {
			n := oversize - written
			if n > len(chunk) {
				n = len(chunk)
			}
			_, _ = w.Write(chunk[:n])
			written += n
		}
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "big.bin")
	err := DownloadFile(t.Context(), srv.URL+"/big", dst, MaxDownloadBytes)
	if err == nil {
		t.Fatal("DownloadFile: expected error for oversized download, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("DownloadFile error should mention 'exceeds', got: %v", err)
	}
}

// TestDownloadFile_WithinLimit verifies that a download at or below MaxDownloadBytes
// is allowed.
func TestDownloadFile_WithinLimit(t *testing.T) {
	content := []byte("small content")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "small.bin")
	if err := DownloadFile(t.Context(), srv.URL+"/small", dst, MaxDownloadBytes); err != nil {
		t.Fatalf("DownloadFile: unexpected error: %v", err)
	}
	got, _ := os.ReadFile(dst)
	if string(got) != string(content) {
		t.Errorf("content = %q, want %q", got, content)
	}
}
