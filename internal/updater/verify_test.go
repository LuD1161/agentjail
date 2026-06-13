package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// testPubKey is a minisign public key generated for tests only (no passphrase).
// Generated with: minisign -G -p /tmp/agentjail-test.pub -s /tmp/agentjail-test.key -W
const testPubKey = "RWTPsStk1McQwH9zAmYqC1Ge/Vj++o0tkJsehqFDVRaEtv7tf3zdR5T1"

// testSumsContent is the SHA256SUMS file that was signed to produce testSigContent.
const testSumsContent = "abc123def456  agentjail-v1.0.0-darwin-arm64.tar.gz\n"

// testSigContent is the .minisig file produced by:
//
//	echo "abc123def456  agentjail-v1.0.0-darwin-arm64.tar.gz" > /tmp/test-SHA256SUMS
//	minisign -S -s /tmp/agentjail-test.key -m /tmp/test-SHA256SUMS
const testSigContent = `untrusted comment: signature from minisign secret key
RUTPsStk1McQwDx3wawJg+bF/XPz/aNRjLQQJQ0QQxjZjCFn90E0OmDqmUK5/uMCScw7Xu5udOzc0+jyHMTfM0OPl5gAEFaMZwE=
trusted comment: timestamp:1781329099	file:test-SHA256SUMS	hashed
rsdfKu10NmV2E7sxQtvIcFPiEv5Ldk1TPO/VYeQwvS5DE479SCF8fB3+q8x9jnunlykZQRU/YUVmrypPDffeAQ==`

// setupSigFiles creates the SHA256SUMS and .minisig temp files and returns their paths.
func setupSigFiles(t *testing.T) (sumsPath, sigPath string) {
	t.Helper()
	dir := t.TempDir()
	sumsPath = filepath.Join(dir, "SHA256SUMS")
	if err := os.WriteFile(sumsPath, []byte(testSumsContent), 0o600); err != nil {
		t.Fatalf("write sums file: %v", err)
	}
	sigPath = filepath.Join(dir, "SHA256SUMS.minisig")
	if err := os.WriteFile(sigPath, []byte(testSigContent), 0o600); err != nil {
		t.Fatalf("write sig file: %v", err)
	}
	return sumsPath, sigPath
}

// TestVerifySignature_Valid checks that a valid signature passes.
func TestVerifySignature_Valid(t *testing.T) {
	sumsPath, sigPath := setupSigFiles(t)
	if err := VerifySignature(sumsPath, sigPath, testPubKey); err != nil {
		t.Fatalf("expected valid signature to pass, got: %v", err)
	}
}

// TestVerifySignature_Invalid checks that a tampered signature fails.
func TestVerifySignature_Invalid(t *testing.T) {
	sumsPath, _ := setupSigFiles(t)
	// Write a signature file with a corrupted base64 payload.
	dir := t.TempDir()
	badSigPath := filepath.Join(dir, "SHA256SUMS.minisig")
	tampered := `untrusted comment: signature from minisign secret key
RUTPsStk1McQwDx3wawJg+bF/XPz/aNRjLQQJQ0QQxjZjCFn90E0OmDqmUK5/uMCScw7Xu5udOzc0+jyHMTfM0OPl5gAEFAAAAA=
trusted comment: timestamp:1781329099	file:test-SHA256SUMS	hashed
rsdfKu10NmV2E7sxQtvIcFPiEv5Ldk1TPO/VYeQwvS5DE479SCF8fB3+q8x9jnunlykZQRU/YUVmrypPDffeAQ==`
	if err := os.WriteFile(badSigPath, []byte(tampered), 0o600); err != nil {
		t.Fatalf("write bad sig: %v", err)
	}
	if err := VerifySignature(sumsPath, badSigPath, testPubKey); err == nil {
		t.Fatal("expected tampered signature to fail, but it passed")
	}
}

// TestVerifySignature_MissingSigFile checks that a missing .minisig file returns an error.
func TestVerifySignature_MissingSigFile(t *testing.T) {
	sumsPath, _ := setupSigFiles(t)
	missingPath := filepath.Join(t.TempDir(), "nonexistent.minisig")
	if err := VerifySignature(sumsPath, missingPath, testPubKey); err == nil {
		t.Fatal("expected error for missing sig file, got nil")
	}
}

// TestVerifyHash_Match checks that the correct hash passes.
func TestVerifyHash_Match(t *testing.T) {
	dir := t.TempDir()

	// Create a fake tarball with known content.
	tarContent := []byte("fake tarball content for testing")
	tarPath := filepath.Join(dir, "agentjail-v1.0.0-darwin-arm64.tar.gz")
	if err := os.WriteFile(tarPath, tarContent, 0o600); err != nil {
		t.Fatalf("write tarball: %v", err)
	}

	// Compute its actual hash.
	h := sha256.Sum256(tarContent)
	hashStr := hex.EncodeToString(h[:])

	// Write a SUMS file referencing it.
	sumsContent := hashStr + "  agentjail-v1.0.0-darwin-arm64.tar.gz\n"
	sumsPath := filepath.Join(dir, "SHA256SUMS")
	if err := os.WriteFile(sumsPath, []byte(sumsContent), 0o600); err != nil {
		t.Fatalf("write sums file: %v", err)
	}

	if err := VerifyHash(tarPath, "agentjail-v1.0.0-darwin-arm64.tar.gz", sumsPath); err != nil {
		t.Fatalf("expected hash match to pass, got: %v", err)
	}
}

// TestVerifyHash_Mismatch checks that a wrong hash returns an error.
func TestVerifyHash_Mismatch(t *testing.T) {
	dir := t.TempDir()

	tarContent := []byte("real content")
	tarPath := filepath.Join(dir, "agentjail-v1.0.0-linux-amd64.tar.gz")
	if err := os.WriteFile(tarPath, tarContent, 0o600); err != nil {
		t.Fatalf("write tarball: %v", err)
	}

	// Put a wrong hash in the SUMS file.
	sumsContent := "0000000000000000000000000000000000000000000000000000000000000000  agentjail-v1.0.0-linux-amd64.tar.gz\n"
	sumsPath := filepath.Join(dir, "SHA256SUMS")
	if err := os.WriteFile(sumsPath, []byte(sumsContent), 0o600); err != nil {
		t.Fatalf("write sums file: %v", err)
	}

	if err := VerifyHash(tarPath, "agentjail-v1.0.0-linux-amd64.tar.gz", sumsPath); err == nil {
		t.Fatal("expected hash mismatch to fail, but it passed")
	}
}

// TestVerifyHash_MissingEntry checks that an absent tarball name in the SUMS file fails.
func TestVerifyHash_MissingEntry(t *testing.T) {
	dir := t.TempDir()

	tarContent := []byte("some content")
	tarPath := filepath.Join(dir, "agentjail-v2.0.0-darwin-arm64.tar.gz")
	if err := os.WriteFile(tarPath, tarContent, 0o600); err != nil {
		t.Fatalf("write tarball: %v", err)
	}

	// SUMS file exists but has a different filename.
	sumsContent := "abc123  agentjail-v1.0.0-darwin-arm64.tar.gz\n"
	sumsPath := filepath.Join(dir, "SHA256SUMS")
	if err := os.WriteFile(sumsPath, []byte(sumsContent), 0o600); err != nil {
		t.Fatalf("write sums file: %v", err)
	}

	if err := VerifyHash(tarPath, "agentjail-v2.0.0-darwin-arm64.tar.gz", sumsPath); err == nil {
		t.Fatal("expected missing entry to fail, but it passed")
	}
}
