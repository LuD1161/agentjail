package updater

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	minisign "github.com/jedisct1/go-minisign"
)

// VerifySignature verifies that the SHA256SUMS file at sumsPath has a valid
// minisign signature at sigPath, using the provided base64-encoded public key
// string (the single-line key, not including any "untrusted comment" prefix).
func VerifySignature(sumsPath, sigPath, pubKeyStr string) error {
	pk, err := minisign.NewPublicKey(pubKeyStr)
	if err != nil {
		return fmt.Errorf("updater: parse public key: %w", err)
	}

	sig, err := minisign.NewSignatureFromFile(sigPath)
	if err != nil {
		return fmt.Errorf("updater: read signature file %q: %w", sigPath, err)
	}

	msg, err := os.ReadFile(sumsPath)
	if err != nil {
		return fmt.Errorf("updater: read sums file %q: %w", sumsPath, err)
	}

	ok, err := pk.Verify(msg, sig)
	if err != nil {
		return fmt.Errorf("updater: verify signature: %w", err)
	}
	if !ok {
		return fmt.Errorf("updater: signature verification failed for %q", sumsPath)
	}
	return nil
}

// VerifyHash reads the SHA256SUMS file at sumsPath, finds the expected hash for
// tarballName (matched by the "  <name>" suffix convention), then computes the
// actual SHA256 of the file at tarballPath and compares.
func VerifyHash(tarballPath, tarballName, sumsPath string) error {
	expected, err := findExpectedHash(sumsPath, tarballName)
	if err != nil {
		return err
	}

	actual, err := sha256File(tarballPath)
	if err != nil {
		return fmt.Errorf("updater: hash tarball %q: %w", tarballPath, err)
	}

	if !strings.EqualFold(expected, actual) {
		return fmt.Errorf("updater: hash mismatch for %q: expected %s, got %s", tarballName, expected, actual)
	}
	return nil
}

// findExpectedHash parses sumsPath looking for a line ending with "  <name>".
func findExpectedHash(sumsPath, tarballName string) (string, error) {
	f, err := os.Open(sumsPath)
	if err != nil {
		return "", fmt.Errorf("updater: open sums file %q: %w", sumsPath, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// SHA256SUMS lines are: "<hash>  <filename>"
		if strings.HasSuffix(line, "  "+tarballName) {
			parts := strings.SplitN(line, "  ", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[0]), nil
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("updater: scan sums file %q: %w", sumsPath, err)
	}
	return "", fmt.Errorf("updater: no entry for %q in %q", tarballName, sumsPath)
}

// sha256File returns the lowercase hex SHA256 digest of the file at path.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
