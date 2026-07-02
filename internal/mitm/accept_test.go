package mitm

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// AcceptTest_GenerateCA_FilesExist verifies that GenerateCA writes both
// root.crt and root.key to the target directory.
func TestAccept_GenerateCA_FilesExist(t *testing.T) {
	dir := t.TempDir()
	_, _, err := GenerateCA(dir)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	certPath := filepath.Join(dir, "root.crt")
	keyPath := filepath.Join(dir, "root.key")

	if _, err := os.Stat(certPath); err != nil {
		t.Errorf("root.crt missing: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("root.key missing: %v", err)
	}
}

// TestAccept_CA_SelfSigned verifies that the generated CA cert is self-signed
// (Issuer DN equals Subject DN).
func TestAccept_CA_SelfSigned(t *testing.T) {
	dir := t.TempDir()
	caCert, _, err := GenerateCA(dir)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	if caCert.Issuer.String() != caCert.Subject.String() {
		t.Errorf("cert is not self-signed: Issuer=%q Subject=%q",
			caCert.Issuer.String(), caCert.Subject.String())
	}
}

// TestAccept_CA_CommonName verifies the Subject CN is exactly
// "AgentJail Inspection CA".
func TestAccept_CA_CommonName(t *testing.T) {
	dir := t.TempDir()
	caCert, _, err := GenerateCA(dir)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	const wantCN = "AgentJail Inspection CA"
	if caCert.Subject.CommonName != wantCN {
		t.Errorf("CommonName = %q, want %q", caCert.Subject.CommonName, wantCN)
	}
}

// TestAccept_CA_IsCA verifies that BasicConstraintsValid and IsCA are both true.
func TestAccept_CA_IsCA(t *testing.T) {
	dir := t.TempDir()
	caCert, _, err := GenerateCA(dir)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	if !caCert.BasicConstraintsValid {
		t.Error("BasicConstraintsValid = false, want true")
	}
	if !caCert.IsCA {
		t.Error("IsCA = false, want true")
	}
}

// TestAccept_CA_KeyUsageCertSign verifies that the CA cert's KeyUsage
// includes KeyUsageCertSign.
func TestAccept_CA_KeyUsageCertSign(t *testing.T) {
	dir := t.TempDir()
	caCert, _, err := GenerateCA(dir)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	if caCert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Errorf("KeyUsage = %v, missing KeyUsageCertSign", caCert.KeyUsage)
	}
}

// TestAccept_CA_KeyIsRSA2048 verifies that the private key written to
// root.key is RSA with a 2048-bit modulus.
func TestAccept_CA_KeyIsRSA2048(t *testing.T) {
	dir := t.TempDir()
	_, _, err := GenerateCA(dir)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	keyPEM, err := os.ReadFile(filepath.Join(dir, "root.key"))
	if err != nil {
		t.Fatalf("read root.key: %v", err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("root.key contains no PEM block")
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse root.key: %v", err)
	}

	rsaKey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("key type = %T, want *rsa.PrivateKey", priv)
	}

	bits := rsaKey.N.BitLen()
	if bits != 2048 {
		t.Errorf("RSA modulus = %d bits, want 2048", bits)
	}
}

// TestAccept_LoadOrCreateCA_CreatesIfMissing verifies that LoadOrCreateCA
// creates root.crt and root.key when the directory is empty.
func TestAccept_LoadOrCreateCA_CreatesIfMissing(t *testing.T) {
	dir := t.TempDir()
	cert, key, tlsCert, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}
	if cert == nil {
		t.Error("cert is nil")
	}
	if key == nil {
		t.Error("key is nil")
	}
	if tlsCert == nil {
		t.Error("tlsCert is nil")
	}

	if _, err := os.Stat(filepath.Join(dir, "root.crt")); err != nil {
		t.Errorf("root.crt missing after LoadOrCreateCA: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "root.key")); err != nil {
		t.Errorf("root.key missing after LoadOrCreateCA: %v", err)
	}
}

// TestAccept_LoadOrCreateCA_LoadsIfExisting verifies that a second call to
// LoadOrCreateCA on the same directory returns the same cert (matching serial).
func TestAccept_LoadOrCreateCA_LoadsIfExisting(t *testing.T) {
	dir := t.TempDir()

	// Pre-generate so the files already exist.
	generated, _, err := GenerateCA(dir)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	loaded, _, _, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}

	if generated.SerialNumber.Cmp(loaded.SerialNumber) != 0 {
		t.Errorf("serial mismatch: generated=%s loaded=%s",
			generated.SerialNumber, loaded.SerialNumber)
	}
}

// TestAccept_CA_ValidityPeriod verifies that NotBefore is approximately now
// and NotAfter is approximately 10 years from now.
func TestAccept_CA_ValidityPeriod(t *testing.T) {
	before := time.Now()
	dir := t.TempDir()
	caCert, _, err := GenerateCA(dir)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	after := time.Now()

	// NotBefore should be within the window [before, after].
	if caCert.NotBefore.Before(before.Add(-5*time.Second)) || caCert.NotBefore.After(after.Add(5*time.Second)) {
		t.Errorf("NotBefore = %v, expected ~now (%v)", caCert.NotBefore, before)
	}

	// NotAfter should be approximately 10 years (3650 days) from NotBefore.
	wantExpiry := caCert.NotBefore.Add(10 * 365 * 24 * time.Hour)
	diff := caCert.NotAfter.Sub(wantExpiry)
	if diff < -time.Minute || diff > time.Minute {
		t.Errorf("NotAfter = %v, expected ~%v (10 years from NotBefore)", caCert.NotAfter, wantExpiry)
	}
}

// TestAccept_TwoGenerateCA_DifferentSerials verifies that two independent
// GenerateCA calls produce certs with distinct serial numbers.
func TestAccept_TwoGenerateCA_DifferentSerials(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	cert1, _, err := GenerateCA(dir1)
	if err != nil {
		t.Fatalf("GenerateCA (1): %v", err)
	}
	cert2, _, err := GenerateCA(dir2)
	if err != nil {
		t.Fatalf("GenerateCA (2): %v", err)
	}

	if cert1.SerialNumber.Cmp(cert2.SerialNumber) == 0 {
		t.Errorf("two GenerateCA calls produced the same serial %s", cert1.SerialNumber)
	}
}
