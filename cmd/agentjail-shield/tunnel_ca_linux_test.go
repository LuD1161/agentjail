//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWriteTunnelCACert_NoPrivateKeyOnDisk is the S-C1 test: the tunnel CA temp
// dir must contain the public root.crt but MUST NOT contain root.key, and the
// key must be returned in memory instead. The sandboxed agent shares the host
// uid and /tmp, so any persisted key would be readable and defeat the MITM.
func TestWriteTunnelCACert_NoPrivateKeyOnDisk(t *testing.T) {
	caDir, caCert, caKey, certPath, cleanup, err := writeTunnelCACert()
	if err != nil {
		t.Fatalf("writeTunnelCACert: %v", err)
	}
	defer cleanup()

	if caKey == nil {
		t.Fatal("writeTunnelCACert returned a nil private key; key must be kept in memory")
	}
	if caCert == nil {
		t.Fatal("writeTunnelCACert returned a nil certificate; cert is needed to build the MITM handler")
	}

	// root.crt must exist.
	if _, err := os.Stat(certPath); err != nil {
		t.Errorf("root.crt missing: %v", err)
	}
	if certPath != filepath.Join(caDir, "root.crt") {
		t.Errorf("certPath = %q, want %q", certPath, filepath.Join(caDir, "root.crt"))
	}

	// root.key must NOT exist anywhere in the dir.
	if _, err := os.Stat(filepath.Join(caDir, "root.key")); !os.IsNotExist(err) {
		t.Errorf("root.key must not be persisted (S-C1); stat err = %v", err)
	}

	entries, err := os.ReadDir(caDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if e.Name() == "root.key" {
			t.Errorf("found root.key on disk in %s — CA key persisted (S-C1)", caDir)
		}
	}
}
