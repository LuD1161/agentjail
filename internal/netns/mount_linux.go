//go:build linux

package netns

import (
	"fmt"
	"os"
	"os/exec"
)

// Well-known system CA trust store paths.
var caTrustPaths = []string{
	"/etc/ssl/certs/ca-certificates.crt",    // Debian, Ubuntu, Alpine
	"/etc/pki/tls/certs/ca-bundle.crt",      // RHEL, CentOS, Fedora
	"/etc/ssl/ca-bundle.pem",                 // openSUSE
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // RHEL (p11-kit)
}

// CATrustPaths returns the system trust store paths this package bind-mounts
// over, in preference order. Exported so the env-var side of the CA contract
// reads the same list rather than keeping its own copy: the bind-mounted store
// and the bundle named by SSL_CERT_FILE must contain the same roots, and two
// lists would drift. ADR 0034-platform-backend-shared-contract, AGE-221.
func CATrustPaths() []string {
	return append([]string(nil), caTrustPaths...)
}

// InjectCA bind-mounts a CA certificate file over the system trust store
// inside the mount namespace.  The host trust store is untouched because
// the namespace has its own mount table (CLONE_NEWNS).
//
// The function:
//  1. Reads the existing system trust store (first path found from
//     caTrustPaths).
//  2. Appends the agentjail CA cert from caPath.
//  3. Writes the combined bundle to a temp file.
//  4. Bind-mounts the temp file over the trust store inside the namespace.
//
// This lets the MITM proxy's CA be trusted by tools running inside the
// namespace without modifying the host's trust store.
func (ns *Namespace) InjectCA(caPath string) error {
	// Read the agentjail CA cert.
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return fmt.Errorf("read CA cert %s: %w", caPath, err)
	}

	// Find the existing system trust store.
	var trustStorePath string
	var existingBundle []byte
	for _, p := range caTrustPaths {
		data, readErr := os.ReadFile(p)
		if readErr == nil {
			trustStorePath = p
			existingBundle = data
			break
		}
	}
	if trustStorePath == "" {
		return fmt.Errorf("no system CA trust store found (checked %v)", caTrustPaths)
	}

	// Create the combined bundle: existing certs + agentjail CA.
	combined := make([]byte, 0, len(existingBundle)+1+len(caCert))
	combined = append(combined, existingBundle...)
	if len(combined) > 0 && combined[len(combined)-1] != '\n' {
		combined = append(combined, '\n')
	}
	combined = append(combined, caCert...)

	// Write combined bundle to a temp file.
	tmp, err := os.CreateTemp("", "agentjail-ca-bundle-*")
	if err != nil {
		return fmt.Errorf("create temp CA bundle: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(combined); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write temp CA bundle: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close temp CA bundle: %w", err)
	}

	// Bind-mount the combined bundle over the trust store inside the
	// namespace.  We use `mount --bind` via nsenter so the mount happens
	// in the namespace's mount table.
	mountCmd := exec.Command("mount", "--bind", tmpPath, trustStorePath)
	if out, err := ns.ExecInCombinedOutput(mountCmd); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("bind-mount CA bundle over %s: %w (output: %s)", trustStorePath, err, out)
	}

	// Also overlay any other trust store paths that exist, so tools that
	// check a different path also pick up the agentjail CA.
	for _, p := range caTrustPaths {
		if p == trustStorePath {
			continue
		}
		// Only overlay paths that actually exist on the host.
		if _, statErr := os.Stat(p); statErr != nil {
			continue
		}
		overlayCmd := exec.Command("mount", "--bind", tmpPath, p)
		if _, overlayErr := ns.ExecInCombinedOutput(overlayCmd); overlayErr != nil {
			// Non-fatal: the primary trust store was successfully
			// overlaid; additional paths are best-effort.
			fmt.Fprintf(os.Stderr, "netns: warning: could not overlay CA at %s: %v\n", p, overlayErr)
		}
	}

	// Note: we intentionally do NOT remove tmpPath here.  The bind mount
	// references the file, and we need it alive for the lifetime of the
	// namespace.  It will be cleaned up when the namespace is torn down
	// (the mount is released) and /tmp is cleaned.

	return nil
}
