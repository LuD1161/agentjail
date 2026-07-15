//go:build linux

package shieldapp

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"github.com/LuD1161/agentjail/internal/mitm"
	"github.com/LuD1161/agentjail/internal/netns"
)

// setupTunnelCA generates the ephemeral tunnel MITM CA and injects only its
// public certificate (root.crt) into the agent's mount namespace trust store.
// It returns the CA certificate and private key (both in memory) so the caller
// can build a mitm.MITMHandler that signs leaf certs the injected trust store
// accepts.
//
// SECURITY (S-C1): the CA private key is generated in memory and NEVER written
// to disk. The sandboxed agent runs as the same host uid with the host /tmp
// mounted, so a 0600 root.key would still be readable by the agent, letting it
// mint certs the injected trust store accepts. We therefore keep the key in
// memory and persist only the certificate, which is public.
func setupTunnelCA(ns *netns.Namespace) (caDir string, caCert *x509.Certificate, caKey crypto.PrivateKey, cleanup func(), err error) {
	caDir, caCert, caKey, certPath, cleanup, err := writeTunnelCACert()
	if err != nil {
		return "", nil, nil, func() {}, err
	}

	if err := ns.InjectCA(certPath); err != nil {
		cleanup()
		return "", nil, nil, func() {}, fmt.Errorf("inject CA into namespace: %w", err)
	}

	return caDir, caCert, caKey, cleanup, nil
}

// writeTunnelCACert generates the ephemeral tunnel CA in memory and writes ONLY
// the public certificate (root.crt) to a fresh temp dir. The CA certificate and
// private key are returned to the caller; the key is NEVER written to disk
// (S-C1): the sandboxed agent shares the host uid and mount namespace, so a
// persisted root.key — even 0600 — would be readable by the agent and let it
// mint trusted certs. Split out from setupTunnelCA so the on-disk guarantee is
// testable without namespace privileges.
func writeTunnelCACert() (caDir string, caCert *x509.Certificate, caKey crypto.PrivateKey, certPath string, cleanup func(), err error) {
	caDir, err = os.MkdirTemp("", "agentjail-tunnel-ca-*")
	if err != nil {
		return "", nil, nil, "", func() {}, fmt.Errorf("create temp CA dir: %w", err)
	}
	cleanup = func() { os.RemoveAll(caDir) }

	cert, key, certPEM, err := mitm.GenerateCAInMemory()
	if err != nil {
		cleanup()
		return "", nil, nil, "", func() {}, fmt.Errorf("generate tunnel CA: %w", err)
	}

	certPath = filepath.Join(caDir, "root.crt")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		cleanup()
		return "", nil, nil, "", func() {}, fmt.Errorf("write tunnel CA cert: %w", err)
	}

	return caDir, cert, key, certPath, cleanup, nil
}
