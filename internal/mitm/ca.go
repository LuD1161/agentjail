// Package mitm provides TLS man-in-the-middle inspection for agentjail-netproxy.
// It generates a local CA, signs per-host certificates on the fly, and intercepts
// HTTP requests flowing through CONNECT tunnels so they can be logged.
package mitm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// LoadOrCreateCA loads an existing CA from caDir, or generates a new one.
// Returns the parsed CA certificate, the private key, and a tls.Certificate
// ready for use in TLS configurations.
func LoadOrCreateCA(caDir string) (*x509.Certificate, crypto.PrivateKey, *tls.Certificate, error) {
	certPath := filepath.Join(caDir, "root.crt")
	keyPath := filepath.Join(caDir, "root.key")

	// Try loading existing CA.
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)

	if certErr == nil && keyErr == nil {
		if fi, err := os.Stat(keyPath); err == nil && fi.Mode().Perm()&0077 != 0 {
			return nil, nil, nil, fmt.Errorf("CA private key %s has insecure permissions %04o (expected 0600)", keyPath, fi.Mode().Perm())
		}
		tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("parse existing CA keypair: %w", err)
		}
		caCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			return nil, nil, nil, fmt.Errorf("parse existing CA cert: %w", err)
		}
		return caCert, tlsCert.PrivateKey, &tlsCert, nil
	}

	// Generate new CA.
	caCert, caKey, err := GenerateCA(caDir)
	if err != nil {
		return nil, nil, nil, err
	}

	// Re-read from disk to build tls.Certificate.
	certPEM, _ = os.ReadFile(certPath)
	keyPEM, _ = os.ReadFile(keyPath)
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse newly generated CA keypair: %w", err)
	}

	return caCert, caKey, &tlsCert, nil
}

// GenerateCAInMemory creates a new self-signed CA certificate valid for 10
// years and returns the parsed certificate, its private key, and the cert PEM
// bytes WITHOUT writing anything to disk. This is the S-C1-safe path: the CA
// private key stays in the gateway's memory and never touches a filesystem the
// same-uid agent can read, so it cannot be exfiltrated to mint trusted certs.
// Callers that need to inject trust write only the returned cert PEM (root.crt).
func GenerateCAInMemory() (*x509.Certificate, crypto.PrivateKey, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate RSA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "AgentJail Inspection CA",
			Organization: []string{"AgentJail"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse generated CA cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if certPEM == nil {
		return nil, nil, nil, fmt.Errorf("encode CA cert PEM")
	}

	return caCert, key, certPEM, nil
}

// GenerateCA creates a new self-signed CA certificate valid for 10 years.
// It writes root.crt (PEM) and root.key (PEM, mode 0600) to caDir.
//
// SECURITY NOTE (S-C1): persisting root.key is unsafe when the sandboxed agent
// shares the host uid and mount namespace — prefer GenerateCAInMemory for the
// tunnel MITM path. GenerateCA remains for callers (tests, netproxy) that need
// a reusable on-disk CA in a directory the agent cannot read.
func GenerateCA(caDir string) (*x509.Certificate, crypto.PrivateKey, error) {
	if err := os.MkdirAll(caDir, 0700); err != nil {
		return nil, nil, fmt.Errorf("create CA dir: %w", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate RSA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "AgentJail Inspection CA",
			Organization: []string{"AgentJail"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CA certificate: %w", err)
	}

	// Write cert PEM.
	certPath := filepath.Join(caDir, "root.crt")
	certFile, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return nil, nil, fmt.Errorf("write CA cert: %w", err)
	}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		certFile.Close()
		return nil, nil, fmt.Errorf("encode CA cert PEM: %w", err)
	}
	certFile.Close()

	// Write key PEM (mode 0600).
	keyPath := filepath.Join(caDir, "root.key")
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, nil, fmt.Errorf("write CA key: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		keyFile.Close()
		return nil, nil, fmt.Errorf("marshal CA key: %w", err)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}); err != nil {
		keyFile.Close()
		return nil, nil, fmt.Errorf("encode CA key PEM: %w", err)
	}
	keyFile.Close()

	caCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse generated CA cert: %w", err)
	}
	return caCert, key, nil
}

// hostCertCache is a bounded cache for signed host certificates.
// When the cache exceeds maxSize entries, a random half is evicted
// (map iteration order is non-deterministic in Go).
type hostCertCache struct {
	mu      sync.Mutex
	certs   map[string]*hostCertEntry
	maxSize int
}

type hostCertEntry struct {
	cert      *tls.Certificate
	createdAt time.Time
}

const maxHostCerts = 1000

func newHostCertCache() *hostCertCache {
	return &hostCertCache{
		certs:   make(map[string]*hostCertEntry),
		maxSize: maxHostCerts,
	}
}

func (c *hostCertCache) get(host string) *tls.Certificate {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.certs[host]
	if !ok {
		return nil
	}
	// Expired certs are stale.
	if time.Now().After(entry.createdAt.Add(20 * time.Hour)) {
		delete(c.certs, host)
		return nil
	}
	return entry.cert
}

func (c *hostCertCache) put(host string, cert *tls.Certificate) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict random half when at capacity.
	if len(c.certs) >= c.maxSize {
		target := len(c.certs) / 2
		removed := 0
		for h := range c.certs {
			if removed >= target {
				break
			}
			delete(c.certs, h)
			removed++
		}
	}
	c.certs[host] = &hostCertEntry{
		cert:      cert,
		createdAt: time.Now(),
	}
}

// SignHostCert generates a short-lived (24h) TLS certificate for the given
// hostname, signed by the CA. The host cert uses ECDSA P-256 for fast TLS
// handshakes.
func SignHostCert(ca *x509.Certificate, caKey crypto.PrivateKey, host string) (*tls.Certificate, error) {
	hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate host key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	// An IP literal must go in IPAddresses: no verifier accepts a DNS SAN for a
	// connection to an IP (RFC 6125, x509.Certificate.VerifyHostname). Putting
	// it in DNSNames failed every https://<ip> request. AGE-220.
	target := ParseHostTarget(host)

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: target.Host,
		},
		NotBefore: now.Add(-5 * time.Minute), // small clock skew allowance
		NotAfter:  now.Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}
	if target.IsIP() {
		template.IPAddresses = []net.IP{target.IP}
	} else {
		template.DNSNames = []string{target.Host}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca, &hostKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("sign host cert: %w", err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  hostKey,
	}
	return tlsCert, nil
}

// randomSerial returns a random 128-bit serial number for X.509 certificates.
func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return serial, nil
}
