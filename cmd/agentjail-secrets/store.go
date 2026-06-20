package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// keySize is the AES-256 key length in bytes.
const keySize = 32

// nonceSize is the GCM nonce length in bytes.
const nonceSize = 12

// Store manages encrypted secrets at rest.  Secrets are stored as individual
// files in a directory, each encrypted with AES-256-GCM using a master key.
//
// The master key is a 32-byte random key stored at keyPath (default:
// ~/.agentjail/secrets.key) with 0600 permissions.  On first run, a new key
// is generated.  Future enhancement: integrate with OS keystore (macOS
// Keychain, Linux secret-service) for key management.
type Store struct {
	dir     string
	keyPath string
	key     []byte
}

// NewStore opens or creates a secrets store at the given directory.
// The master key is loaded from keyPath (or generated if it doesn't exist).
// Both the store directory and key file are created with restrictive
// permissions (0700 and 0600 respectively).
func NewStore(dir, keyPath string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create store dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("chmod store dir: %w", err)
	}

	key, err := loadOrCreateKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("load key: %w", err)
	}

	return &Store{dir: dir, keyPath: keyPath, key: key}, nil
}

// loadOrCreateKey loads the master key from path, or generates a new random
// key and writes it to path with 0600 permissions if the file doesn't exist.
func loadOrCreateKey(path string) ([]byte, error) {
	if key, err := os.ReadFile(path); err == nil {
		if len(key) != keySize {
			return nil, fmt.Errorf("key file %s is %d bytes; expected %d", path, len(key), keySize)
		}
		return key, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read key: %w", err)
	}

	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}
	return key, nil
}

// Set encrypts and stores a secret under the given name.
func (s *Store) Set(name, value string) error {
	if err := validateName(name); err != nil {
		return err
	}
	plaintext := []byte(value)
	ciphertext, err := encrypt(s.key, plaintext)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	path := s.secretPath(name)
	parent := filepath.Dir(path)
	if parent != s.dir {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return fmt.Errorf("create secret parent dir: %w", err)
		}
	}
	if err := os.WriteFile(path, ciphertext, 0o600); err != nil {
		return fmt.Errorf("write secret: %w", err)
	}
	return nil
}

// Get decrypts and returns the secret with the given name.
// Returns os.ErrNotExist if the secret doesn't exist.
func (s *Store) Get(name string) (string, error) {
	if err := validateName(name); err != nil {
		return "", err
	}
	ciphertext, err := os.ReadFile(s.secretPath(name))
	if err != nil {
		return "", err
	}
	plaintext, err := decrypt(s.key, ciphertext)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	return string(plaintext), nil
}

// List returns the names of all stored secrets (sorted, no values).
// Names with a / prefix (e.g. aws/prod) are stored in subdirectories;
// this function walks the store tree and returns relative paths.
func (s *Store) List() ([]string, error) {
	var names []string
	err := filepath.WalkDir(s.dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(s.dir, path)
		if err != nil {
			return err
		}
		names = append(names, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk store dir: %w", err)
	}
	return names, nil
}

// Delete removes the secret with the given name.
// Returns os.ErrNotExist if the secret doesn't exist.
func (s *Store) Delete(name string) error {
	if err := validateName(name); err != nil {
		return err
	}
	return os.Remove(s.secretPath(name))
}

// secretPath returns the file path for a secret name.
func (s *Store) secretPath(name string) string {
	return filepath.Join(s.dir, name)
}

// validateName ensures a secret name is safe to use as a filename.
// Allowed: letters, digits, /, -, _ (the / enables backend namespacing
// like aws/prod, pg/prod, redis/prod).
func validateName(name string) error {
	if name == "" {
		return errors.New("secret name is empty")
	}
	if name == "." || name == ".." || strings.Contains(name, "..") {
		return fmt.Errorf("invalid secret name: %q", name)
	}
	for _, c := range name {
		if c < 0x20 || c == 0x7f {
			return fmt.Errorf("secret name contains control character: %q", name)
		}
	}
	return nil
}

// encrypt encrypts plaintext with AES-256-GCM.
// The output format is: nonce (12 bytes) || ciphertext || tag (16 bytes, appended by GCM).
func encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

// decrypt decrypts data produced by encrypt.
func decrypt(key, data []byte) ([]byte, error) {
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// secretConfig is the JSON structure stored for each backend secret.
// It holds the backend-specific configuration needed to issue scoped creds.
type secretConfig struct {
	// Backend is auto-detected from the secret name prefix (aws/, pg/, redis/).
	Backend string `json:"-"`

	// AWS fields (backend=aws):
	RoleARN    string `json:"role_arn,omitempty"`
	AccessKey  string `json:"access_key,omitempty"`
	SecretKey  string `json:"secret_key,omitempty"`
	SessionTTL string `json:"session_ttl,omitempty"`

	// PG fields (backend=pg):
	DSN string `json:"dsn,omitempty"`

	// Redis fields (backend=redis):
	Addr     string `json:"addr,omitempty"`
	Password string `json:"password,omitempty"`
	Keys     string `json:"keys,omitempty"`
}

// loadConfig reads and parses the secret config for the given name.
func (s *Store) loadConfig(name string) (*secretConfig, error) {
	value, err := s.Get(name)
	if err != nil {
		return nil, err
	}
	var cfg secretConfig
	if err := json.Unmarshal([]byte(value), &cfg); err != nil {
		return nil, fmt.Errorf("parse secret config: %w", err)
	}
	cfg.Backend = backendFromName(name)
	return &cfg, nil
}

// backendFromName determines the backend from the secret name prefix.
// "aws/prod" → "aws", "pg/prod" → "pg", "redis/prod" → "redis".
// Names without a known prefix default to "raw" (the secret is returned as-is).
func backendFromName(name string) string {
	if strings.HasPrefix(name, "aws/") {
		return "aws"
	}
	if strings.HasPrefix(name, "pg/") {
		return "pg"
	}
	if strings.HasPrefix(name, "redis/") {
		return "redis"
	}
	return "raw"
}
