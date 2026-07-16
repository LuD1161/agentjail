package mitm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
)

// KeyWrapper wraps a per-file DEK under a keychain-backed KEK. Defined here
// because the consumer defines the seam; internal/keyring implements it.
// See ADR 0095-chunked-body-envelope.
type KeyWrapper interface {
	// Wrap seals dek under the current KEK. aad binds the wrap to one file.
	Wrap(dek, aad []byte) (kekID string, wrapped []byte, err error)
	// Unwrap opens a wrapped DEK under the KEK named by kekID.
	Unwrap(kekID string, wrapped, aad []byte) (dek []byte, err error)
}

// MemoryKeyWrapper holds KEKs in process memory. It is the test and
// bootstrap implementor of KeyWrapper; it is not at-rest protection.
// See ADR 0095-chunked-body-envelope.
type MemoryKeyWrapper struct {
	mu      sync.RWMutex
	keks    map[string][]byte
	current string
}

// NewMemoryKeyWrapper mints one KEK and makes it current.
func NewMemoryKeyWrapper() (*MemoryKeyWrapper, error) {
	m := &MemoryKeyWrapper{keks: map[string][]byte{}}
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, fmt.Errorf("mitm/keywrap: kek id: %w", err)
	}
	if err := m.AddKEK(hex.EncodeToString(id[:])); err != nil {
		return nil, err
	}
	return m, nil
}

// AddKEK mints a KEK under kekID and makes it current. Prior KEKs stay
// available so a rewrap can still unwrap what they sealed.
func (m *MemoryKeyWrapper) AddKEK(kekID string) error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("mitm/keywrap: kek: %w", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keks[kekID] = key
	m.current = kekID
	return nil
}

// CurrentKEK returns the kek id new wraps will use.
func (m *MemoryKeyWrapper) CurrentKEK() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

func (m *MemoryKeyWrapper) aeadFor(kekID string) (cipher.AEAD, error) {
	m.mu.RLock()
	key, ok := m.keks[kekID]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("mitm/keywrap: unknown kek %q", kekID)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("mitm/keywrap: cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

func (m *MemoryKeyWrapper) Wrap(dek, aad []byte) (string, []byte, error) {
	id := m.CurrentKEK()
	aead, err := m.aeadFor(id)
	if err != nil {
		return "", nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", nil, fmt.Errorf("mitm/keywrap: nonce: %w", err)
	}
	return id, aead.Seal(nonce, nonce, dek, aad), nil
}

func (m *MemoryKeyWrapper) Unwrap(kekID string, wrapped, aad []byte) ([]byte, error) {
	aead, err := m.aeadFor(kekID)
	if err != nil {
		return nil, err
	}
	if len(wrapped) < aead.NonceSize() {
		return nil, fmt.Errorf("mitm/keywrap: wrapped dek is %d bytes, too short", len(wrapped))
	}
	nonce, ct := wrapped[:aead.NonceSize()], wrapped[aead.NonceSize():]
	dek, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("mitm/keywrap: wrapped dek fails authentication under kek %q: %w", kekID, err)
	}
	return dek, nil
}
