// Package keyring provides a key-encryption-key (KEK) held by the OS keychain,
// used to wrap the per-file DEKs that encrypt captured bodies (plan 014 §5).
//
// This file is the OS-agnostic source of truth. Item naming, KEK size, and the
// wrap format live here ONCE; the per-OS backends (keyring_linux.go,
// keyring_darwin.go) translate the Store contract into their own primitive and
// never re-list this data. See ADR 0034-platform-backend-shared-contract.
//
// # What this buys, stated narrowly
//
// The sandboxed agent runs as the SAME uid as agentjail. ADR 0076 S-C1 reasons
// from exactly this: a 0600 file does not stop a same-uid reader, which is why
// the MITM CA key is never written to disk. The OS keychain does not change
// that. On Linux, Secret Service hands the secret to any process running as the
// user; Chrome's cookie encryption works this way and is well known not to stop
// same-uid infostealers.
//
// So: this does NOT stop the agent. What it buys is that body transcripts
// survive an accidental copy of ~/.agentjail without their key -- backups, sync
// clients, editor search indexes, a support bundle, an issue attachment. It is
// also not stolen-disk protection; that is FDE's job. Mediation of the agent's
// reads is ADR 0092 D3's job, not this package's.
package keyring

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// The shared contract: every backend translates these, none redefines them.
const (
	// ServiceName labels agentjail's items in the OS keychain.
	ServiceName = "agentjail"

	// KEKSize is the AES-256 key length. The wrap is AES-256-GCM.
	KEKSize = 32

	// kekAccountPrefix namespaces per-KEK items; currentAccount records which
	// KEK id is active so rotation can add an id without losing the old ones.
	kekAccountPrefix = "body-kek/"
	currentAccount   = "body-kek/current"

	// kekIDBytes is the SHA-256 prefix length used to name a KEK.
	kekIDBytes = 8
)

// AccountForKEK is the keychain item name holding the raw bytes of one KEK.
// Backends translate this account string into their primitive; they do not
// build item names of their own.
func AccountForKEK(id KEKID) string { return kekAccountPrefix + string(id) }

// CurrentAccount is the keychain item naming the active KEK id.
func CurrentAccount() string { return currentAccount }

// KEKID names one KEK. It is a fingerprint of the key bytes, so a rotated key
// gets a new id by construction and ids never collide across rotations.
type KEKID string

// Tier names how well the KEK is protected. Callers MUST report the live tier
// rather than a flat "encrypted": that would be a lie for TierFileKEK, and a
// silent downgrade is the failure this whole path exists to avoid.
// See ADR 0097-linux-kek-fallback.
type Tier string

const (
	// TierKeychain: the KEK lives in the OS keychain and never touches our
	// disk. Survives a whole-$HOME backup.
	TierKeychain Tier = "os-keychain"

	// TierFileKEK: the KEK is a 0600 file outside ~/.agentjail. Survives a copy
	// of ~/.agentjail; does NOT survive a whole-$HOME backup.
	TierFileKEK Tier = "file-kek"

	// TierMemory: process-lifetime key. Tests only; Open() never selects it.
	TierMemory Tier = "memory"
)

// Sentinel errors. Callers branch on these with errors.Is -- never on strings.
var (
	// ErrNoKeychain means no OS keychain is reachable: headless Linux, CI, no
	// Secret Service, an unsupported OS, or a backend not yet built. Whether
	// this fails recording closed or degrades to plaintext with a loud notice
	// is plan 014 §9.2 and is NOT decided here -- the caller branches.
	ErrNoKeychain = errors.New("keyring: no OS keychain available")

	// ErrKeychainLocked means a keychain IS present and its collection is
	// locked. It wraps ErrNoKeychain so existing callers keep working, but the
	// advice differs: unlock it, versus there is none here. See AGE-254.
	ErrKeychainLocked = fmt.Errorf("%w: locked", ErrNoKeychain)

	// ErrUnknownKEK means the named KEK id is not in the keychain: a body
	// wrapped under a KEK from another machine, or one deleted since.
	ErrUnknownKEK = errors.New("keyring: unknown KEK id")

	// ErrUnwrap means the wrapped DEK did not authenticate: wrong aad, tampered
	// ciphertext, or a truncated wrap. GCM cannot tell these apart, and it must
	// not -- distinguishing them would be an oracle.
	ErrUnwrap = errors.New("keyring: wrapped DEK failed authentication")

	// ErrCorruptKEK means the keychain returned an item of the wrong shape.
	ErrCorruptKEK = errors.New("keyring: keychain item is not a valid KEK")

	// errNotFound is a backend's "no such item". It never escapes this package.
	errNotFound = errors.New("keyring: item not found")
)

// Store is the seam every OS backend implements: a named, byte-valued item
// store. Keeping it this dumb is what keeps the KEK semantics (naming, sizing,
// fingerprinting, wrap format) in this file for every platform at once.
type Store interface {
	// Get returns the item's bytes, or a wrapped errNotFound if absent.
	Get(account string) ([]byte, error)
	// Set stores the item, replacing any existing value.
	Set(account string, secret []byte) error
	// Name identifies the backend for logs and audit events.
	Name() string
	// Tier reports how well this backend protects the KEK, so callers can
	// state the posture honestly.
	Tier() Tier
}

// Locker is the optional Store extension for backends whose mint is a
// read-modify-write two processes can race. Held across mint so two daemons
// converge on one KEK. See ADR 0097-linux-kek-fallback.
type Locker interface {
	// Lock blocks until the mint lock is held, returning its release.
	Lock() (func(), error)
}

// Keyring wraps and unwraps DEKs under a keychain-held KEK.
type Keyring struct {
	store Store
}

// New returns a Keyring over an explicitly chosen backend.
func New(s Store) *Keyring { return &Keyring{store: s} }

// Open returns a Keyring over this OS's keychain. It returns ErrNoKeychain if
// none is reachable; it never silently falls back to an in-memory key.
func Open() (*Keyring, error) {
	s, err := openOSStore()
	if err != nil {
		return nil, err
	}
	return New(s), nil
}

// Backend names the store in use, for logs and audit events.
func (k *Keyring) Backend() string { return k.store.Name() }

// Tier reports how well the live backend protects the KEK.
func (k *Keyring) Tier() Tier { return k.store.Tier() }

// Wrap encrypts dek under the current KEK, binding aad. The caller puts file
// identity in aad so a wrapped DEK cannot be lifted to another file.
func (k *Keyring) Wrap(dek []byte, aad []byte) (kekID string, wrapped []byte, err error) {
	if len(dek) == 0 {
		return "", nil, errors.New("keyring: refusing to wrap an empty DEK")
	}
	id, kek, err := k.current()
	if err != nil {
		return "", nil, err
	}
	gcm, err := newGCM(kek)
	if err != nil {
		return "", nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", nil, fmt.Errorf("keyring: nonce: %w", err)
	}
	// Nonce is prepended, not stored separately: a wrapped DEK is one blob.
	return string(id), gcm.Seal(nonce, nonce, dek, aad), nil
}

// Unwrap decrypts a DEK wrapped under kekID with the same aad. A wrong aad,
// tampered ciphertext, or an unknown kekID each fail with a distinguishable
// sentinel; none of them return a partial or zero DEK.
func (k *Keyring) Unwrap(kekID string, wrapped []byte, aad []byte) ([]byte, error) {
	kek, err := k.lookup(KEKID(kekID))
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	if len(wrapped) < gcm.NonceSize()+gcm.Overhead() {
		return nil, fmt.Errorf("%w: wrapped DEK is %d bytes, shorter than a nonce plus tag", ErrUnwrap, len(wrapped))
	}
	nonce, ct := wrapped[:gcm.NonceSize()], wrapped[gcm.NonceSize():]
	dek, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		// Do not report which of wrong-aad / tampered / truncated it was.
		return nil, fmt.Errorf("%w under KEK %s", ErrUnwrap, kekID)
	}
	return dek, nil
}

// current returns the active KEK, minting one on first use.
func (k *Keyring) current() (KEKID, []byte, error) {
	id, kek, err := k.loadCurrent()
	if errors.Is(err, errNotFound) {
		return k.mint()
	}
	return id, kek, err
}

func (k *Keyring) loadCurrent() (KEKID, []byte, error) {
	idBytes, err := k.store.Get(CurrentAccount())
	if err != nil {
		return "", nil, err
	}
	id := KEKID(idBytes)
	kek, err := k.lookup(id)
	if err != nil {
		return "", nil, err
	}
	return id, kek, nil
}

// mint generates a KEK, stores it under its fingerprint, then marks it current.
// Order matters: a crash between the two leaves an orphan item, never a current
// pointer to a KEK that was never stored.
func (k *Keyring) mint() (KEKID, []byte, error) {
	if l, ok := k.store.(Locker); ok {
		unlock, err := l.Lock()
		if err != nil {
			return "", nil, err
		}
		defer unlock()
		// Another minter may have won while we waited for the lock.
		id, kek, err := k.loadCurrent()
		if err == nil {
			return id, kek, nil
		}
		if !errors.Is(err, errNotFound) {
			return "", nil, err
		}
	}
	kek := make([]byte, KEKSize)
	if _, err := rand.Read(kek); err != nil {
		return "", nil, fmt.Errorf("keyring: generate KEK: %w", err)
	}
	id := fingerprint(kek)
	if err := k.store.Set(AccountForKEK(id), kek); err != nil {
		return "", nil, err
	}
	if err := k.store.Set(CurrentAccount(), []byte(id)); err != nil {
		return "", nil, err
	}
	return id, kek, nil
}

func (k *Keyring) lookup(id KEKID) ([]byte, error) {
	if id == "" {
		return nil, fmt.Errorf("%w: empty KEK id", ErrUnknownKEK)
	}
	kek, err := k.store.Get(AccountForKEK(id))
	if errors.Is(err, errNotFound) {
		return nil, fmt.Errorf("%w: %s", ErrUnknownKEK, id)
	}
	if err != nil {
		return nil, err
	}
	if len(kek) != KEKSize {
		return nil, fmt.Errorf("%w: KEK %s is %d bytes, want %d", ErrCorruptKEK, id, len(kek), KEKSize)
	}
	return kek, nil
}

// fingerprint names a KEK by its own bytes, so rotation cannot reuse an id.
func fingerprint(kek []byte) KEKID {
	sum := sha256.Sum256(kek)
	return KEKID(hex.EncodeToString(sum[:kekIDBytes]))
}

func newGCM(kek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("keyring: cipher: %w", err)
	}
	return cipher.NewGCM(block)
}
