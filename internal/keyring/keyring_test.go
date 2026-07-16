package keyring

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

// Tests never touch a real keychain: CI has none. MemoryStore is named
// explicitly at every call site, never selected by fallback.
func newTestKeyring(t *testing.T) (*Keyring, *MemoryStore) {
	t.Helper()
	m := NewMemoryStore()
	return New(m), m
}

func testDEK(t *testing.T) []byte {
	t.Helper()
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return dek
}

func TestWrapUnwrapRoundTrip(t *testing.T) {
	k, _ := newTestKeyring(t)
	dek := testDEK(t)
	aad := []byte("bodies/sess-1/body-9.raw.enc")

	id, wrapped, err := k.Wrap(dek, aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if id == "" {
		t.Fatal("Wrap returned an empty KEK id")
	}
	if bytes.Contains(wrapped, dek) {
		t.Fatal("wrapped blob contains the plaintext DEK")
	}

	got, err := k.Unwrap(id, wrapped, aad)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("round-trip mismatch: got %x want %x", got, dek)
	}
}

// Guards cross-file DEK lifting: the caller binds file identity into aad.
func TestUnwrapWrongAADFails(t *testing.T) {
	k, _ := newTestKeyring(t)
	dek := testDEK(t)

	id, wrapped, err := k.Wrap(dek, []byte("bodies/sess-1/body-9.raw.enc"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	got, err := k.Unwrap(id, wrapped, []byte("bodies/sess-1/body-10.raw.enc"))
	if err == nil {
		t.Fatal("Unwrap accepted a DEK lifted to another file's aad")
	}
	if !errors.Is(err, ErrUnwrap) {
		t.Fatalf("want ErrUnwrap, got %v", err)
	}
	if got != nil {
		t.Fatalf("Unwrap returned %x alongside an error", got)
	}
}

func TestUnwrapTamperedCiphertextFails(t *testing.T) {
	k, _ := newTestKeyring(t)
	dek := testDEK(t)
	aad := []byte("bodies/sess-1/body-9.raw.enc")

	id, wrapped, err := k.Wrap(dek, aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// Flip a bit in every position: nonce, ciphertext, and GCM tag alike.
	for i := range wrapped {
		tampered := append([]byte(nil), wrapped...)
		tampered[i] ^= 0x01

		got, err := k.Unwrap(id, tampered, aad)
		if err == nil {
			t.Fatalf("Unwrap accepted ciphertext tampered at byte %d", i)
		}
		if !errors.Is(err, ErrUnwrap) {
			t.Fatalf("byte %d: want ErrUnwrap, got %v", i, err)
		}
		if got != nil {
			t.Fatalf("byte %d: Unwrap returned %x alongside an error", i, got)
		}
	}
}

func TestUnwrapTruncatedFails(t *testing.T) {
	k, _ := newTestKeyring(t)
	id, wrapped, err := k.Wrap(testDEK(t), []byte("aad"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	for _, n := range []int{0, 1, 12, len(wrapped) - 1} {
		if _, err := k.Unwrap(id, wrapped[:n], []byte("aad")); !errors.Is(err, ErrUnwrap) {
			t.Fatalf("truncated to %d: want ErrUnwrap, got %v", n, err)
		}
	}
}

func TestUnwrapUnknownKEKIDIsTyped(t *testing.T) {
	k, store := newTestKeyring(t)
	id, wrapped, err := k.Wrap(testDEK(t), []byte("aad"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	for name, kekID := range map[string]string{
		"never existed": "deadbeefdeadbeef",
		"empty":         "",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := k.Unwrap(kekID, wrapped, []byte("aad")); !errors.Is(err, ErrUnknownKEK) {
				t.Fatalf("want ErrUnknownKEK, got %v", err)
			}
		})
	}

	// A KEK deleted since the wrap must not be mistaken for bad ciphertext.
	t.Run("deleted since wrap", func(t *testing.T) {
		store.Forget(AccountForKEK(KEKID(id)))
		if _, err := k.Unwrap(id, wrapped, []byte("aad")); !errors.Is(err, ErrUnknownKEK) {
			t.Fatalf("want ErrUnknownKEK, got %v", err)
		}
	})
}

func TestUnwrapCorruptKEKIsTyped(t *testing.T) {
	k, store := newTestKeyring(t)
	id, wrapped, err := k.Wrap(testDEK(t), []byte("aad"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if err := store.Set(AccountForKEK(KEKID(id)), []byte("short")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, err := k.Unwrap(id, wrapped, []byte("aad")); !errors.Is(err, ErrCorruptKEK) {
		t.Fatalf("want ErrCorruptKEK, got %v", err)
	}
}

// The §9.2 seam: "no keychain" is one typed error the caller branches on, so
// fail-closed vs loud-plaintext is a decision at ONE call site, not here.
func TestOpenWithoutKeychainIsTyped(t *testing.T) {
	k, err := Open()
	if err == nil {
		t.Skipf("this host has a %s keychain; the no-keychain seam is exercised by the error path", k.Backend())
	}
	if !errors.Is(err, ErrNoKeychain) {
		t.Fatalf("want ErrNoKeychain, got %v", err)
	}
	if k != nil {
		t.Fatal("Open returned a Keyring alongside an error")
	}
}

// A KEK is minted once and reused; a second Wrap must not rotate silently.
func TestKEKIsStableAcrossWraps(t *testing.T) {
	k, _ := newTestKeyring(t)
	id1, _, err := k.Wrap(testDEK(t), []byte("a"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	id2, _, err := k.Wrap(testDEK(t), []byte("b"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if id1 != id2 {
		t.Fatalf("KEK id changed across wraps: %s then %s", id1, id2)
	}
}

// Two files with distinct aad must not produce interchangeable wraps even for
// the same DEK bytes -- the property the aad binding exists to give.
func TestSameDEKWrappedTwiceIsNotInterchangeable(t *testing.T) {
	k, _ := newTestKeyring(t)
	dek := testDEK(t)

	idA, wrapA, err := k.Wrap(dek, []byte("file-a"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	_, wrapB, err := k.Wrap(dek, []byte("file-b"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if bytes.Equal(wrapA, wrapB) {
		t.Fatal("identical wraps for the same DEK: the nonce is not random")
	}
	if _, err := k.Unwrap(idA, wrapB, []byte("file-a")); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("file-b's wrap opened under file-a's aad: %v", err)
	}
}

func TestWrapRejectsEmptyDEK(t *testing.T) {
	k, _ := newTestKeyring(t)
	if _, _, err := k.Wrap(nil, []byte("aad")); err == nil {
		t.Fatal("Wrap accepted an empty DEK")
	}
}

// Nil and empty aad are the same to GCM; pin it so a caller passing nil for
// "no identity" cannot later be surprised by an empty-slice caller matching.
func TestNilAndEmptyAADAreEquivalent(t *testing.T) {
	k, _ := newTestKeyring(t)
	dek := testDEK(t)
	id, wrapped, err := k.Wrap(dek, nil)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	got, err := k.Unwrap(id, wrapped, []byte{})
	if err != nil {
		t.Fatalf("Unwrap with empty aad after nil aad: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("round-trip mismatch across nil/empty aad")
	}
}

func TestMemoryStoreIsNotSelectedImplicitly(t *testing.T) {
	// Open() must never hand back the test backend, or a keychain-less host
	// would silently get a process-lifetime key.
	k, err := Open()
	if err == nil && k.Backend() == (&MemoryStore{}).Name() {
		t.Fatal("Open() selected the in-memory store")
	}
}
