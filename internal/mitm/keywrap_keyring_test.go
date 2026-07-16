package mitm_test

import (
	"testing"

	"github.com/LuD1161/agentjail/internal/keyring"
	"github.com/LuD1161/agentjail/internal/mitm"
)

// The wrapper and its only real implementor were written by different authors
// who could not see each other's code. Pin the seam in the compiler, not in
// review. See ADR 0095-chunked-body-envelope.
var _ mitm.KeyWrapper = (*keyring.Keyring)(nil)

// A DEK wrapped through the real keyring must open through the real keyring,
// and must not open under another file's aad.
func TestKeyringSatisfiesKeyWrapper(t *testing.T) {
	var kw mitm.KeyWrapper = keyring.New(keyring.NewMemoryStore())

	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i)
	}
	aadA := []byte("file-a|request")
	aadB := []byte("file-b|request")

	kekID, wrapped, err := kw.Wrap(dek, aadA)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if kekID == "" {
		t.Fatal("Wrap returned an empty kekID; the header could not name its KEK")
	}

	got, err := kw.Unwrap(kekID, wrapped, aadA)
	if err != nil {
		t.Fatalf("Unwrap under the same aad: %v", err)
	}
	if string(got) != string(dek) {
		t.Fatalf("round-trip mismatch: got %x, want %x", got, dek)
	}

	if _, err := kw.Unwrap(kekID, wrapped, aadB); err == nil {
		t.Error("SECURITY: a wrapped DEK opened under another file's aad — " +
			"it could be lifted between bodies")
	}
}
