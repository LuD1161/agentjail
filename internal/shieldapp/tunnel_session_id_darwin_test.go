//go:build darwin

package shieldapp

import (
	"testing"

	"github.com/LuD1161/agentjail/internal/mitm"
)

// TestGenerateSessionID_ValidBodyStoreComponent guards the AGE-259 fix: the
// darwin tunnel session id is used as the per-session bodystore group key, so
// it MUST satisfy mitm.NewBodyStore's validIDComponent contract. The old
// "shield-<ts>-<hex>" form had dashes and was rejected there, silently
// disabling body persistence. If this fails, bodies stop landing on the darwin
// tunnel again.
func TestGenerateSessionID_ValidBodyStoreComponent(t *testing.T) {
	for i := 0; i < 100; i++ {
		id := generateSessionID()
		store, err := mitm.NewBodyStore(t.TempDir(), id, nil)
		if err != nil {
			t.Fatalf("generateSessionID() = %q is not a valid bodystore session id: %v", id, err)
		}
		if store.SessionID() != id {
			t.Fatalf("bodystore session = %q, want %q", store.SessionID(), id)
		}
	}
}
