package credentials

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestGrantManager_RegisterAndRevoke(t *testing.T) {
	gm := NewGrantManager()

	// Register a grant with a revokeFn that records it was called.
	revoked := false
	g := &Grant{
		SecretName: "test-secret",
		Backend:    "test",
		Scope:      "read-only",
		ExpiresAt:  time.Now().Add(1 * time.Hour),
		EnvVars:    map[string]string{"FOO": "bar"},
	}
	g.SetRevokeFn(func() error {
		revoked = true
		return nil
	})

	id := gm.Register(g)
	if id == "" {
		t.Fatal("Register returned empty ID")
	}
	if !strings.HasPrefix(id, "grant-") {
		t.Fatalf("grant ID should start with 'grant-', got %q", id)
	}
	if gm.Active() != 1 {
		t.Fatalf("expected 1 active grant, got %d", gm.Active())
	}

	// Get the grant back.
	got, ok := gm.Get(id)
	if !ok {
		t.Fatal("Get returned not-found for registered grant")
	}
	if got.SecretName != "test-secret" {
		t.Fatalf("expected SecretName 'test-secret', got %q", got.SecretName)
	}

	// Revoke.
	if err := gm.Revoke(id); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !revoked {
		t.Fatal("revokeFn was not called")
	}
	if gm.Active() != 0 {
		t.Fatalf("expected 0 active grants after revoke, got %d", gm.Active())
	}

	// Revoking again should fail.
	if err := gm.Revoke(id); err == nil {
		t.Fatal("expected error revoking unknown grant")
	}
}

func TestGrantManager_RevokeAll(t *testing.T) {
	gm := NewGrantManager()
	count := 0
	for i := 0; i < 3; i++ {
		g := &Grant{
			SecretName: "s",
			Backend:    "test",
			ExpiresAt:  time.Now().Add(1 * time.Hour),
			EnvVars:    map[string]string{},
		}
		g.SetRevokeFn(func() error {
			count++
			return nil
		})
		gm.Register(g)
	}

	gm.RevokeAll()
	if count != 3 {
		t.Fatalf("expected 3 revocations, got %d", count)
	}
	if gm.Active() != 0 {
		t.Fatalf("expected 0 active grants, got %d", gm.Active())
	}
}

func TestGrantManager_RevokeError(t *testing.T) {
	gm := NewGrantManager()
	g := &Grant{
		SecretName: "s",
		Backend:    "test",
		ExpiresAt:  time.Now().Add(1 * time.Hour),
		EnvVars:    map[string]string{},
	}
	g.SetRevokeFn(func() error {
		return errors.New("backend unavailable")
	})
	id := gm.Register(g)

	err := gm.Revoke(id)
	if err == nil {
		t.Fatal("expected error from failing revokeFn")
	}
	if !strings.Contains(err.Error(), "backend unavailable") {
		t.Fatalf("unexpected error: %v", err)
	}
	// Grant should still be removed from the map even on revokeFn error.
	if gm.Active() != 0 {
		t.Fatalf("expected 0 active grants after failed revoke, got %d", gm.Active())
	}
}

func TestGrantManager_CleanupExpired(t *testing.T) {
	gm := NewGrantManager()

	// Register an already-expired grant.
	revoked := false
	expired := &Grant{
		SecretName: "expired",
		Backend:    "test",
		ExpiresAt:  time.Now().Add(-1 * time.Hour),
		EnvVars:    map[string]string{},
	}
	expired.SetRevokeFn(func() error {
		revoked = true
		return nil
	})
	gm.Register(expired)

	// Register a still-valid grant.
	valid := &Grant{
		SecretName: "valid",
		Backend:    "test",
		ExpiresAt:  time.Now().Add(1 * time.Hour),
		EnvVars:    map[string]string{},
	}
	gm.Register(valid)

	gm.CleanupExpired()

	if !revoked {
		t.Fatal("expired grant revokeFn was not called")
	}
	if gm.Active() != 1 {
		t.Fatalf("expected 1 active grant after cleanup, got %d", gm.Active())
	}
}

func TestNewGrantID(t *testing.T) {
	id1 := NewGrantID()
	id2 := NewGrantID()
	if id1 == id2 {
		t.Fatal("NewGrantID returned duplicate IDs")
	}
	if !strings.HasPrefix(id1, "grant-") {
		t.Fatalf("grant ID should start with 'grant-', got %q", id1)
	}
}

func TestGrantManager_NilRevokeFn(t *testing.T) {
	gm := NewGrantManager()
	g := &Grant{
		SecretName: "no-revoke",
		Backend:    "aws",
		ExpiresAt:  time.Now().Add(1 * time.Hour),
		EnvVars:    map[string]string{},
		// revokeFn is nil (STS-style)
	}
	id := gm.Register(g)

	if err := gm.Revoke(id); err != nil {
		t.Fatalf("Revoke with nil revokeFn should succeed, got: %v", err)
	}
}
