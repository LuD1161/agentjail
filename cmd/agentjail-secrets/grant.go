package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Grant represents an active credential grant issued by a backend.
type Grant struct {
	ID         string            `json:"id"`
	SecretName string            `json:"secret_name"`
	Backend    string            `json:"backend"`
	Scope      string            `json:"scope"`
	ExpiresAt  time.Time         `json:"expires_at"`
	EnvVars    map[string]string `json:"env_vars"`
	// revokeFn is called to revoke the grant (backend-specific).
	// Nil for STS (relies on short TTL; cannot revoke early).
	revokeFn func() error `json:"-"`
}

// GrantManager tracks active grants and handles revocation.
// It is safe for concurrent use.
type GrantManager struct {
	mu     sync.Mutex
	grants map[string]*Grant
}

// NewGrantManager creates a new GrantManager.
func NewGrantManager() *GrantManager {
	return &GrantManager{grants: make(map[string]*Grant)}
}

// newGrantID generates a random grant ID.
func newGrantID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "grant-" + hex.EncodeToString(b)
}

// Register adds a grant to the manager and returns its ID.
func (gm *GrantManager) Register(g *Grant) string {
	if g.ID == "" {
		g.ID = newGrantID()
	}
	gm.mu.Lock()
	gm.grants[g.ID] = g
	gm.mu.Unlock()
	slog.Info("grant issued",
		"grant_id", g.ID,
		"secret", g.SecretName,
		"backend", g.Backend,
		"scope", g.Scope,
		"expires_at", g.ExpiresAt.Format(time.RFC3339),
	)
	return g.ID
}

// Revoke revokes a grant by ID.  If the grant has a revokeFn, it is called
// to perform backend-specific revocation (e.g. DROP ROLE for PG, ACL DELUSER
// for Redis).  For STS, revokeFn is nil (relies on short TTL).
func (gm *GrantManager) Revoke(id string) error {
	gm.mu.Lock()
	g, ok := gm.grants[id]
	if ok {
		delete(gm.grants, id)
	}
	gm.mu.Unlock()

	if !ok {
		return fmt.Errorf("grant %s not found", id)
	}

	if g.revokeFn != nil {
		if err := g.revokeFn(); err != nil {
			slog.Error("grant revocation failed",
				"grant_id", id,
				"backend", g.Backend,
				"err", err,
			)
			return err
		}
	}

	slog.Info("grant revoked",
		"grant_id", id,
		"secret", g.SecretName,
		"backend", g.Backend,
	)
	return nil
}

// RevokeAll revokes all active grants.  Used on session end / shield exit.
func (gm *GrantManager) RevokeAll() {
	gm.mu.Lock()
	ids := make([]string, 0, len(gm.grants))
	for id := range gm.grants {
		ids = append(ids, id)
	}
	gm.mu.Unlock()

	for _, id := range ids {
		_ = gm.Revoke(id)
	}
}

// Get returns a grant by ID.
func (gm *GrantManager) Get(id string) (*Grant, bool) {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	g, ok := gm.grants[id]
	return g, ok
}

// Active returns the number of active grants.
func (gm *GrantManager) Active() int {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	return len(gm.grants)
}

// CleanupExpired removes and revokes expired grants.
func (gm *GrantManager) CleanupExpired() {
	gm.mu.Lock()
	var expired []string
	now := time.Now()
	for id, g := range gm.grants {
		if !g.ExpiresAt.IsZero() && now.After(g.ExpiresAt) {
			expired = append(expired, id)
		}
	}
	gm.mu.Unlock()

	for _, id := range expired {
		_ = gm.Revoke(id)
	}
}
