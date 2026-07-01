package credentials

import (
	"context"
	"time"
)

// Backend issues and revokes scoped credentials for a specific secret backend
// (AWS STS, PostgreSQL, Redis, etc.).
type Backend interface {
	// Grant issues scoped credentials with the given scope and TTL.
	Grant(ctx context.Context, cfg *Config, scope string, ttl time.Duration) (*Grant, error)

	// Revoke revokes a previously issued grant.  For backends that don't
	// support early revocation (e.g. STS), this is a no-op.
	Revoke(ctx context.Context, grant *Grant) error
}
