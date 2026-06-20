package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

// grantPostgres creates a short-lived PG role with scoped privileges.
//
// The secret config must contain a DSN (e.g.
// "postgresql://admin:pass@host:5432/db").  The backend shells out to
// `psql` to run SQL commands, avoiding the need for a PG driver dependency
// (per ADR 0023 — no new deps for the secret server).
//
// The scope determines the privileges:
//   - read-only: GRANT USAGE on schema, GRANT SELECT on all tables
//   - read-write: GRANT USAGE on schema, GRANT SELECT/INSERT/UPDATE/DELETE
//
// The role is created with VALID UNTIL set to now + TTL.  On revocation,
// the role is DROPped (immediate revocation, unlike STS).
func grantPostgres(cfg *secretConfig, scope string, ttl time.Duration) (*Grant, error) {
	if cfg.DSN == "" {
		return nil, fmt.Errorf("pg secret missing dsn")
	}

	// Generate a random role name and password.
	roleName := "agentjail_" + randomHex(4)
	password := randomHex(16)

	expiresAt := time.Now().Add(ttl)
	validUntil := expiresAt.Format("2006-01-02 15:04:05")

	// Build the SQL to create the role with scoped privileges.
	sql := buildPGCreateRoleSQL(roleName, password, validUntil, scope)

	// Execute via psql.
	if err := psqlExec(cfg.DSN, sql); err != nil {
		return nil, fmt.Errorf("create pg role: %w", err)
	}

	// Parse the DSN to extract host, port, database for the env vars.
	host, port, database := parsePGDSN(cfg.DSN)

	grant := &Grant{
		ID:         newGrantID(),
		SecretName: cfg.Backend,
		Backend:    "pg",
		Scope:      scope,
		ExpiresAt:  expiresAt,
		EnvVars: map[string]string{
			"PGUSER":     roleName,
			"PGPASSWORD": password,
			"PGHOST":     host,
			"PGPORT":     port,
			"PGDATABASE": database,
		},
		revokeFn: func() error {
			dropSQL := fmt.Sprintf(`DROP ROLE IF EXISTS %s;`, quoteIdent(roleName))
			if err := psqlExec(cfg.DSN, dropSQL); err != nil {
				return fmt.Errorf("drop pg role: %w", err)
			}
			return nil
		},
	}

	slog.Info("pg grant issued",
		"grant_id", grant.ID,
		"role", roleName,
		"scope", scope,
		"expires_at", expiresAt.Format(time.RFC3339),
	)

	return grant, nil
}

// buildPGCreateRoleSQL builds the SQL to create a scoped PG role.
func buildPGCreateRoleSQL(roleName, password, validUntil, scope string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `CREATE ROLE %s WITH LOGIN PASSWORD '%s' VALID UNTIL '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE;`,
		quoteIdent(roleName), escapeSQLString(password), validUntil)
	fmt.Fprintf(&b, ` GRANT USAGE ON SCHEMA public TO %s;`, quoteIdent(roleName))

	switch scope {
	case "read-only":
		fmt.Fprintf(&b, ` GRANT SELECT ON ALL TABLES IN SCHEMA public TO %s;`, quoteIdent(roleName))
	case "read-write":
		fmt.Fprintf(&b, ` GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO %s;`, quoteIdent(roleName))
	default:
		fmt.Fprintf(&b, ` GRANT SELECT ON ALL TABLES IN SCHEMA public TO %s;`, quoteIdent(roleName))
	}

	return b.String()
}

// psqlExec runs SQL via the psql command-line client.
func psqlExec(dsn, sql string) error {
	cmd := exec.Command("psql", dsn, "-c", sql, "-v", "ON_ERROR_STOP=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("psql: %w: %s", err, string(output))
	}
	return nil
}

// parsePGDSN extracts host, port, and database from a PG DSN.
// Supports both URL format (postgresql://user:pass@host:port/db) and
// key=value format (host=h port=p dbname=db).
func parsePGDSN(dsn string) (host, port, database string) {
	host = "localhost"
	port = "5432"

	if strings.HasPrefix(dsn, "postgresql://") || strings.HasPrefix(dsn, "postgres://") {
		// URL format: parse with net/url
		// Simple extraction without importing net/url to keep imports minimal.
		s := dsn
		// Strip scheme.
		if idx := strings.Index(s, "://"); idx >= 0 {
			s = s[idx+3:]
		}
		// Strip credentials.
		if idx := strings.LastIndex(s, "@"); idx >= 0 {
			s = s[idx+1:]
		}
		// Strip path.
		var pathPart string
		if idx := strings.Index(s, "/"); idx >= 0 {
			pathPart = s[idx+1:]
			s = s[:idx]
		}
		// s is now host:port
		if idx := strings.LastIndex(s, ":"); idx >= 0 {
			host = s[:idx]
			port = s[idx+1:]
		} else {
			host = s
		}
		// Strip query from path.
		if idx := strings.Index(pathPart, "?"); idx >= 0 {
			pathPart = pathPart[:idx]
		}
		database = pathPart
	} else {
		// key=value format
		parts := strings.Fields(dsn)
		for _, p := range parts {
			if idx := strings.Index(p, "="); idx >= 0 {
				k, v := p[:idx], p[idx+1:]
				switch k {
				case "host":
					host = v
				case "port":
					port = v
				case "dbname":
					database = v
				}
			}
		}
	}
	return
}

// quoteIdent quotes a PostgreSQL identifier (role name, table name).
func quoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

// escapeSQLString escapes a string for use in single-quoted SQL literal.
func escapeSQLString(s string) string {
	return strings.ReplaceAll(s, `'`, `''`)
}

// randomHex returns n random bytes as a hex string.
func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
