package credentials

import "strings"

// Config holds the backend-specific configuration needed to issue scoped
// credentials.  It is the exported form of the per-secret JSON stored by
// the secrets store.
type Config struct {
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

// BackendFromName determines the backend from the secret name prefix.
// "aws/prod" -> "aws", "pg/prod" -> "pg", "redis/prod" -> "redis".
// Names without a known prefix default to "raw" (the secret is returned as-is).
func BackendFromName(name string) string {
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
