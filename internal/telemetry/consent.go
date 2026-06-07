package telemetry

import (
	"encoding/json"
	"os"
	"time"

	"github.com/google/uuid"
)

// EnvVar is the dedicated kill switch. "false" disables, "true" force-enables.
// Deliberately NOT DO_NOT_TRACK: a shared global signal would opt users out of
// agentjail because of an unrelated CLI.
const EnvVar = "AGENTJAIL_SEND_ANONYMOUS_USAGE_STATS"

// Consent is the on-disk telemetry state (~/.agentjail/telemetry.json).
type Consent struct {
	Enabled     bool   `json:"enabled"`
	AnonymousID string `json:"anonymous_id"`
	FirstSeen   string `json:"first_seen"` // coarse date only, no time
	NoticeShown bool   `json:"notice_shown"`
	Schema      int    `json:"schema"`
}

// Resolve returns whether telemetry is enabled and the source of that decision.
// Order (first match wins): env var → CI auto-detect → config file → default(on).
func Resolve(c Consent, getenv func(string) string) (enabled bool, source string) {
	switch getenv(EnvVar) {
	case "false", "0", "no":
		return false, "env"
	case "true", "1", "yes":
		return true, "env"
	}
	if isCI(getenv) {
		return false, "ci"
	}
	return c.Enabled, "config"
}

func isCI(getenv func(string) string) bool {
	for _, k := range []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "CIRCLECI"} {
		if v := getenv(k); v != "" && v != "false" && v != "0" {
			return true
		}
	}
	return false
}

// LoadConsent reads telemetry.json, creating it with opt-out defaults (enabled,
// fresh random anonymous ID) if absent.
func LoadConsent(p Paths) (Consent, error) {
	b, err := os.ReadFile(p.Consent())
	if err == nil {
		var c Consent
		if jErr := json.Unmarshal(b, &c); jErr == nil && c.Schema >= 1 && c.AnonymousID != "" {
			return c, nil
		}
		// Corrupt/old: fall through and re-init.
	} else if !os.IsNotExist(err) {
		return Consent{}, err
	}
	c := Consent{
		Enabled:     true,
		AnonymousID: uuid.NewString(),
		FirstSeen:   time.Now().UTC().Format("2006-01-02"),
		NoticeShown: false,
		Schema:      1,
	}
	if err := SaveConsent(p, c); err != nil {
		return Consent{}, err
	}
	return c, nil
}

// NewAnonymousID returns a fresh random anonymous ID.
func NewAnonymousID() string { return uuid.NewString() }

// SaveConsent atomically writes telemetry.json at mode 0600.
func SaveConsent(p Paths, c Consent) error {
	if err := os.MkdirAll(p.Base, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := p.Consent() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p.Consent())
}
