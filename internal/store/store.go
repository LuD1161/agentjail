// Package store is agentjail's local SQLite-backed event store (ADR 0018).
//
// It persists decisions, audit events, and session metadata to
// ~/.agentjail/agentjail.db (WAL mode, 0600). It replaces the flat-file
// daemon.log/audit.log JSON-lines as the queryable local store; the slog
// JSON line is retained as a debug trail during the transition. Telemetry
// (anonymous, remote, PostHog) is a separate concern and stays out of here.
//
// The full tool_input is persisted but redacted, then truncated to 4 KB:
// secret-bearing keys become "[redacted]" (ADR 0019-redaction-policy) and
// secret-shaped values become "[redacted:TYPE]" wherever they appear
// (ADR 0084-redact-secret-values).
package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/LuD1161/agentjail/internal/redact"

	"github.com/LuD1161/agentjail/internal/audit"
)

// DecisionRecord is one tool-call evaluation. Writes set ToolInput (raw); the
// store redacts it before persisting. Reads populate ToolInputRedacted (the
// redacted JSON from the DB) and ID (the row id, for --follow tailing) and
// leave ToolInput nil — the raw input is never persisted.
type DecisionRecord struct {
	ID                int64
	Ts                time.Time
	SessionID         string
	Agent             string
	ToolName          string
	Summary           string
	Action            string
	RuleID            string
	Reason            string
	Impact            string
	ElapsedUs         int64
	CWD               string
	ToolInput         map[string]interface{} `json:"-"`
	ToolInputRedacted string

	// Action is what was ACTUALLY enforced. WouldAction is the verdict policy
	// returned when monitor mode downgraded it, and is empty when the two
	// matched. Action must never claim a block that did not happen -- a reader
	// of this row has no other way to tell (AGE-212).
	// See ADR 0091-monitor-mode-tools.
	WouldAction string
}

// AuditRecord is one policy-mutation audit event (replaces audit.log).
type AuditRecord struct {
	ID     int64
	Ts     time.Time
	Action string
	RuleID string
	User   string
}

// Session is the upserted session metadata derived from decisions.
type Session struct {
	SessionID     string
	StartTs       time.Time
	EndTs         time.Time
	Agent         string
	CWD           string
	DecisionCount int
}

// Filter selects decisions. Zero-value fields are not filtered on.
type Filter struct {
	SessionID string        // substring match (consistent with daemon.log --session)
	Since     time.Duration // only decisions newer than now-Since; 0 = no filter
	Actions   []string      // match any (lower-cased)
	Tool      string        // exact tool name
	Rule      string        // substring match on rule_id (case-insensitive)
	Limit     int           // 0 = no limit (caller should bound it)
	AfterID   int64         // only rows with id > AfterID (for --follow tailing)
	OrderDesc bool          // order by id DESC (newest first); default ASC (chronological)
}

// SessionFilter selects sessions for ListSessionsFiltered.
type SessionFilter struct {
	Since time.Duration // only sessions with end_ts newer than now-Since; 0 = no filter
	Limit int           // 0 = no limit
}

// ActionCount is one row from the per-session action aggregate query.
type ActionCount struct {
	SessionID string
	Action    string
	Count     int
}

// DiscoveredTool is a persisted MCP tool entry from scan/audit/session logs.
type DiscoveredTool struct {
	ID        int64
	Server    string // MCP server name (e.g. "chrome-devtools", "claude_ai_Gmail")
	Tool      string // tool name (e.g. "click", "authenticate")
	Source    string // discovery source: "audit", "session_log", "live", "config"
	FirstSeen time.Time
	LastSeen  time.Time
}

// DiscoveredSkill is a persisted skill entry from audit history.
type DiscoveredSkill struct {
	ID        int64
	Name      string // skill name (e.g. "superpowers:brainstorming", "deep-research")
	Source    string // "audit" or "session_log"
	FirstSeen time.Time
	LastSeen  time.Time
	UseCount  int
}

// AuditLogFilter selects unified audit log entries (Plan 009).
type AuditLogFilter struct {
	Entity    string
	EventType string
	SessionID string
	Limit     int
}

// AuditLogEntry is one row from the audit_log table (Plan 009).
type AuditLogEntry struct {
	ID        int64
	Ts        time.Time
	EventType string
	Entity    string
	Detail    string
	Actor     string
	SessionID string
	RefID     string
}

// AuditFilter selects audit events.
type AuditFilter struct {
	Limit     int  // 0 = no limit (caller should bound it)
	OrderDesc bool // newest first when true; default is chronological
}

// EventStore is the store abstraction. The concrete implementation is the
// SQLite store; tests may substitute an in-memory or fake store.
type EventStore interface {
	RecordDecision(ctx context.Context, d DecisionRecord) error
	RecordAuditEvent(ctx context.Context, a AuditRecord) error
	DecisionCount(ctx context.Context) (int64, error)
	ListDecisions(ctx context.Context, f Filter) ([]DecisionRecord, error)
	ListAuditEvents(ctx context.Context, f AuditFilter) ([]AuditRecord, error)
	ListSessions(ctx context.Context) ([]Session, error)
	ListSessionsFiltered(ctx context.Context, f SessionFilter) ([]Session, error)
	Cleanup(ctx context.Context, maxAge time.Duration) error
	UpsertDiscoveredTool(ctx context.Context, server, tool, source string) error
	UpsertDiscoveredSkill(ctx context.Context, name, source string) error
	ListDiscoveredTools(ctx context.Context, server string) ([]DiscoveredTool, error)
	ListDiscoveredSkills(ctx context.Context) ([]DiscoveredSkill, error)
	Emit(ctx context.Context, e audit.Event) error
	ListAuditLog(ctx context.Context, f AuditLogFilter) ([]AuditLogEntry, error)
	ListGrantAuditLog(ctx context.Context, limit int) ([]AuditLogEntry, error)
	Close() error
}

// ReadOnlyStore is the read-only subset of EventStore. UI, logs, and replay
// use this to avoid write-lock contention with the daemon.
type ReadOnlyStore interface {
	DecisionCount(ctx context.Context) (int64, error)
	ListDecisions(ctx context.Context, f Filter) ([]DecisionRecord, error)
	ListAuditEvents(ctx context.Context, f AuditFilter) ([]AuditRecord, error)
	ListSessions(ctx context.Context) ([]Session, error)
	ListSessionsFiltered(ctx context.Context, f SessionFilter) ([]Session, error)
	CountActionsBySession(ctx context.Context) ([]ActionCount, error)
	ListDiscoveredTools(ctx context.Context, server string) ([]DiscoveredTool, error)
	ListDiscoveredSkills(ctx context.Context) ([]DiscoveredSkill, error)
	ListAuditLog(ctx context.Context, f AuditLogFilter) ([]AuditLogEntry, error)
	ListGrantAuditLog(ctx context.Context, limit int) ([]AuditLogEntry, error)
	ListDistinctCWDs(ctx context.Context) ([]string, error)
	ListDistinctMCPToolNames(ctx context.Context) ([]string, error)
	ListDistinctSkillInputs(ctx context.Context) ([]string, error)
	CountWouldBlock(ctx context.Context, since time.Time) ([]WouldBlockCount, error)
	Close() error
}

// WouldBlockCount is one row of the monitor-mode report: a rule that fired,
// the verdict it returned, and how often -- for calls that ran anyway.
// Aggregated in SQL rather than over ListDecisions, whose limit is clamped and
// would silently truncate the report.
// See ADR 0091-monitor-mode-tools.
type WouldBlockCount struct {
	RuleID      string
	WouldAction string
	ToolName    string
	Count       int64
}

// The key-matching rules live in internal/redact. They used to live here and
// claim to be the single source of truth while internal/mitm kept its own,
// weaker list -- so a Datadog API key reached network.db in the clear. The
// claim is now true because there is only one list. ADR 0019, ADR 0032,
// AGE-232.

// maxRedactedLen is the byte cap on the persisted tool_input JSON.
const maxRedactedLen = 4096

// RedactToolInput returns the JSON encoding of in with secret-bearing values
// replaced by "[redacted]", truncated to maxRedactedLen bytes on a rune
// boundary. Returns "{}" for a nil input. This is the sole redactor; the raw
// input is never persisted.
func RedactToolInput(in map[string]interface{}) string {
	if in == nil {
		return "{}"
	}
	redacted := redactValue(in).(map[string]interface{})
	b, err := json.Marshal(redacted)
	if err != nil {
		return "{}"
	}
	s := string(b)
	if len(s) <= maxRedactedLen {
		return s
	}
	end := maxRedactedLen
	for end > 0 && (s[end]&0xC0) == 0x80 {
		end--
	}
	return s[:end] + "…"
}

// redactValue recursively walks maps and slices. Key-matched values are
// replaced wholesale; string scalars are also swept for secret-shaped values,
// which is what catches a credential in a positional value like a Bash
// command (ADR 0084-redact-secret-values).
func redactValue(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, vv := range val {
			if shouldRedactKey(k) {
				out[k] = "[redacted]"
			} else {
				out[k] = redactValue(vv)
			}
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(val))
		for i, vv := range val {
			out[i] = redactValue(vv)
		}
		return out
	case string:
		return redactSecretsInText(val)
	default:
		return v
	}
}

// shouldRedactKey reports whether k names a secret-bearing value.
func shouldRedactKey(k string) bool {
	return redact.ShouldRedactKey(k)
}
