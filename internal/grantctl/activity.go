package grantctl

const (
	MaxNetworkEvents           = 200
	MaxActivitySessions        = 50
	MaxSessionLogEntries       = 500
	MaxActivityTextBytes       = 512
	MaxSessionCommandBytes     = 4096
	MaxSessionSearchBytes      = 256
	MaxSessionLogSnapshotBytes = 56 * 1024
)

// NetworkSnapshotV1 is a bounded read-only window over intercepted traffic.
// Available is false when no network store has been created yet.
type NetworkSnapshotV1 struct {
	ProtocolVersion   ProtocolVersion  `json:"protocol_version"`
	GeneratedAtUnixMs UnixMilliseconds `json:"generated_at_unix_ms"`
	Available         bool             `json:"available"`
	Events            []NetworkEventV1 `json:"events"`
}

// NetworkEventV1 omits headers, bodies, full URLs, and full working paths.
type NetworkEventV1 struct {
	ID              int64            `json:"id"`
	TimestampUnixMs UnixMilliseconds `json:"timestamp_unix_ms"`
	Host            string           `json:"host"`
	Method          string           `json:"method"`
	Path            string           `json:"path"`
	StatusCode      int              `json:"status_code"`
	RequestSize     int64            `json:"request_size"`
	ResponseSize    int64            `json:"response_size"`
	ElapsedMs       int64            `json:"elapsed_ms"`
	Error           string           `json:"error,omitempty"`
	SessionID       string           `json:"session_id,omitempty"`
	Agent           string           `json:"agent,omitempty"`
	Project         string           `json:"project,omitempty"`
	ToolName        string           `json:"tool_name,omitempty"`
	PolicyAction    string           `json:"policy_action,omitempty"`
	PolicyReason    string           `json:"policy_reason,omitempty"`
	Service         string           `json:"service,omitempty"`
	Verb            string           `json:"verb,omitempty"`
	ResourceType    string           `json:"resource_type,omitempty"`
}

// SessionLogSnapshotV1 returns a bounded session picker and exact-session rows.
type SessionLogSnapshotV1 struct {
	ProtocolVersion   ProtocolVersion     `json:"protocol_version"`
	GeneratedAtUnixMs UnixMilliseconds    `json:"generated_at_unix_ms"`
	SelectedSessionID string              `json:"selected_session_id,omitempty"`
	Sessions          []ActivitySessionV1 `json:"sessions"`
	Entries           []SessionActionV1   `json:"entries"`
	TotalMatches      int                 `json:"total_matches"`
	HasMore           bool                `json:"has_more"`
	NextBeforeID      int64               `json:"next_before_id,omitempty"`
	Truncated         bool                `json:"truncated"`
}

// SessionLogQueryV1 selects one byte-bounded page from an exact session.
// BeforeID is a descending keyset cursor; Search never scans raw tool input.
type SessionLogQueryV1 struct {
	SessionID string
	BeforeID  int64
	Search    string
	Actions   []string
}

type ActivitySessionV1 struct {
	SessionID       string           `json:"session_id"`
	Agent           string           `json:"agent"`
	Project         string           `json:"project"`
	StartedAtUnixMs UnixMilliseconds `json:"started_at_unix_ms"`
	EndedAtUnixMs   UnixMilliseconds `json:"ended_at_unix_ms,omitempty"`
	AuditedCalls    int              `json:"audited_calls"`
	Active          bool             `json:"active"`
}

// SessionActionV1 is a redacted action summary; tool input is never projected.
type SessionActionV1 struct {
	ID                int64            `json:"id"`
	TimestampUnixMs   UnixMilliseconds `json:"timestamp_unix_ms"`
	ToolName          string           `json:"tool_name"`
	Summary           string           `json:"summary,omitempty"`
	Action            string           `json:"action"`
	RuleID            string           `json:"rule_id,omitempty"`
	Reason            string           `json:"reason,omitempty"`
	Impact            string           `json:"impact,omitempty"`
	ElapsedUs         int64            `json:"elapsed_us"`
	WouldAction       string           `json:"would_action,omitempty"`
	PolicyAction      string           `json:"policy_action,omitempty"`
	EffectiveAction   string           `json:"effective_action,omitempty"`
	Adapter           string           `json:"adapter,omitempty"`
	TranslationReason string           `json:"translation_reason,omitempty"`
	FinalAction       string           `json:"final_action,omitempty"`
	Enforcer          string           `json:"enforcer,omitempty"`
}

// SessionActionDetailV1 is fetched only after a user opens one timeline row.
// Command is the bounded, store-redacted shell command; non-Bash actions return
// an empty command.
type SessionActionDetailV1 struct {
	ProtocolVersion ProtocolVersion `json:"protocol_version"`
	ActionID        int64           `json:"action_id"`
	SessionID       string          `json:"session_id"`
	Command         string          `json:"command,omitempty"`
}
