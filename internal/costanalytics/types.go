package costanalytics

import "time"

type Source string

const (
	SourceClaudeCode Source = "claude-code"
	SourceCodex      Source = "codex"
	SourceOpenCode   Source = "opencode"
)

type SessionID string
type Agent string
type Model string
type Project string
type Period string
type PricingMode string

const (
	PricingModeBaseEstimate PricingMode = "base-estimate"
	PricingModeTTLEstimate  PricingMode = "ttl-estimate"
	PricingModeRequestAware PricingMode = "request-aware"
	PricingModeRecorded     PricingMode = "recorded"
)

// TokenUsage is the typed pricing input retained from one request or aggregate.
type TokenUsage struct {
	Input        int64
	Output       int64
	CacheRead    int64
	CacheWrite   int64
	CacheWrite5m int64
	CacheWrite1h int64
}

const (
	AgentClaudeCode Agent = "claude-code"
	AgentCodex      Agent = "codex"
	AgentOpenCode   Agent = "opencode"
)

type SessionCost struct {
	Source       Source      `json:"source"`
	SessionID    SessionID   `json:"session_id"`
	Agent        Agent       `json:"agent"`
	Model        Model       `json:"model"`
	Project      Project     `json:"project"`
	CostUSD      float64     `json:"cost_usd"`
	InputTokens  int64       `json:"input_tokens"`
	OutputTokens int64       `json:"output_tokens"`
	CacheRead    int64       `json:"cache_read_tokens"`
	CacheWrite   int64       `json:"cache_write_tokens"`
	CacheWrite5m int64       `json:"cache_write_5m_tokens"`
	CacheWrite1h int64       `json:"cache_write_1h_tokens"`
	Reasoning    int64       `json:"reasoning_tokens"`
	PricingMode  PricingMode `json:"pricing_mode"`
	StartedAt    time.Time   `json:"started_at"`
}

type ProjectSummary struct {
	Project      Project `json:"project"`
	CostUSD      float64 `json:"cost_usd"`
	Percent      float64 `json:"percent"`
	SessionCount int     `json:"session_count"`
}

type ModelSummary struct {
	Model        Model   `json:"model"`
	CostUSD      float64 `json:"cost_usd"`
	Percent      float64 `json:"percent"`
	SessionCount int     `json:"session_count"`
	InputTokens  int64   `json:"input_tokens"`
	OutputTokens int64   `json:"output_tokens"`
	CacheRead    int64   `json:"cache_read_tokens"`
	CacheWrite   int64   `json:"cache_write_tokens"`
	CacheWrite5m int64   `json:"cache_write_5m_tokens"`
	CacheWrite1h int64   `json:"cache_write_1h_tokens"`
	BaseEstimate bool    `json:"base_estimate"`
	TTLEstimate  bool    `json:"ttl_estimate"`
}

type CostReport struct {
	Period       Period           `json:"period"`
	TotalCost    float64          `json:"total_cost"`
	SessionCount int              `json:"session_count"`
	ByProject    []ProjectSummary `json:"by_project"`
	ByModel      []ModelSummary   `json:"by_model"`
	CacheHitRate float64          `json:"cache_hit_rate"`
	AvgCost      float64          `json:"avg_cost_per_session"`
	AvgInputTok  int64            `json:"avg_input_tokens"`
	AvgOutputTok int64            `json:"avg_output_tokens"`
}

type Reader interface {
	ReadSessions(since time.Time) ([]SessionCost, error)
	Close() error
}
