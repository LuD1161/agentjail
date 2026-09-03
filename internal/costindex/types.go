// Package costindex defines the typed persistence contract for local cost
// usage. It stores usage metadata only; transcript content never crosses this
// boundary. See ADR 0142-incremental-cost-index.
package costindex

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type Source string

const (
	SourceClaudeCode Source = "claude-code"
	SourceCodex      Source = "codex"
	SourceOpenCode   Source = "opencode"
)

type Path string
type Generation string
type EventKey string
type SessionID string
type Agent string
type Model string
type Project string
type PricingMode string
type PricingRevision string
type Day string

var (
	ErrCheckpointRegression = errors.New("cost index checkpoint offset regressed")
	ErrGenerationMismatch   = errors.New("cost index generation mismatch")
)

const maxParserStateBytes = 64 << 10

// ParserStateJSON is bounded, typed-parser continuation metadata serialized at
// the store boundary. It must never contain transcript or message content.
type ParserStateJSON string

func NewParserStateJSON(encoded []byte) (ParserStateJSON, error) {
	if len(encoded) == 0 {
		return ParserStateJSON("{}"), nil
	}
	if len(encoded) > maxParserStateBytes {
		return "", fmt.Errorf("cost index parser state exceeds %d bytes", maxParserStateBytes)
	}
	if !json.Valid(encoded) {
		return "", errors.New("cost index parser state is not valid JSON")
	}
	return ParserStateJSON(encoded), nil
}

// SourceRef identifies one current transcript or external usage source.
type SourceRef struct {
	Source Source
	Path   Path
}

// GenerationRef identifies one immutable incarnation of a source path.
type GenerationRef struct {
	Source     Source
	Path       Path
	Generation Generation
}

// Checkpoint is the last complete record committed for one source path.
type Checkpoint struct {
	Source        Source
	Path          Path
	Generation    Generation
	FileIdentity  string
	SizeBytes     int64
	ModTimeNS     int64
	OffsetBytes   int64
	ParserVersion int64
	ParserState   ParserStateJSON
	UpdatedAt     time.Time
}

// TokenUsage is the pricing input retained from one normalized usage event.
type TokenUsage struct {
	Input        int64
	Output       int64
	CacheRead    int64
	CacheWrite   int64
	CacheWrite5m int64
	CacheWrite1h int64
}

// UsageEvent is one idempotent token fact. RequestUsage retains the exact
// request dimensions needed for long-context repricing; HasRequestUsage says
// whether those dimensions are complete.
type UsageEvent struct {
	Source          Source
	Path            Path
	Generation      Generation
	EventKey        EventKey
	SessionID       SessionID
	ParentSessionID SessionID
	Timestamp       time.Time
	Agent           Agent
	Model           Model
	Project         Project
	Usage           TokenUsage
	Reasoning       int64
	RequestUsage    TokenUsage
	HasRequestUsage bool
	HasCacheTTL     bool
	RecordedCostUSD float64
}

// IngestionBatch advances one checkpoint atomically with idempotent event
// inserts. Every event must belong to the checkpoint's source generation.
type IngestionBatch struct {
	Checkpoint Checkpoint
	Events     []UsageEvent
}

// DailyUsage is one precomputed per-session/model/day row. Source generation
// remains part of the row so a replaced source can be removed without touching
// unrelated history from the same day.
type DailyUsage struct {
	Source          Source
	Path            Path
	Generation      Generation
	Day             Day
	StartedAt       time.Time
	SessionID       SessionID
	Agent           Agent
	Model           Model
	Project         Project
	Usage           TokenUsage
	Reasoning       int64
	PricingMode     PricingMode
	PricingRevision PricingRevision
	CostUSD         float64
	EventCount      int64
}

// Window is half-open: Since is inclusive and Before is exclusive. Zero
// bounds are expanded by the SQLite adapter.
type Window struct {
	Since  time.Time
	Before time.Time
}

type Status struct {
	Ready           bool
	CheckpointCount int64
	EventCount      int64
	DailyRowCount   int64
	LatestUpdate    time.Time
}

// Writer is implemented by the daemon-owned singleton store connection.
type Writer interface {
	CostCheckpoint(context.Context, SourceRef) (Checkpoint, bool, error)
	CommitCostBatch(context.Context, IngestionBatch) error
	ResetCostGeneration(context.Context, GenerationRef) error
	ReplaceCostDailyUsage(context.Context, GenerationRef, Day, []DailyUsage) error
	ReplaceAllCostDailyUsage(context.Context, []DailyUsage) error
}

// Reader is implemented by both writable and read-only singleton store views.
type Reader interface {
	CostCheckpoint(context.Context, SourceRef) (Checkpoint, bool, error)
	ListCostCheckpoints(context.Context, Source) ([]Checkpoint, error)
	ListCostUsageEvents(context.Context, Window) ([]UsageEvent, error)
	ListCostDailyUsage(context.Context, Window) ([]DailyUsage, error)
	CostIndexStatus(context.Context) (Status, error)
}
