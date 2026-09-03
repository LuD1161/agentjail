package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/LuD1161/agentjail/internal/costindex"
)

var maxCostIndexTime = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

func (s *sqliteStore) CostCheckpoint(ctx context.Context, ref costindex.SourceRef) (costindex.Checkpoint, bool, error) {
	row, err := s.queries.GetCostSourceCheckpoint(ctx, GetCostSourceCheckpointParams{
		Source: string(ref.Source), SourcePath: string(ref.Path),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return costindex.Checkpoint{}, false, nil
	}
	if err != nil {
		return costindex.Checkpoint{}, false, fmt.Errorf("store: get cost checkpoint: %w", err)
	}
	cp, err := costCheckpointFromRow(row)
	return cp, err == nil, err
}

func (s *sqliteStore) ListCostCheckpoints(ctx context.Context, source costindex.Source) ([]costindex.Checkpoint, error) {
	rows, err := s.queries.ListCostSourceCheckpoints(ctx, ListCostSourceCheckpointsParams{
		Column1: string(source), Source: string(source),
	})
	if err != nil {
		return nil, fmt.Errorf("store: list cost checkpoints: %w", err)
	}
	out := make([]costindex.Checkpoint, 0, len(rows))
	for _, row := range rows {
		cp, err := costCheckpointFromRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, cp)
	}
	return out, nil
}

func costCheckpointFromRow(row GetCostSourceCheckpointRow) (costindex.Checkpoint, error) {
	updated, err := time.Parse(time.RFC3339Nano, row.UpdatedTs)
	if err != nil {
		return costindex.Checkpoint{}, fmt.Errorf("store: parse cost checkpoint updated timestamp: %w", err)
	}
	state, err := costindex.NewParserStateJSON([]byte(row.ParserStateJson))
	if err != nil {
		return costindex.Checkpoint{}, fmt.Errorf("store: decode cost checkpoint parser state: %w", err)
	}
	return costindex.Checkpoint{
		Source: costindex.Source(row.Source), Path: costindex.Path(row.SourcePath),
		Generation: costindex.Generation(row.Generation), FileIdentity: row.FileIdentity,
		SizeBytes: row.SizeBytes, ModTimeNS: row.MtimeNs, OffsetBytes: row.OffsetBytes,
		ParserVersion: row.ParserVersion, ParserState: state, UpdatedAt: updated,
	}, nil
}

func (s *sqliteStore) CommitCostBatch(ctx context.Context, batch costindex.IngestionBatch) error {
	cp := batch.Checkpoint
	if err := validateCostCheckpoint(cp); err != nil {
		return err
	}
	for _, event := range batch.Events {
		if err := validateCostEvent(cp, event); err != nil {
			return err
		}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin cost batch: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	txq := New(tx)
	current, err := txq.GetCostSourceCheckpoint(ctx, GetCostSourceCheckpointParams{
		Source: string(cp.Source), SourcePath: string(cp.Path),
	})
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("store: load cost checkpoint for batch: %w", err)
	}
	if err == nil {
		if current.Generation != string(cp.Generation) {
			return fmt.Errorf("%w: have %q, got %q", costindex.ErrGenerationMismatch, current.Generation, cp.Generation)
		}
		if cp.OffsetBytes < current.OffsetBytes {
			return fmt.Errorf("%w: have %d, got %d", costindex.ErrCheckpointRegression, current.OffsetBytes, cp.OffsetBytes)
		}
	}

	for _, event := range batch.Events {
		if err := txq.InsertCostUsageEvent(ctx, costEventParams(event)); err != nil {
			return fmt.Errorf("store: insert cost usage event: %w", err)
		}
	}
	if err := txq.UpsertCostSourceCheckpoint(ctx, costCheckpointParams(cp)); err != nil {
		return fmt.Errorf("store: advance cost checkpoint: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit cost batch: %w", err)
	}
	return nil
}

func validateCostCheckpoint(cp costindex.Checkpoint) error {
	if cp.Source == "" || cp.Path == "" || cp.Generation == "" || cp.FileIdentity == "" {
		return errors.New("store: cost checkpoint identity is incomplete")
	}
	if cp.SizeBytes < 0 || cp.ModTimeNS < 0 || cp.OffsetBytes < 0 || cp.OffsetBytes > cp.SizeBytes || cp.ParserVersion < 1 {
		return errors.New("store: cost checkpoint metadata is invalid")
	}
	if cp.UpdatedAt.IsZero() {
		return errors.New("store: cost checkpoint updated timestamp is required")
	}
	if _, err := costindex.NewParserStateJSON([]byte(cp.ParserState)); err != nil {
		return fmt.Errorf("store: cost checkpoint parser state: %w", err)
	}
	return nil
}

func validateCostEvent(cp costindex.Checkpoint, event costindex.UsageEvent) error {
	if event.Source != cp.Source || event.Path != cp.Path || event.Generation != cp.Generation {
		return errors.New("store: cost event does not belong to batch generation")
	}
	if event.EventKey == "" || event.SessionID == "" || event.Timestamp.IsZero() {
		return errors.New("store: cost event identity is incomplete")
	}
	if event.RecordedCostUSD < 0 || !validTokenUsage(event.Usage) || !validTokenUsage(event.RequestUsage) || event.Reasoning < 0 {
		return errors.New("store: cost event usage is invalid")
	}
	return nil
}

func validTokenUsage(usage costindex.TokenUsage) bool {
	return usage.Input >= 0 && usage.Output >= 0 && usage.CacheRead >= 0 &&
		usage.CacheWrite >= 0 && usage.CacheWrite5m >= 0 && usage.CacheWrite1h >= 0
}

func costCheckpointParams(cp costindex.Checkpoint) UpsertCostSourceCheckpointParams {
	return UpsertCostSourceCheckpointParams{
		Source: string(cp.Source), SourcePath: string(cp.Path), Generation: string(cp.Generation),
		FileIdentity: cp.FileIdentity, SizeBytes: cp.SizeBytes, MtimeNs: cp.ModTimeNS,
		OffsetBytes: cp.OffsetBytes, ParserVersion: cp.ParserVersion,
		ParserStateJson: string(cp.ParserState), UpdatedTs: cp.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}

func costEventParams(event costindex.UsageEvent) InsertCostUsageEventParams {
	return InsertCostUsageEventParams{
		Source: string(event.Source), SourcePath: string(event.Path), Generation: string(event.Generation),
		EventKey: string(event.EventKey), SessionID: string(event.SessionID), ParentSessionID: string(event.ParentSessionID),
		Ts: event.Timestamp.UTC().Format(time.RFC3339Nano), Agent: string(event.Agent), Model: string(event.Model), Project: string(event.Project),
		InputTokens: event.Usage.Input, OutputTokens: event.Usage.Output, CacheReadTokens: event.Usage.CacheRead,
		CacheWriteTokens: event.Usage.CacheWrite, CacheWrite5mTokens: event.Usage.CacheWrite5m,
		CacheWrite1hTokens: event.Usage.CacheWrite1h, ReasoningTokens: event.Reasoning,
		RequestInputTokens: event.RequestUsage.Input, RequestOutputTokens: event.RequestUsage.Output,
		RequestCacheReadTokens: event.RequestUsage.CacheRead, RequestCacheWriteTokens: event.RequestUsage.CacheWrite,
		HasRequestUsage: boolInt64(event.HasRequestUsage), HasCacheTtl: boolInt64(event.HasCacheTTL),
		RecordedCostUsd: event.RecordedCostUSD,
	}
}

func boolInt64(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

func (s *sqliteStore) ResetCostGeneration(ctx context.Context, ref costindex.GenerationRef) error {
	if ref.Source == "" || ref.Path == "" || ref.Generation == "" {
		return errors.New("store: cost generation identity is incomplete")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin reset cost generation: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	q := New(tx)
	params := DeleteCostGenerationParams{Source: string(ref.Source), SourcePath: string(ref.Path), Generation: string(ref.Generation)}
	if err := q.DeleteCostUsageEventsGeneration(ctx, params); err != nil {
		return fmt.Errorf("store: reset cost events: %w", err)
	}
	if err := q.DeleteCostDailyUsageGeneration(ctx, params); err != nil {
		return fmt.Errorf("store: reset cost daily usage: %w", err)
	}
	if err := q.DeleteCostSourceCheckpointGeneration(ctx, params); err != nil {
		return fmt.Errorf("store: reset cost checkpoint: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit reset cost generation: %w", err)
	}
	return nil
}

func (s *sqliteStore) ReplaceCostDailyUsage(ctx context.Context, ref costindex.GenerationRef, day costindex.Day, rows []costindex.DailyUsage) error {
	if ref.Source == "" || ref.Path == "" || ref.Generation == "" || day == "" {
		return errors.New("store: cost daily usage identity is incomplete")
	}
	for _, row := range rows {
		if row.Source != ref.Source || row.Path != ref.Path || row.Generation != ref.Generation || row.Day != day {
			return errors.New("store: cost daily usage row does not belong to replacement")
		}
		if err := validateCostDailyUsage(row); err != nil {
			return err
		}
	}
	return s.replaceCostDailyUsage(ctx, func(q *Queries) error {
		return q.DeleteCostDailyUsageGenerationDay(ctx, DeleteCostGenerationDayParams{
			Source: string(ref.Source), SourcePath: string(ref.Path), Generation: string(ref.Generation), UsageDay: string(day),
		})
	}, rows)
}

func (s *sqliteStore) ReplaceAllCostDailyUsage(ctx context.Context, rows []costindex.DailyUsage) error {
	for _, row := range rows {
		if err := validateCostDailyUsage(row); err != nil {
			return err
		}
	}
	return s.replaceCostDailyUsage(ctx, func(q *Queries) error { return q.DeleteAllCostDailyUsage(ctx) }, rows)
}

func (s *sqliteStore) replaceCostDailyUsage(ctx context.Context, clear func(*Queries) error, rows []costindex.DailyUsage) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin replace cost daily usage: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	q := New(tx)
	if err := clear(q); err != nil {
		return fmt.Errorf("store: clear cost daily usage: %w", err)
	}
	for _, row := range rows {
		if err := q.InsertCostDailyUsage(ctx, costDailyUsageParams(row)); err != nil {
			return fmt.Errorf("store: insert cost daily usage: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit cost daily usage: %w", err)
	}
	return nil
}

func validateCostDailyUsage(row costindex.DailyUsage) error {
	if row.Source == "" || row.Path == "" || row.Generation == "" || row.Day == "" || row.SessionID == "" || row.StartedAt.IsZero() || row.PricingRevision == "" {
		return errors.New("store: cost daily usage identity is incomplete")
	}
	if !validTokenUsage(row.Usage) || row.Reasoning < 0 || row.CostUSD < 0 || row.EventCount < 0 {
		return errors.New("store: cost daily usage is invalid")
	}
	return nil
}

func costDailyUsageParams(row costindex.DailyUsage) InsertCostDailyUsageParams {
	return InsertCostDailyUsageParams{
		UsageDay: string(row.Day), Source: string(row.Source), SourcePath: string(row.Path), Generation: string(row.Generation),
		SessionID: string(row.SessionID), StartedTs: row.StartedAt.UTC().Format(time.RFC3339Nano), Agent: string(row.Agent),
		Model: string(row.Model), Project: string(row.Project), InputTokens: row.Usage.Input, OutputTokens: row.Usage.Output,
		CacheReadTokens: row.Usage.CacheRead, CacheWriteTokens: row.Usage.CacheWrite,
		CacheWrite5mTokens: row.Usage.CacheWrite5m, CacheWrite1hTokens: row.Usage.CacheWrite1h,
		ReasoningTokens: row.Reasoning, PricingMode: string(row.PricingMode), PricingRevision: string(row.PricingRevision),
		CostUsd: row.CostUSD, EventCount: row.EventCount,
	}
}

func costWindowBounds(window costindex.Window) (string, string) {
	since := time.Time{}
	if !window.Since.IsZero() {
		since = window.Since.UTC()
	}
	before := maxCostIndexTime
	if !window.Before.IsZero() {
		before = window.Before.UTC()
	}
	return since.Format(time.RFC3339Nano), before.Format(time.RFC3339Nano)
}

func (s *sqliteStore) ListCostUsageEvents(ctx context.Context, window costindex.Window) ([]costindex.UsageEvent, error) {
	since, before := costWindowBounds(window)
	rows, err := s.queries.ListCostUsageEventsWindow(ctx, ListCostUsageEventsWindowParams{Ts: since, Ts_2: before})
	if err != nil {
		return nil, fmt.Errorf("store: list cost usage events: %w", err)
	}
	out := make([]costindex.UsageEvent, 0, len(rows))
	for _, row := range rows {
		ts, err := time.Parse(time.RFC3339Nano, row.Ts)
		if err != nil {
			return nil, fmt.Errorf("store: parse cost event timestamp: %w", err)
		}
		out = append(out, costindex.UsageEvent{
			Source: costindex.Source(row.Source), Path: costindex.Path(row.SourcePath), Generation: costindex.Generation(row.Generation),
			EventKey: costindex.EventKey(row.EventKey), SessionID: costindex.SessionID(row.SessionID), ParentSessionID: costindex.SessionID(row.ParentSessionID),
			Timestamp: ts, Agent: costindex.Agent(row.Agent), Model: costindex.Model(row.Model), Project: costindex.Project(row.Project),
			Usage:           costindex.TokenUsage{Input: row.InputTokens, Output: row.OutputTokens, CacheRead: row.CacheReadTokens, CacheWrite: row.CacheWriteTokens, CacheWrite5m: row.CacheWrite5mTokens, CacheWrite1h: row.CacheWrite1hTokens},
			Reasoning:       row.ReasoningTokens,
			RequestUsage:    costindex.TokenUsage{Input: row.RequestInputTokens, Output: row.RequestOutputTokens, CacheRead: row.RequestCacheReadTokens, CacheWrite: row.RequestCacheWriteTokens},
			HasRequestUsage: row.HasRequestUsage != 0, HasCacheTTL: row.HasCacheTtl != 0, RecordedCostUSD: row.RecordedCostUsd,
		})
	}
	return out, nil
}

func (s *sqliteStore) ListCostDailyUsage(ctx context.Context, window costindex.Window) ([]costindex.DailyUsage, error) {
	since, before := costWindowBounds(window)
	rows, err := s.queries.ListCostDailyUsageWindow(ctx, ListCostDailyUsageWindowParams{StartedTs: since, StartedTs_2: before})
	if err != nil {
		return nil, fmt.Errorf("store: list cost daily usage: %w", err)
	}
	out := make([]costindex.DailyUsage, 0, len(rows))
	for _, row := range rows {
		startedAt, err := time.Parse(time.RFC3339Nano, row.StartedTs)
		if err != nil {
			return nil, fmt.Errorf("store: parse cost daily started timestamp: %w", err)
		}
		out = append(out, costindex.DailyUsage{
			Source: costindex.Source(row.Source), Path: costindex.Path(row.SourcePath), Generation: costindex.Generation(row.Generation),
			Day: costindex.Day(row.UsageDay), SessionID: costindex.SessionID(row.SessionID), StartedAt: startedAt,
			Agent: costindex.Agent(row.Agent), Model: costindex.Model(row.Model), Project: costindex.Project(row.Project),
			Usage:     costindex.TokenUsage{Input: row.InputTokens, Output: row.OutputTokens, CacheRead: row.CacheReadTokens, CacheWrite: row.CacheWriteTokens, CacheWrite5m: row.CacheWrite5mTokens, CacheWrite1h: row.CacheWrite1hTokens},
			Reasoning: row.ReasoningTokens, PricingMode: costindex.PricingMode(row.PricingMode), PricingRevision: costindex.PricingRevision(row.PricingRevision),
			CostUSD: row.CostUsd, EventCount: row.EventCount,
		})
	}
	return out, nil
}

func (s *sqliteStore) CostIndexStatus(ctx context.Context) (costindex.Status, error) {
	row, err := s.queries.CostIndexStatus(ctx)
	if err != nil {
		return costindex.Status{}, fmt.Errorf("store: cost index status: %w", err)
	}
	status := costindex.Status{CheckpointCount: row.CheckpointCount, EventCount: row.EventCount, DailyRowCount: row.DailyRowCount}
	if row.LatestUpdate != "" {
		status.LatestUpdate, err = time.Parse(time.RFC3339Nano, row.LatestUpdate)
		if err != nil {
			return costindex.Status{}, fmt.Errorf("store: parse latest cost index update: %w", err)
		}
	}
	ready, found, err := s.CostCheckpoint(ctx, costindex.SourceRef{Source: "projection", Path: "@projection"})
	if err != nil {
		return costindex.Status{}, fmt.Errorf("store: cost index readiness: %w", err)
	}
	status.Ready = found
	if found {
		status.LatestUpdate = ready.UpdatedAt
	}
	return status, nil
}

func (r *sqliteROStore) CostCheckpoint(ctx context.Context, ref costindex.SourceRef) (costindex.Checkpoint, bool, error) {
	return r.inner.CostCheckpoint(ctx, ref)
}

func (r *sqliteROStore) ListCostCheckpoints(ctx context.Context, source costindex.Source) ([]costindex.Checkpoint, error) {
	return r.inner.ListCostCheckpoints(ctx, source)
}

func (r *sqliteROStore) ListCostUsageEvents(ctx context.Context, window costindex.Window) ([]costindex.UsageEvent, error) {
	return r.inner.ListCostUsageEvents(ctx, window)
}

func (r *sqliteROStore) ListCostDailyUsage(ctx context.Context, window costindex.Window) ([]costindex.DailyUsage, error) {
	return r.inner.ListCostDailyUsage(ctx, window)
}

func (r *sqliteROStore) CostIndexStatus(ctx context.Context) (costindex.Status, error) {
	return r.inner.CostIndexStatus(ctx)
}
