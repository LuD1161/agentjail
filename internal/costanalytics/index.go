package costanalytics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LuD1161/agentjail/internal/costindex"
)

const (
	costParserVersion  = int64(1)
	costPricingVersion = costindex.PricingRevision("2026-09-02-v1")
	indexBatchRecords  = 1_000
)

// IndexStore is the daemon-owned persistence seam used by the cost indexer.
type IndexStore interface {
	costindex.Writer
	costindex.Reader
}

// IndexPaths locates the local, provider-owned usage sources.
type IndexPaths struct {
	ClaudeProjects string
	CodexSessions  string
	OpenCodeDB     string
}

func DefaultIndexPaths() IndexPaths {
	home, _ := os.UserHomeDir()
	return IndexPaths{
		ClaudeProjects: filepath.Join(home, ".claude", "projects"),
		CodexSessions:  filepath.Join(home, ".codex", "sessions"),
		OpenCodeDB:     DefaultOpenCodeDBPath(),
	}
}

// Indexer incrementally ingests transcript usage metadata and materializes
// report-ready session rows. It never stores transcript content.
type Indexer struct {
	store IndexStore
	paths IndexPaths
	now   func() time.Time
}

func NewIndexer(store IndexStore, paths IndexPaths) *Indexer {
	return &Indexer{store: store, paths: paths, now: time.Now}
}

type persistedParserState struct {
	Cursor JSONLCursorState   `json:"cursor"`
	Claude *ClaudeParserState `json:"claude,omitempty"`
	Codex  *CodexParserState  `json:"codex,omitempty"`
}

// Refresh ingests only new complete records and atomically replaces the small
// report projection after every source has been visited.
func (i *Indexer) Refresh(ctx context.Context) error {
	if i == nil || i.store == nil {
		return errors.New("cost index store is unavailable")
	}
	var errs []error
	for _, source := range []struct {
		kind costindex.Source
		root string
	}{
		{costindex.SourceClaudeCode, i.paths.ClaudeProjects},
		{costindex.SourceCodex, i.paths.CodexSessions},
	} {
		paths, err := transcriptPaths(source.root)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, path := range paths {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := i.ingestFile(ctx, source.kind, path); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if err := i.rebuildProjection(ctx); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	return i.markProjectionReady(ctx)
}

func transcriptPaths(root string) ([]string, error) {
	if root == "" {
		return nil, nil
	}
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, fs.ErrNotExist) {
				return nil
			}
			return walkErr
		}
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(path), ".jsonl") {
			return nil
		}
		if len(paths) >= maxTranscriptFiles {
			return errTranscriptFileLimit
		}
		paths = append(paths, path)
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("discover cost sources under %s: %w", root, err)
	}
	sort.Strings(paths)
	return paths, nil
}

func (i *Indexer) ingestFile(ctx context.Context, source costindex.Source, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open cost source %s: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat cost source %s: %w", path, err)
	}

	identity := transcriptFileIdentity(info)
	ref := costindex.SourceRef{Source: source, Path: costindex.Path(path)}
	checkpoint, found, err := i.store.CostCheckpoint(ctx, ref)
	if err != nil {
		return fmt.Errorf("load cost checkpoint %s: %w", path, err)
	}
	if found && (checkpoint.FileIdentity != identity || checkpoint.OffsetBytes > info.Size() || checkpoint.ParserVersion != costParserVersion) {
		if err := i.store.ResetCostGeneration(ctx, costindex.GenerationRef{Source: source, Path: ref.Path, Generation: checkpoint.Generation}); err != nil {
			return fmt.Errorf("reset cost source %s: %w", path, err)
		}
		found = false
	}

	generation := costindex.Generation(identity + ":v" + strconv.FormatInt(costParserVersion, 10))
	state := initialParserState(source, path, info.ModTime())
	if found {
		generation = checkpoint.Generation
		if err := json.Unmarshal([]byte(checkpoint.ParserState), &state); err != nil {
			return fmt.Errorf("decode cost checkpoint %s: %w", path, err)
		}
		state.Cursor.Offset = checkpoint.OffsetBytes
	}
	reader := io.NewSectionReader(file, 0, info.Size())
	cursor, err := NewJSONLCursor(reader, state.Cursor)
	if err != nil {
		return fmt.Errorf("resume cost source %s: %w", path, err)
	}

	events := make([]costindex.UsageEvent, 0, indexBatchRecords)
	records := 0
	flush := func() error {
		state.Cursor = cursor.State()
		encoded, err := json.Marshal(state)
		if err != nil {
			return err
		}
		parserState, err := costindex.NewParserStateJSON(encoded)
		if err != nil {
			return err
		}
		batch := costindex.IngestionBatch{Checkpoint: costindex.Checkpoint{
			Source: source, Path: ref.Path, Generation: generation,
			FileIdentity: identity, SizeBytes: info.Size(), ModTimeNS: info.ModTime().UnixNano(),
			OffsetBytes: state.Cursor.Offset, ParserVersion: costParserVersion,
			ParserState: parserState, UpdatedAt: i.now().UTC(),
		}, Events: events}
		if err := i.store.CommitCostBatch(ctx, batch); err != nil {
			return err
		}
		events = events[:0]
		records = 0
		return nil
	}

	for cursor.Scan() {
		record := cursor.Record()
		if event, ok := applyIndexedRecord(source, path, record, &state); ok {
			event.Generation = generation
			events = append(events, event)
		}
		records++
		if records >= indexBatchRecords {
			if err := flush(); err != nil {
				return fmt.Errorf("commit cost source %s: %w", path, err)
			}
		}
	}
	if err := cursor.Err(); err != nil {
		return fmt.Errorf("read cost source %s: %w", path, err)
	}
	if records != 0 || !found || cursor.State() != state.Cursor {
		if err := flush(); err != nil {
			return fmt.Errorf("commit cost source %s: %w", path, err)
		}
	}
	return nil
}

func initialParserState(source costindex.Source, path string, fallback time.Time) persistedParserState {
	state := persistedParserState{}
	sessionID := SessionID(strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)))
	switch source {
	case costindex.SourceClaudeCode:
		parser := NewClaudeParserState(sessionID, Project(extractProjectFromPath(path)), fallback)
		state.Claude = &parser
	case costindex.SourceCodex:
		parser := NewCodexParserState(sessionID, fallback)
		state.Codex = &parser
	}
	return state
}

func applyIndexedRecord(source costindex.Source, path string, record JSONLRecord, state *persistedParserState) (costindex.UsageEvent, bool) {
	base := costindex.UsageEvent{Source: source, Path: costindex.Path(path)}
	switch source {
	case costindex.SourceClaudeCode:
		usage, ok := ApplyClaudeRecord(state.Claude, record.Bytes)
		if !ok {
			return costindex.UsageEvent{}, false
		}
		base.EventKey = costindex.EventKey(strconv.FormatInt(record.Offset, 10))
		base.SessionID = costindex.SessionID(usage.SessionID)
		base.Timestamp = usage.OccurredAt.UTC()
		base.Agent = costindex.Agent(AgentClaudeCode)
		base.Model = costindex.Model(usage.Model)
		base.Project = costindex.Project(usage.Project)
		base.Usage = indexUsage(usage.Usage)
		base.HasCacheTTL = usage.Usage.CacheWrite == usage.Usage.CacheWrite5m+usage.Usage.CacheWrite1h
		return base, true
	case costindex.SourceCodex:
		usage, ok := ApplyCodexRecord(state.Codex, record.Bytes)
		if !ok {
			return costindex.UsageEvent{}, false
		}
		base.EventKey = cumulativeEventKey(usage.Cumulative)
		base.SessionID = costindex.SessionID(usage.SessionID)
		base.ParentSessionID = costindex.SessionID(state.Codex.ForkedFrom)
		base.Timestamp = usage.OccurredAt.UTC()
		base.Agent = costindex.Agent(AgentCodex)
		base.Model = costindex.Model(usage.Model)
		base.Project = costindex.Project(usage.Project)
		base.Usage = indexUsage(usage.Usage)
		base.Reasoning = usage.Reasoning
		if usage.Last != nil {
			base.RequestUsage = indexUsage(codexUsageForPricing(*usage.Last))
			base.HasRequestUsage = true
		}
		return base, true
	default:
		return costindex.UsageEvent{}, false
	}
}

func cumulativeEventKey(usage CodexTokenUsage) costindex.EventKey {
	return costindex.EventKey(fmt.Sprintf("%d/%d/%d/%d/%d", usage.InputTokens, usage.CachedInputTokens, usage.CacheWriteTokens, usage.OutputTokens, usage.ReasoningOutput))
}

func indexUsage(usage TokenUsage) costindex.TokenUsage {
	return costindex.TokenUsage{Input: usage.Input, Output: usage.Output, CacheRead: usage.CacheRead, CacheWrite: usage.CacheWrite, CacheWrite5m: usage.CacheWrite5m, CacheWrite1h: usage.CacheWrite1h}
}

func analyticsUsage(usage costindex.TokenUsage) TokenUsage {
	return TokenUsage{Input: usage.Input, Output: usage.Output, CacheRead: usage.CacheRead, CacheWrite: usage.CacheWrite, CacheWrite5m: usage.CacheWrite5m, CacheWrite1h: usage.CacheWrite1h}
}

func (i *Indexer) rebuildProjection(ctx context.Context) error {
	events, err := i.store.ListCostUsageEvents(ctx, costindex.Window{})
	if err != nil {
		return fmt.Errorf("read cost usage events: %w", err)
	}
	checkpoints, err := i.store.ListCostCheckpoints(ctx, "")
	if err != nil {
		return fmt.Errorf("read cost checkpoints: %w", err)
	}
	sessions, projectionErrs := projectIndexedSessions(events, checkpoints)
	if i.paths.OpenCodeDB != "" {
		reader, openErr := NewOpenCodeReader(i.paths.OpenCodeDB)
		if openErr == nil {
			openCode, readErr := reader.ReadSessions(time.Time{})
			closeErr := reader.Close()
			sessions = append(sessions, openCode...)
			projectionErrs = append(projectionErrs, readErr, closeErr)
		} else if !errors.Is(openErr, os.ErrNotExist) {
			projectionErrs = append(projectionErrs, openErr)
		}
	}
	rows := make([]costindex.DailyUsage, 0, len(sessions))
	for _, session := range sessions {
		rows = append(rows, dailyUsage(session))
	}
	if err := i.store.ReplaceAllCostDailyUsage(ctx, rows); err != nil {
		return fmt.Errorf("replace cost projection: %w", err)
	}
	return errors.Join(projectionErrs...)
}

func (i *Indexer) markProjectionReady(ctx context.Context) error {
	readyState, err := costindex.NewParserStateJSON([]byte(`{}`))
	if err != nil {
		return err
	}
	now := i.now().UTC()
	if err := i.store.CommitCostBatch(ctx, costindex.IngestionBatch{Checkpoint: costindex.Checkpoint{
		Source: "projection", Path: "@projection", Generation: "v1",
		FileIdentity: "projection", ParserVersion: costParserVersion,
		ParserState: readyState, UpdatedAt: now, ModTimeNS: now.UnixNano(),
	}}); err != nil {
		return fmt.Errorf("mark cost projection ready: %w", err)
	}
	return nil
}

type indexedSessionState struct {
	startedAt  time.Time
	project    Project
	parent     SessionID
	canSplit   bool
	finalUsage CodexTokenUsage
	maxTotal   int64
}

func projectIndexedSessions(events []costindex.UsageEvent, checkpoints []costindex.Checkpoint) ([]SessionCost, []error) {
	states := make(map[string]indexedSessionState)
	for _, checkpoint := range checkpoints {
		var persisted persistedParserState
		if json.Unmarshal([]byte(checkpoint.ParserState), &persisted) != nil {
			continue
		}
		if persisted.Claude != nil {
			key := string(costindex.SourceClaudeCode) + "\x00" + string(persisted.Claude.SessionID)
			current := states[key]
			if current.startedAt.IsZero() || persisted.Claude.StartedAt.Before(current.startedAt) {
				current.startedAt = persisted.Claude.StartedAt
			}
			if persisted.Claude.Project != "" {
				current.project = persisted.Claude.Project
			}
			states[key] = current
		}
		if persisted.Codex != nil {
			key := string(costindex.SourceCodex) + "\x00" + string(persisted.Codex.SessionID)
			current, exists := states[key]
			if !exists {
				current.canSplit = true
			}
			current.canSplit = current.canSplit && persisted.Codex.CanSplit
			if current.startedAt.IsZero() || persisted.Codex.StartedAt.Before(current.startedAt) {
				current.startedAt = persisted.Codex.StartedAt
			}
			if persisted.Codex.Project != "" {
				current.project = persisted.Codex.Project
			}
			if persisted.Codex.ForkedFrom != "" {
				current.parent = persisted.Codex.ForkedFrom
			}
			if persisted.Codex.MaxTotal >= current.maxTotal {
				current.maxTotal = persisted.Codex.MaxTotal
				current.finalUsage = persisted.Codex.Usage
			}
			states[key] = current
		}
	}

	claude := make(map[string]*SessionCost)
	codexEvents := make(map[string]map[costindex.EventKey]costindex.UsageEvent)
	for _, event := range events {
		key := string(event.Source) + "\x00" + string(event.SessionID)
		switch event.Source {
		case costindex.SourceClaudeCode:
			group := key + "\x00" + string(event.Model)
			session := claude[group]
			if session == nil {
				state := states[key]
				session = &SessionCost{Source: SourceClaudeCode, SessionID: SessionID(event.SessionID), Agent: AgentClaudeCode, Model: Model(event.Model), Project: Project(event.Project), StartedAt: state.startedAt, PricingMode: PricingModeRequestAware}
				claude[group] = session
			}
			addSessionUsage(session, event.Usage, event.Reasoning)
			if event.Usage.CacheWrite > event.Usage.CacheWrite5m+event.Usage.CacheWrite1h {
				session.PricingMode = PricingModeTTLEstimate
			}
		case costindex.SourceCodex:
			if codexEvents[key] == nil {
				codexEvents[key] = make(map[costindex.EventKey]costindex.UsageEvent)
			}
			codexEvents[key][event.EventKey] = event
		}
	}

	var errs []error
	for key, state := range states {
		if !strings.HasPrefix(key, string(costindex.SourceCodex)+"\x00") || !state.canSplit || state.parent == "" {
			continue
		}
		visited := map[string]struct{}{key: {}}
		parent := string(costindex.SourceCodex) + "\x00" + string(state.parent)
		for parent != string(costindex.SourceCodex)+"\x00" {
			if _, found := visited[parent]; found {
				errs = append(errs, fmt.Errorf("Codex fork lineage cycle for session %q; copied history may be included", strings.TrimPrefix(key, string(costindex.SourceCodex)+"\x00")))
				break
			}
			visited[parent] = struct{}{}
			ancestor, found := states[parent]
			if !found {
				errs = append(errs, fmt.Errorf("Codex fork parent %q is unavailable; copied history may be included", strings.TrimPrefix(parent, string(costindex.SourceCodex)+"\x00")))
				break
			}
			for eventKey := range codexEvents[parent] {
				delete(codexEvents[key], eventKey)
			}
			if ancestor.parent == "" {
				break
			}
			parent = string(costindex.SourceCodex) + "\x00" + string(ancestor.parent)
		}
	}

	sessions := make([]SessionCost, 0, len(claude)+len(codexEvents))
	for _, session := range claude {
		session.CostUSD = ComputeBaseCost(session.Model, TokenUsage{Input: session.InputTokens, Output: session.OutputTokens, CacheRead: session.CacheRead, CacheWrite: session.CacheWrite, CacheWrite5m: session.CacheWrite5m, CacheWrite1h: session.CacheWrite1h})
		sessions = append(sessions, *session)
	}
	for key, state := range states {
		if !strings.HasPrefix(key, string(costindex.SourceCodex)+"\x00") || state.maxTotal == 0 {
			continue
		}
		sessionID := SessionID(strings.TrimPrefix(key, string(costindex.SourceCodex)+"\x00"))
		if !state.canSplit {
			model := Model("(unknown)")
			for _, event := range codexEvents[key] {
				if event.Model != "" {
					model = Model(event.Model)
				}
			}
			usage := codexUsageForPricing(state.finalUsage)
			sessions = append(sessions, SessionCost{Source: SourceCodex, SessionID: sessionID, Agent: AgentCodex, Model: model, Project: state.project, CostUSD: ComputeBaseCost(model, usage), InputTokens: usage.Input, OutputTokens: usage.Output, CacheRead: usage.CacheRead, CacheWrite: usage.CacheWrite, Reasoning: state.finalUsage.ReasoningOutput, PricingMode: PricingModeBaseEstimate, StartedAt: state.startedAt})
			continue
		}
		byModel := make(map[Model]*SessionCost)
		pricedUsage := make(map[Model]TokenUsage)
		requestCost := make(map[Model]float64)
		for _, event := range codexEvents[key] {
			model := Model(event.Model)
			session := byModel[model]
			if session == nil {
				session = &SessionCost{Source: SourceCodex, SessionID: sessionID, Agent: AgentCodex, Model: model, Project: state.project, StartedAt: state.startedAt, PricingMode: PricingModeBaseEstimate}
				byModel[model] = session
			}
			addSessionUsage(session, event.Usage, event.Reasoning)
			if event.HasRequestUsage {
				usage := analyticsUsage(event.RequestUsage)
				current := pricedUsage[model]
				addTokenUsage(&current, usage)
				pricedUsage[model] = current
				requestCost[model] += ComputeRequestCost(model, usage)
			}
		}
		for model, session := range byModel {
			usage := TokenUsage{Input: session.InputTokens, Output: session.OutputTokens, CacheRead: session.CacheRead, CacheWrite: session.CacheWrite}
			session.CostUSD = ComputeBaseCost(model, usage)
			if tokenUsageEqual(pricedUsage[model], usage) {
				session.PricingMode = PricingModeRequestAware
				session.CostUSD = requestCost[model]
			}
			sessions = append(sessions, *session)
		}
	}
	return sessions, errs
}

func addSessionUsage(session *SessionCost, usage costindex.TokenUsage, reasoning int64) {
	session.InputTokens += usage.Input
	session.OutputTokens += usage.Output
	session.CacheRead += usage.CacheRead
	session.CacheWrite += usage.CacheWrite
	session.CacheWrite5m += usage.CacheWrite5m
	session.CacheWrite1h += usage.CacheWrite1h
	session.Reasoning += reasoning
}

func addTokenUsage(total *TokenUsage, usage TokenUsage) {
	total.Input += usage.Input
	total.Output += usage.Output
	total.CacheRead += usage.CacheRead
	total.CacheWrite += usage.CacheWrite
	total.CacheWrite5m += usage.CacheWrite5m
	total.CacheWrite1h += usage.CacheWrite1h
}

func tokenUsageEqual(left, right TokenUsage) bool {
	return left == right
}

func dailyUsage(session SessionCost) costindex.DailyUsage {
	started := session.StartedAt.UTC()
	return costindex.DailyUsage{
		Source: costindex.Source(session.Source), Path: "@projection", Generation: "v1",
		Day: costindex.Day(started.Format("2006-01-02")), StartedAt: started,
		SessionID: costindex.SessionID(session.SessionID), Agent: costindex.Agent(session.Agent),
		Model: costindex.Model(session.Model), Project: costindex.Project(session.Project),
		Usage:     costindex.TokenUsage{Input: session.InputTokens, Output: session.OutputTokens, CacheRead: session.CacheRead, CacheWrite: session.CacheWrite, CacheWrite5m: session.CacheWrite5m, CacheWrite1h: session.CacheWrite1h},
		Reasoning: session.Reasoning, PricingMode: costindex.PricingMode(session.PricingMode),
		PricingRevision: costPricingVersion, CostUSD: session.CostUSD, EventCount: 1,
	}
}

// ReadIndexedSessions reads the report projection without touching provider
// transcripts. The returned status lets callers expose freshness explicitly.
func ReadIndexedSessions(ctx context.Context, reader costindex.Reader, since time.Time) ([]SessionCost, costindex.Status, error) {
	status, err := reader.CostIndexStatus(ctx)
	if err != nil {
		return nil, costindex.Status{}, err
	}
	rows, err := reader.ListCostDailyUsage(ctx, costindex.Window{Since: since})
	if err != nil {
		return nil, status, err
	}
	sessions := make([]SessionCost, 0, len(rows))
	for _, row := range rows {
		sessions = append(sessions, SessionCost{
			Source: Source(row.Source), SessionID: SessionID(row.SessionID), Agent: Agent(row.Agent), Model: Model(row.Model), Project: Project(row.Project),
			CostUSD: row.CostUSD, InputTokens: row.Usage.Input, OutputTokens: row.Usage.Output, CacheRead: row.Usage.CacheRead,
			CacheWrite: row.Usage.CacheWrite, CacheWrite5m: row.Usage.CacheWrite5m, CacheWrite1h: row.Usage.CacheWrite1h,
			Reasoning: row.Reasoning, PricingMode: PricingMode(row.PricingMode), StartedAt: row.StartedAt,
		})
	}
	return sessions, status, nil
}
