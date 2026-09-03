package costanalytics

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// CodexReader reads Codex session usage without decoding conversation content.
type CodexReader struct {
	sessionsDir string
}

type codexEnvelope struct {
	Type      string          `json:"type"`
	Timestamp string          `json:"timestamp"`
	Payload   json.RawMessage `json:"payload"`
}

type codexSessionMeta struct {
	ID           string `json:"id"`
	SessionID    string `json:"session_id"`
	ForkedFromID string `json:"forked_from_id"`
	CWD          string `json:"cwd"`
}

type codexTurnContext struct {
	Model string `json:"model"`
}

type codexEvent struct {
	Type string `json:"type"`
	Info *struct {
		TotalTokenUsage *codexTokenUsage `json:"total_token_usage"`
		LastTokenUsage  *codexTokenUsage `json:"last_token_usage"`
	} `json:"info"`
}

type CodexTokenUsage struct {
	InputTokens       int64 `json:"input_tokens"`
	CachedInputTokens int64 `json:"cached_input_tokens"`
	CacheWriteTokens  int64 `json:"cache_write_input_tokens"`
	OutputTokens      int64 `json:"output_tokens"`
	ReasoningOutput   int64 `json:"reasoning_output_tokens"`
	TotalTokens       int64 `json:"total_tokens"`
}

type codexTokenUsage = CodexTokenUsage

// CodexParserState is the resumable, content-free state of one Codex JSONL
// transcript. It retains the cumulative baseline needed to price only a suffix.
type CodexParserState struct {
	SessionID       SessionID       `json:"session_id"`
	Model           Model           `json:"model"`
	Project         Project         `json:"project"`
	StartedAt       time.Time       `json:"started_at"`
	Usage           CodexTokenUsage `json:"usage"`
	MaxTotal        int64           `json:"max_total"`
	ForkedFrom      SessionID       `json:"forked_from,omitempty"`
	CanSplit        bool            `json:"can_split"`
	SeenTimestamp   bool            `json:"seen_timestamp,omitempty"`
	SeenSessionMeta bool            `json:"seen_session_meta,omitempty"`
}

// CodexUsageEvent is one cumulative usage advance attributed to the model that
// was active at that record. Cumulative is also its fork-deduplication identity.
type CodexUsageEvent struct {
	TranscriptUsage
	Cumulative CodexTokenUsage  `json:"cumulative"`
	Delta      CodexTokenUsage  `json:"delta"`
	Last       *CodexTokenUsage `json:"last,omitempty"`
}

func NewCodexParserState(sessionID SessionID, fallbackStart time.Time) CodexParserState {
	return CodexParserState{SessionID: sessionID, StartedAt: fallbackStart, CanSplit: true}
}

// ApplyCodexRecord updates state and returns a new cumulative usage event, if
// any. Malformed, unknown, duplicate, and non-usage records are ignored.
func ApplyCodexRecord(state *CodexParserState, encoded []byte) (CodexUsageEvent, bool) {
	if state == nil {
		return CodexUsageEvent{}, false
	}
	var envelope codexEnvelope
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		return CodexUsageEvent{}, false
	}
	timestamp, timestampErr := time.Parse(time.RFC3339Nano, envelope.Timestamp)
	if !state.SeenSessionMeta && timestampErr == nil && (!state.SeenTimestamp || timestamp.Before(state.StartedAt)) {
		state.StartedAt = timestamp
		state.SeenTimestamp = true
	}

	switch envelope.Type {
	case "session_meta":
		var meta codexSessionMeta
		if state.SeenSessionMeta || json.Unmarshal(envelope.Payload, &meta) != nil {
			return CodexUsageEvent{}, false
		}
		state.SeenSessionMeta = true
		if timestampErr == nil {
			state.StartedAt = timestamp
			state.SeenTimestamp = true
		}
		if meta.ID != "" {
			state.SessionID = SessionID(meta.ID)
		} else if meta.SessionID != "" {
			state.SessionID = SessionID(meta.SessionID)
		}
		if meta.CWD != "" {
			state.Project = Project(meta.CWD)
		}
		state.ForkedFrom = SessionID(meta.ForkedFromID)
	case "turn_context":
		var turn codexTurnContext
		if json.Unmarshal(envelope.Payload, &turn) == nil && turn.Model != "" {
			state.Model = Model(turn.Model)
		}
	case "event_msg":
		var event codexEvent
		if json.Unmarshal(envelope.Payload, &event) != nil || event.Type != "token_count" || event.Info == nil || event.Info.TotalTokenUsage == nil {
			return CodexUsageEvent{}, false
		}
		usage := *event.Info.TotalTokenUsage
		total := usage.InputTokens + usage.OutputTokens
		var decoded CodexUsageEvent
		produced := false
		if total > state.MaxTotal {
			if state.Model == "" || !codexUsageAtLeast(usage, state.Usage) {
				state.CanSplit = false
			} else {
				var last *CodexTokenUsage
				if event.Info.LastTokenUsage != nil {
					copy := *event.Info.LastTokenUsage
					last = &copy
				}
				occurredAt := state.StartedAt
				if timestampErr == nil {
					occurredAt = timestamp
				}
				delta := subtractCodexUsage(usage, state.Usage)
				decoded = CodexUsageEvent{
					TranscriptUsage: TranscriptUsage{
						Source: SourceCodex, SessionID: state.SessionID, Model: state.Model,
						Project: state.Project, OccurredAt: occurredAt,
						Usage: codexUsageForPricing(delta), Reasoning: delta.ReasoningOutput,
					},
					Cumulative: usage,
					Delta:      delta,
					Last:       last,
				}
				produced = true
			}
		}
		if total >= state.MaxTotal {
			state.Usage = usage
			state.MaxTotal = total
		}
		return decoded, produced
	}
	return CodexUsageEvent{}, false
}

type codexSessionUsage struct {
	sessionID  string
	model      string
	project    string
	startedAt  time.Time
	usage      codexTokenUsage
	maxTotal   int64
	byModel    map[string]*codexModelUsage
	events     map[codexUsageKey]codexUsageEvent
	forkedFrom string
	canSplit   bool
}

type codexModelUsage struct {
	usage       codexTokenUsage
	pricedUsage codexTokenUsage
	requestCost float64
}

type codexUsageKey struct {
	input      int64
	cacheRead  int64
	cacheWrite int64
	output     int64
}

type codexUsageEvent struct {
	model string
	delta codexTokenUsage
	last  *codexTokenUsage
}

// NewCodexReader discovers transcripts in Codex's default per-user data path.
func NewCodexReader() *CodexReader {
	home, err := os.UserHomeDir()
	if err != nil {
		return &CodexReader{}
	}
	return NewCodexReaderAt(filepath.Join(home, ".codex", "sessions"))
}

// NewCodexReaderAt creates a reader for an injected transcript root.
func NewCodexReaderAt(sessionsDir string) *CodexReader {
	return &CodexReader{sessionsDir: sessionsDir}
}

func (c *CodexReader) ReadSessions(since time.Time) ([]SessionCost, error) {
	if c.sessionsDir == "" {
		return nil, nil
	}
	if _, err := os.Stat(c.sessionsDir); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("stat Codex sessions: %w", err)
	}

	bySession := make(map[string]*codexSessionUsage)
	var readErrs []error
	transcriptFiles := 0
	err := filepath.WalkDir(c.sessionsDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			readErrs = append(readErrs, fmt.Errorf("read Codex sessions %s: %w", path, walkErr))
			if entry != nil && entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(path), ".jsonl") {
			return nil
		}
		if transcriptFiles >= maxTranscriptFiles {
			return errTranscriptFileLimit
		}
		transcriptFiles++

		parsed, err := parseCodexSession(path)
		if err != nil {
			readErrs = append(readErrs, err)
			return nil
		}
		if parsed.maxTotal == 0 {
			return nil
		}
		mergeCodexSession(bySession, parsed)
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if errors.Is(err, errTranscriptFileLimit) {
		readErrs = append(readErrs, fmt.Errorf("Codex transcript file limit of %d reached", maxTranscriptFiles))
	} else if err != nil {
		return nil, fmt.Errorf("walk Codex sessions: %w", err)
	}
	readErrs = append(readErrs, removeInheritedCodexEvents(bySession)...)

	sessions := make([]SessionCost, 0, len(bySession))
	for _, session := range bySession {
		if !since.IsZero() && session.startedAt.Before(since) {
			continue
		}
		sessions = append(sessions, codexSessionCosts(session)...)
	}
	sort.Slice(sessions, func(i, j int) bool {
		if sessions[i].StartedAt.Equal(sessions[j].StartedAt) {
			return sessions[i].SessionID < sessions[j].SessionID
		}
		return sessions[i].StartedAt.After(sessions[j].StartedAt)
	})
	return sessions, errors.Join(readErrs...)
}

func parseCodexSession(path string) (*codexSessionUsage, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open Codex transcript %s: %w", path, err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat Codex transcript %s: %w", path, err)
	}
	parser := NewCodexParserState(SessionID(strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))), info.ModTime())
	state := &codexSessionUsage{
		byModel:  make(map[string]*codexModelUsage),
		events:   make(map[codexUsageKey]codexUsageEvent),
		canSplit: true,
	}
	scanner := newTranscriptScanner(file)
	for scanner.Scan() {
		usage, ok := ApplyCodexRecord(&parser, scanner.Bytes())
		if ok {
			state.addUsageEvent(usage)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read Codex transcript %s: %w", path, err)
	}
	state.sessionID = string(parser.SessionID)
	state.model = string(parser.Model)
	state.project = string(parser.Project)
	state.startedAt = parser.StartedAt
	state.usage = parser.Usage
	state.maxTotal = parser.MaxTotal
	state.forkedFrom = string(parser.ForkedFrom)
	state.canSplit = parser.CanSplit
	return state, nil
}

func (session *codexSessionUsage) addUsageEvent(event CodexUsageEvent) {
	model := string(event.Model)
	modelUsage := session.byModel[model]
	if modelUsage == nil {
		modelUsage = &codexModelUsage{}
		session.byModel[model] = modelUsage
	}
	session.events[codexKey(event.Cumulative)] = codexUsageEvent{model: model, delta: event.Delta, last: event.Last}
	addCodexUsage(&modelUsage.usage, event.Delta)
	if event.Last != nil && HasPricing(event.Model) {
		modelUsage.requestCost += ComputeRequestCost(event.Model, codexUsageForPricing(*event.Last))
		addCodexUsage(&modelUsage.pricedUsage, *event.Last)
	}
}

func mergeCodexSession(sessions map[string]*codexSessionUsage, candidate *codexSessionUsage) {
	current, ok := sessions[candidate.sessionID]
	if !ok {
		sessions[candidate.sessionID] = candidate
		return
	}
	for key, event := range candidate.events {
		current.events[key] = event
	}
	current.canSplit = current.canSplit && candidate.canSplit
	if current.forkedFrom == "" {
		current.forkedFrom = candidate.forkedFrom
	}
	if candidate.startedAt.Before(current.startedAt) {
		current.startedAt = candidate.startedAt
	}
	if candidate.maxTotal >= current.maxTotal {
		current.usage = candidate.usage
		current.maxTotal = candidate.maxTotal
		if candidate.project != "" {
			current.project = candidate.project
		}
		if candidate.model != "" {
			current.model = candidate.model
		}
		return
	}
	if current.project == "" {
		current.project = candidate.project
	}
	if current.model == "" {
		current.model = candidate.model
	}
}

func removeInheritedCodexEvents(sessions map[string]*codexSessionUsage) []error {
	var errs []error
	for _, session := range sessions {
		if !session.canSplit {
			continue
		}
		if session.forkedFrom != "" {
			inherited := make(map[codexUsageKey]struct{})
			visited := map[string]struct{}{session.sessionID: {}}
			ancestorID := session.forkedFrom
			for ancestorID != "" {
				if _, seen := visited[ancestorID]; seen {
					errs = append(errs, fmt.Errorf("Codex fork lineage cycle for session %q; copied history may be included", session.sessionID))
					break
				}
				visited[ancestorID] = struct{}{}
				ancestor := sessions[ancestorID]
				if ancestor == nil {
					errs = append(errs, fmt.Errorf("Codex fork parent %q for session %q is unavailable; copied history may be included", ancestorID, session.sessionID))
					break
				}
				for key := range ancestor.events {
					inherited[key] = struct{}{}
				}
				ancestorID = ancestor.forkedFrom
			}
			for key := range inherited {
				delete(session.events, key)
			}
		}
		session.rebuildModelUsage()
	}
	return errs
}

func (session *codexSessionUsage) rebuildModelUsage() {
	session.byModel = make(map[string]*codexModelUsage)
	session.usage = codexTokenUsage{}
	for _, event := range session.events {
		modelUsage := session.byModel[event.model]
		if modelUsage == nil {
			modelUsage = &codexModelUsage{}
			session.byModel[event.model] = modelUsage
		}
		addCodexUsage(&session.usage, event.delta)
		addCodexUsage(&modelUsage.usage, event.delta)
		if event.last != nil && HasPricing(Model(event.model)) {
			modelUsage.requestCost += ComputeRequestCost(Model(event.model), codexUsageForPricing(*event.last))
			addCodexUsage(&modelUsage.pricedUsage, *event.last)
		}
	}
}

func codexSessionCosts(session *codexSessionUsage) []SessionCost {
	if session.canSplit && len(session.events) == 0 {
		return nil
	}
	if session.canSplit && len(session.byModel) != 0 && codexModelsReconcile(session.byModel, session.usage) {
		models := make([]string, 0, len(session.byModel))
		for model := range session.byModel {
			models = append(models, model)
		}
		sort.Strings(models)
		costs := make([]SessionCost, 0, len(models))
		for _, model := range models {
			usage := session.byModel[model]
			costs = append(costs, newCodexSessionCost(session, model, usage.usage, usage.pricedUsage, usage.requestCost))
		}
		return costs
	}
	return []SessionCost{newCodexSessionCost(session, session.model, session.usage, codexTokenUsage{}, 0)}
}

func newCodexSessionCost(session *codexSessionUsage, model string, usage, pricedUsage codexTokenUsage, requestCost float64) SessionCost {
	pricingMode := PricingModeBaseEstimate
	cost := ComputeBaseCost(Model(model), codexUsageForPricing(usage))
	if codexUsageEqual(pricedUsage, usage) {
		pricingMode = PricingModeRequestAware
		cost = requestCost
	}
	priced := codexUsageForPricing(usage)
	return SessionCost{
		Source:       SourceCodex,
		SessionID:    SessionID(session.sessionID),
		Agent:        AgentCodex,
		Model:        Model(model),
		Project:      Project(session.project),
		CostUSD:      cost,
		InputTokens:  priced.Input,
		OutputTokens: usage.OutputTokens,
		CacheRead:    usage.CachedInputTokens,
		CacheWrite:   usage.CacheWriteTokens,
		Reasoning:    usage.ReasoningOutput,
		PricingMode:  pricingMode,
		StartedAt:    session.startedAt,
	}
}

func codexUsageForPricing(usage codexTokenUsage) TokenUsage {
	input := usage.InputTokens - usage.CachedInputTokens - usage.CacheWriteTokens
	if input < 0 {
		input = 0
	}
	return TokenUsage{
		Input: input, Output: usage.OutputTokens, CacheRead: usage.CachedInputTokens, CacheWrite: usage.CacheWriteTokens,
	}
}

func addCodexUsage(total *codexTokenUsage, usage codexTokenUsage) {
	total.InputTokens += usage.InputTokens
	total.CachedInputTokens += usage.CachedInputTokens
	total.CacheWriteTokens += usage.CacheWriteTokens
	total.OutputTokens += usage.OutputTokens
	total.ReasoningOutput += usage.ReasoningOutput
	total.TotalTokens += usage.TotalTokens
}

func subtractCodexUsage(current, previous codexTokenUsage) codexTokenUsage {
	return codexTokenUsage{
		InputTokens:       current.InputTokens - previous.InputTokens,
		CachedInputTokens: current.CachedInputTokens - previous.CachedInputTokens,
		CacheWriteTokens:  current.CacheWriteTokens - previous.CacheWriteTokens,
		OutputTokens:      current.OutputTokens - previous.OutputTokens,
		ReasoningOutput:   current.ReasoningOutput - previous.ReasoningOutput,
		TotalTokens:       current.TotalTokens - previous.TotalTokens,
	}
}

func codexKey(usage codexTokenUsage) codexUsageKey {
	return codexUsageKey{
		input:      usage.InputTokens,
		cacheRead:  usage.CachedInputTokens,
		cacheWrite: usage.CacheWriteTokens,
		output:     usage.OutputTokens,
	}
}

func codexUsageAtLeast(current, previous codexTokenUsage) bool {
	return current.InputTokens >= previous.InputTokens &&
		current.CachedInputTokens >= previous.CachedInputTokens &&
		current.CacheWriteTokens >= previous.CacheWriteTokens &&
		current.OutputTokens >= previous.OutputTokens &&
		current.ReasoningOutput >= previous.ReasoningOutput
}

func codexModelsReconcile(models map[string]*codexModelUsage, total codexTokenUsage) bool {
	var summed codexTokenUsage
	for _, model := range models {
		addCodexUsage(&summed, model.usage)
	}
	return codexUsageEqual(summed, total)
}

func codexUsageEqual(a, b codexTokenUsage) bool {
	return a.InputTokens == b.InputTokens &&
		a.CachedInputTokens == b.CachedInputTokens &&
		a.CacheWriteTokens == b.CacheWriteTokens &&
		a.OutputTokens == b.OutputTokens
}

func (c *CodexReader) Close() error {
	return nil
}
