package costanalytics

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ClaudeCodeReader reads Claude Code session transcripts without retaining
// conversation content.
type ClaudeCodeReader struct {
	projectsDir string
}

// transcriptLine represents a single line in a Claude Code session JSONL file.
type transcriptLine struct {
	Type      string `json:"type"`
	CWD       string `json:"cwd"`
	Timestamp string `json:"timestamp"`
	Message   struct {
		Model string `json:"model"`
		Usage *struct {
			InputTokens              int64 `json:"input_tokens"`
			OutputTokens             int64 `json:"output_tokens"`
			CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
			CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
			CacheCreation            struct {
				Ephemeral5mInputTokens int64 `json:"ephemeral_5m_input_tokens"`
				Ephemeral1hInputTokens int64 `json:"ephemeral_1h_input_tokens"`
			} `json:"cache_creation"`
		} `json:"usage"`
	} `json:"message"`
}

// modelTokens aggregates token counts for a single model within a session.
type modelTokens struct {
	input        int64
	output       int64
	cacheRead    int64
	cacheWrite   int64
	cacheWrite5m int64
	cacheWrite1h int64
}

// ClaudeParserState is the resumable, content-free state of one Claude JSONL
// transcript. It is safe to persist between incremental reads.
type ClaudeParserState struct {
	SessionID     SessionID `json:"session_id"`
	Project       Project   `json:"project"`
	StartedAt     time.Time `json:"started_at"`
	SeenTimestamp bool      `json:"seen_timestamp,omitempty"`
}

func NewClaudeParserState(sessionID SessionID, project Project, fallbackStart time.Time) ClaudeParserState {
	return ClaudeParserState{SessionID: sessionID, Project: project, StartedAt: fallbackStart}
}

// ApplyClaudeRecord updates state and returns the usage fact, if any, from one
// decoded record. Malformed and non-usage records are intentionally ignored.
func ApplyClaudeRecord(state *ClaudeParserState, encoded []byte) (TranscriptUsage, bool) {
	if state == nil {
		return TranscriptUsage{}, false
	}
	var line transcriptLine
	if err := json.Unmarshal(encoded, &line); err != nil {
		return TranscriptUsage{}, false
	}
	if line.CWD != "" {
		state.Project = Project(line.CWD)
	}
	timestamp, timestampErr := time.Parse(time.RFC3339Nano, line.Timestamp)
	if timestampErr == nil && (!state.SeenTimestamp || timestamp.Before(state.StartedAt)) {
		state.StartedAt = timestamp
		state.SeenTimestamp = true
	}
	if line.Type != "assistant" || line.Message.Usage == nil {
		return TranscriptUsage{}, false
	}

	model := Model(line.Message.Model)
	if model == "" {
		model = "(unknown)"
	}
	cacheWrite5m := line.Message.Usage.CacheCreation.Ephemeral5mInputTokens
	cacheWrite1h := line.Message.Usage.CacheCreation.Ephemeral1hInputTokens
	cacheWrite := line.Message.Usage.CacheCreationInputTokens
	if classified := cacheWrite5m + cacheWrite1h; classified > cacheWrite {
		cacheWrite = classified
	}
	occurredAt := state.StartedAt
	if timestampErr == nil {
		occurredAt = timestamp
	}
	return TranscriptUsage{
		Source:     SourceClaudeCode,
		SessionID:  state.SessionID,
		Model:      model,
		Project:    state.Project,
		OccurredAt: occurredAt,
		Usage: TokenUsage{
			Input:        line.Message.Usage.InputTokens,
			Output:       line.Message.Usage.OutputTokens,
			CacheRead:    line.Message.Usage.CacheReadInputTokens,
			CacheWrite:   cacheWrite,
			CacheWrite5m: cacheWrite5m,
			CacheWrite1h: cacheWrite1h,
		},
	}, true
}

func NewClaudeCodeReader() *ClaudeCodeReader {
	home, _ := os.UserHomeDir()
	return &ClaudeCodeReader{projectsDir: filepath.Join(home, ".claude", "projects")}
}

func (c *ClaudeCodeReader) ReadSessions(since time.Time) ([]SessionCost, error) {
	pattern := filepath.Join(c.projectsDir, "*", "*.jsonl")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("glob claude sessions: %w", err)
	}

	var sessions []SessionCost
	var readErrs []error
	if len(matches) > maxTranscriptFiles {
		matches = matches[:maxTranscriptFiles]
		readErrs = append(readErrs, fmt.Errorf("Claude transcript file limit of %d reached", maxTranscriptFiles))
	}
	for _, path := range matches {
		// Skip plugin/internal directories (e.g. claude-mem observer sessions)
		dir := filepath.Base(filepath.Dir(path))
		if strings.Contains(dir, "claude-mem") || strings.Contains(dir, "observer") {
			continue
		}

		info, err := os.Stat(path)
		if err != nil {
			readErrs = append(readErrs, fmt.Errorf("stat Claude transcript %s: %w", path, err))
			continue
		}
		if info.ModTime().Before(since) {
			continue
		}

		sc, err := c.parseSessionFile(path)
		if err != nil {
			readErrs = append(readErrs, err)
			continue
		}
		sessions, err = appendSessionCosts(sessions, sc)
		if err != nil {
			readErrs = append(readErrs, err)
			break
		}
	}

	return sessions, errors.Join(readErrs...)
}

func (c *ClaudeCodeReader) parseSessionFile(path string) ([]SessionCost, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open Claude transcript %s: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat Claude transcript %s: %w", path, err)
	}
	state := NewClaudeParserState(
		SessionID(strings.TrimSuffix(filepath.Base(path), ".jsonl")),
		Project(extractProjectFromPath(path)),
		info.ModTime(),
	)

	// Aggregate tokens per model
	perModel := make(map[string]*modelTokens)

	scanner := newTranscriptScanner(f)
	for scanner.Scan() {
		usage, ok := ApplyClaudeRecord(&state, scanner.Bytes())
		if !ok {
			continue
		}
		model := string(usage.Model)
		mt, ok := perModel[model]
		if !ok {
			mt = &modelTokens{}
			perModel[model] = mt
		}
		mt.input += usage.Usage.Input
		mt.output += usage.Usage.Output
		mt.cacheRead += usage.Usage.CacheRead
		mt.cacheWrite += usage.Usage.CacheWrite
		mt.cacheWrite5m += usage.Usage.CacheWrite5m
		mt.cacheWrite1h += usage.Usage.CacheWrite1h
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read Claude transcript %s: %w", path, err)
	}

	if len(perModel) == 0 {
		return nil, nil
	}

	models := make([]string, 0, len(perModel))
	for model := range perModel {
		models = append(models, model)
	}
	sort.Strings(models)
	results := make([]SessionCost, 0, len(models))
	for _, model := range models {
		mt := perModel[model]
		pricingMode := PricingModeRequestAware
		if mt.cacheWrite > mt.cacheWrite5m+mt.cacheWrite1h {
			pricingMode = PricingModeTTLEstimate
		}
		cost := ComputeBaseCost(Model(model), TokenUsage{
			Input: mt.input, Output: mt.output, CacheRead: mt.cacheRead, CacheWrite: mt.cacheWrite,
			CacheWrite5m: mt.cacheWrite5m, CacheWrite1h: mt.cacheWrite1h,
		})
		results = append(results, SessionCost{
			Source:       SourceClaudeCode,
			SessionID:    state.SessionID,
			Agent:        AgentClaudeCode,
			Model:        Model(model),
			Project:      state.Project,
			CostUSD:      cost,
			InputTokens:  mt.input,
			OutputTokens: mt.output,
			CacheRead:    mt.cacheRead,
			CacheWrite:   mt.cacheWrite,
			CacheWrite5m: mt.cacheWrite5m,
			CacheWrite1h: mt.cacheWrite1h,
			PricingMode:  pricingMode,
			StartedAt:    state.StartedAt,
		})
	}

	return results, nil
}

// extractProjectFromPath is a fallback for transcript records without cwd.
func extractProjectFromPath(path string) string {
	dir := filepath.Dir(path)
	encoded := filepath.Base(dir)
	if encoded == "" || encoded == "." {
		return ""
	}

	parts := strings.Split(encoded, "-")
	if len(parts) < 2 {
		return encoded
	}

	candidate := ""
	for i := 1; i < len(parts); i++ {
		if candidate == "" {
			candidate = "/" + parts[i]
		} else {
			trySlash := candidate + "/" + parts[i]
			tryDash := candidate + "-" + parts[i]
			if _, err := os.Stat(trySlash); err == nil {
				candidate = trySlash
			} else if _, err := os.Stat(tryDash); err == nil {
				candidate = tryDash
			} else {
				candidate = trySlash
			}
		}
	}

	return candidate
}

func (c *ClaudeCodeReader) Close() error {
	return nil
}
