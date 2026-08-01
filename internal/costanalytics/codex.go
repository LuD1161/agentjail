package costanalytics

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	ID        string `json:"id"`
	SessionID string `json:"session_id"`
	CWD       string `json:"cwd"`
}

type codexTurnContext struct {
	Model string `json:"model"`
}

type codexEvent struct {
	Type string `json:"type"`
	Info *struct {
		TotalTokenUsage *codexTokenUsage `json:"total_token_usage"`
	} `json:"info"`
}

type codexTokenUsage struct {
	InputTokens       int64 `json:"input_tokens"`
	CachedInputTokens int64 `json:"cached_input_tokens"`
	CacheWriteTokens  int64 `json:"cache_write_input_tokens"`
	OutputTokens      int64 `json:"output_tokens"`
	ReasoningOutput   int64 `json:"reasoning_output_tokens"`
	TotalTokens       int64 `json:"total_tokens"`
}

type codexSessionUsage struct {
	sessionID string
	model     string
	project   string
	startedAt time.Time
	usage     codexTokenUsage
	maxTotal  int64
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
	if err != nil {
		return nil, fmt.Errorf("walk Codex sessions: %w", err)
	}

	sessions := make([]SessionCost, 0, len(bySession))
	for _, session := range bySession {
		if !since.IsZero() && session.startedAt.Before(since) {
			continue
		}
		input := session.usage.InputTokens - session.usage.CachedInputTokens - session.usage.CacheWriteTokens
		if input < 0 {
			input = 0
		}
		sessions = append(sessions, SessionCost{
			Source:       SourceCodex,
			SessionID:    SessionID(session.sessionID),
			Agent:        AgentCodex,
			Model:        Model(session.model),
			Project:      Project(session.project),
			CostUSD:      ComputeCostFromTokens(Model(session.model), input, session.usage.OutputTokens, session.usage.CachedInputTokens, session.usage.CacheWriteTokens),
			InputTokens:  input,
			OutputTokens: session.usage.OutputTokens,
			CacheRead:    session.usage.CachedInputTokens,
			CacheWrite:   session.usage.CacheWriteTokens,
			Reasoning:    session.usage.ReasoningOutput,
			StartedAt:    session.startedAt,
		})
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
	state := &codexSessionUsage{
		sessionID: strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)),
		startedAt: info.ModTime(),
	}
	seenTimestamp := false
	reader := bufio.NewReader(file)
	for {
		encoded, readErr := reader.ReadBytes('\n')
		if len(encoded) > 0 {
			var envelope codexEnvelope
			if json.Unmarshal(encoded, &envelope) == nil {
				if timestamp, err := time.Parse(time.RFC3339Nano, envelope.Timestamp); err == nil && (!seenTimestamp || timestamp.Before(state.startedAt)) {
					state.startedAt = timestamp
					seenTimestamp = true
				}
				switch envelope.Type {
				case "session_meta":
					var meta codexSessionMeta
					if json.Unmarshal(envelope.Payload, &meta) == nil {
						if meta.ID != "" {
							state.sessionID = meta.ID
						} else if meta.SessionID != "" {
							state.sessionID = meta.SessionID
						}
						if meta.CWD != "" {
							state.project = meta.CWD
						}
					}
				case "turn_context":
					var context codexTurnContext
					if json.Unmarshal(envelope.Payload, &context) == nil && context.Model != "" {
						state.model = context.Model
					}
				case "event_msg":
					var event codexEvent
					if json.Unmarshal(envelope.Payload, &event) == nil && event.Type == "token_count" && event.Info != nil && event.Info.TotalTokenUsage != nil {
						usage := *event.Info.TotalTokenUsage
						total := usage.TotalTokens
						if total == 0 {
							total = usage.InputTokens + usage.OutputTokens
						}
						if total >= state.maxTotal {
							state.usage = usage
							state.maxTotal = total
						}
					}
				}
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return nil, fmt.Errorf("read Codex transcript %s: %w", path, readErr)
		}
	}
	return state, nil
}

func mergeCodexSession(sessions map[string]*codexSessionUsage, candidate *codexSessionUsage) {
	current, ok := sessions[candidate.sessionID]
	if !ok {
		sessions[candidate.sessionID] = candidate
		return
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

func (c *CodexReader) Close() error {
	return nil
}
