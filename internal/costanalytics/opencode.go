package costanalytics

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type OpenCodeReader struct {
	db *sql.DB
}

type openCodeModelInfo struct {
	ID         string `json:"id"`
	ProviderID string `json:"providerID"`
	Variant    string `json:"variant"`
}

func DefaultOpenCodeDBPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "opencode", "opencode.db")
}

func NewOpenCodeReader(dbPath string) (*OpenCodeReader, error) {
	if _, err := os.Stat(dbPath); err != nil {
		return nil, fmt.Errorf("opencode db not found: %w", err)
	}
	db, err := sql.Open("sqlite", openCodeReadOnlyURI(dbPath))
	if err != nil {
		return nil, fmt.Errorf("open opencode db: %w", err)
	}
	return &OpenCodeReader{db: db}, nil
}

func openCodeReadOnlyURI(dbPath string) string {
	uri := &url.URL{Scheme: "file", Path: filepath.ToSlash(dbPath)}
	query := uri.Query()
	query.Set("mode", "ro")
	query.Add("_pragma", "query_only(1)")
	uri.RawQuery = query.Encode()
	return uri.String()
}

func (o *OpenCodeReader) ReadSessions(since time.Time) ([]SessionCost, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	sinceMs := since.UnixMilli()
	rows, err := o.db.QueryContext(ctx, `
		SELECT id, directory, model, cost,
		       tokens_input, tokens_output, tokens_reasoning,
		       tokens_cache_read, tokens_cache_write,
		       time_created
		FROM session
		WHERE time_created >= ?
		ORDER BY time_created DESC
		LIMIT ?`,
		sinceMs, maxSessionCosts+1)
	if err != nil {
		return nil, fmt.Errorf("query opencode sessions: %w", err)
	}
	defer rows.Close()

	var sessions []SessionCost
	for rows.Next() {
		if len(sessions) >= maxSessionCosts {
			return sessions, fmt.Errorf("OpenCode session limit of %d reached", maxSessionCosts)
		}
		var (
			id, dir        string
			modelJSON      sql.NullString
			cost           float64
			inp, out       int64
			reasoning      int64
			cacheR, cacheW int64
			createdMs      int64
		)
		if err := rows.Scan(&id, &dir, &modelJSON, &cost, &inp, &out, &reasoning, &cacheR, &cacheW, &createdMs); err != nil {
			return nil, fmt.Errorf("scan opencode session: %w", err)
		}

		model := ""
		if modelJSON.Valid && modelJSON.String != "" {
			var info openCodeModelInfo
			if err := json.Unmarshal([]byte(modelJSON.String), &info); err == nil {
				model = info.ID
			}
		}

		pricingMode := PricingModeRecorded
		if cost == 0 && (inp > 0 || out > 0 || cacheR > 0 || cacheW > 0) && model != "" {
			cost = ComputeCostFromTokens(Model(model), inp, out, cacheR, cacheW)
			pricingMode = PricingModeBaseEstimate
		}

		sessions = append(sessions, SessionCost{
			Source:       SourceOpenCode,
			SessionID:    SessionID(id),
			Agent:        AgentOpenCode,
			Model:        Model(model),
			Project:      Project(dir),
			CostUSD:      cost,
			InputTokens:  inp,
			OutputTokens: out,
			CacheRead:    cacheR,
			CacheWrite:   cacheW,
			Reasoning:    reasoning,
			PricingMode:  pricingMode,
			StartedAt:    time.UnixMilli(createdMs),
		})
	}
	return sessions, rows.Err()
}

func (o *OpenCodeReader) Close() error {
	return o.db.Close()
}
