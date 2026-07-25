package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestDecisionPersistsCanonicalAndAdapterActions(t *testing.T) {
	st, _ := newTestStore(t)
	err := st.RecordDecision(context.Background(), DecisionRecord{
		Ts:                time.Now(),
		SessionID:         "codex-ask",
		Agent:             "codex",
		ToolName:          "Bash",
		Action:            "ask",
		Reason:            "git push requires review",
		PolicyAction:      "ask",
		EffectiveAction:   "deny",
		Adapter:           "codex",
		TranslationReason: "Codex PreToolUse cannot render an interactive ask; fail closed",
		FinalAction:       "blocked",
		Enforcer:          "policy",
	})
	if err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}
	rows, err := st.ListDecisions(context.Background(), Filter{SessionID: "codex-ask"})
	if err != nil {
		t.Fatalf("ListDecisions: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	got := rows[0]
	if got.PolicyAction != "ask" || got.EffectiveAction != "deny" || got.Adapter != "codex" {
		t.Fatalf("stored translation = policy=%q effective=%q adapter=%q", got.PolicyAction, got.EffectiveAction, got.Adapter)
	}
	if got.Reason != "git push requires review" || got.TranslationReason == "" {
		t.Fatalf("reasons = policy=%q translation=%q", got.Reason, got.TranslationReason)
	}
	if got.FinalAction != "blocked" || got.Enforcer != "policy" {
		t.Fatalf("final attribution = %q/%q, want blocked/policy", got.FinalAction, got.Enforcer)
	}
}

func TestMigrationAddsAgentDecisionMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	if _, err := raw.Exec(`CREATE TABLE decisions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ts TEXT NOT NULL, session_id TEXT NOT NULL, agent TEXT, tool_name TEXT NOT NULL,
		summary TEXT, action TEXT NOT NULL, rule_id TEXT, reason TEXT, impact TEXT,
		elapsed_us INTEGER, cwd TEXT, tool_input_redacted TEXT, would_action TEXT NOT NULL DEFAULT '',
		tool_use_id TEXT NOT NULL DEFAULT '', final_action TEXT NOT NULL DEFAULT '', enforcer TEXT NOT NULL DEFAULT ''
	)`); err != nil {
		t.Fatalf("create legacy decisions: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close legacy db: %v", err)
	}
	st, err := Open(path)
	if err != nil {
		t.Fatalf("migrate legacy db: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	concrete := st.(*sqliteStore)
	for _, col := range []string{"policy_action", "effective_action", "adapter", "translation_reason"} {
		if !columnExists(concrete.db, "decisions", col) {
			t.Errorf("migration did not add decisions.%s", col)
		}
	}
}
