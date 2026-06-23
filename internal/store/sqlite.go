package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var dsnPathReplacer = strings.NewReplacer("%", "%25", "?", "%3F", "#", "%23")

const (
	defaultLimit = 100
	maxLimit     = 10000
)

func clampLimit(n int) int {
	if n <= 0 {
		return defaultLimit
	}
	if n > maxLimit {
		return maxLimit
	}
	return n
}

// sqliteStore is the SQLite-backed EventStore.
type sqliteStore struct {
	db   *sql.DB
	path string
}

// Open opens (or creates) the SQLite store at path. The directory is created
// with 0700; the DB file is chmod 0600. WAL mode + synchronous=NORMAL +
// busy_timeout=5000 are set via DSN pragmas so a kill mid-write leaves the DB
// consistent (the WAL replays on next open). SetMaxOpenConns(1) serializes
// writes — SQLite is a single-writer database.
func Open(path string) (EventStore, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: mkdir %s: %w", dir, err)
	}
	dsn := fmt.Sprintf(
		"file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)",
		dsnPathReplacer.Replace(path),
	)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	s := &sqliteStore{db: db, path: path}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := chmodDBFiles(path, 0o600); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: chmod: %w", err)
	}
	return s, nil
}

// chmodDBFiles chmods the DB and its WAL/SHM sidecars to mode (best-effort
// on sidecars; they may not exist yet). The 0700 parent dir is the primary
// protection; this is defense-in-depth + meets the 0600 acceptance.
func chmodDBFiles(path string, mode os.FileMode) error {
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(path + suffix); err == nil {
			_ = os.Chmod(path+suffix, mode)
		}
	}
	return nil
}

// orderDir returns the SQL order direction for the filter.
func orderDir(desc bool) string {
	if desc {
		return "DESC"
	}
	return "ASC"
}

// migrate creates the schema idempotently.
func (s *sqliteStore) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS decisions (
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			ts              TEXT    NOT NULL,
			session_id      TEXT    NOT NULL,
			agent           TEXT,
			tool_name       TEXT    NOT NULL,
			summary         TEXT,
			action          TEXT    NOT NULL,
			rule_id         TEXT,
			reason          TEXT,
			impact          TEXT,
			elapsed_us      INTEGER,
			cwd             TEXT,
			tool_input_redacted TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_decisions_session_ts ON decisions(session_id, ts)`,
		`CREATE INDEX IF NOT EXISTS idx_decisions_ts ON decisions(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_decisions_action ON decisions(action)`,
		`CREATE INDEX IF NOT EXISTS idx_decisions_tool_name ON decisions(tool_name)`,
		`CREATE INDEX IF NOT EXISTS idx_decisions_rule_id ON decisions(rule_id)`,
		`CREATE TABLE IF NOT EXISTS audit_events (
			id      INTEGER PRIMARY KEY AUTOINCREMENT,
			ts      TEXT    NOT NULL,
			action  TEXT    NOT NULL,
			rule_id TEXT,
			user    TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			session_id      TEXT PRIMARY KEY,
			start_ts        TEXT    NOT NULL,
			end_ts          TEXT,
			agent           TEXT,
			cwd             TEXT,
			decision_count  INTEGER NOT NULL DEFAULT 0
		)`,
	}
	for _, st := range stmts {
		if _, err := s.db.Exec(st); err != nil {
			return fmt.Errorf("store: migrate: %w", err)
		}
	}
	return nil
}

// RecordDecision inserts a decision and upserts its session. The tool_input
// is redacted before persisting (ADR 0019).
func (s *sqliteStore) RecordDecision(ctx context.Context, d DecisionRecord) error {
	ts := d.Ts.UTC().Format(time.RFC3339Nano)
	redacted := RedactToolInput(d.ToolInput)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO decisions
		(ts, session_id, agent, tool_name, summary, action, rule_id, reason, impact, elapsed_us, cwd, tool_input_redacted)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		ts, d.SessionID, d.Agent, d.ToolName, d.Summary, d.Action, d.RuleID, d.Reason, d.Impact, d.ElapsedUs, d.CWD, redacted,
	); err != nil {
		return fmt.Errorf("store: insert decision: %w", err)
	}
	if d.SessionID != "" {
		if _, err := tx.ExecContext(ctx, `INSERT INTO sessions (session_id, start_ts, end_ts, agent, cwd, decision_count)
			VALUES (?, ?, ?, ?, ?, 1)
			ON CONFLICT(session_id) DO UPDATE SET
				end_ts = excluded.end_ts,
				agent = COALESCE(excluded.agent, sessions.agent),
				cwd = COALESCE(excluded.cwd, sessions.cwd),
				decision_count = sessions.decision_count + 1`,
			d.SessionID, ts, ts, d.Agent, d.CWD,
		); err != nil {
			return fmt.Errorf("store: upsert session: %w", err)
		}
	}
	return tx.Commit()
}

// RecordAuditEvent inserts an audit event (replaces audit.log).
func (s *sqliteStore) RecordAuditEvent(ctx context.Context, a AuditRecord) error {
	ts := a.Ts.UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_events (ts, action, rule_id, user) VALUES (?, ?, ?, ?)`,
		ts, a.Action, a.RuleID, a.User)
	if err != nil {
		return fmt.Errorf("store: insert audit: %w", err)
	}
	return nil
}

// DecisionCount returns the total number of decision rows (used by the daemon
// to decide whether to migrate an existing daemon.log on first run).
func (s *sqliteStore) DecisionCount(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM decisions`).Scan(&n)
	return n, err
}

// ListDecisions returns decisions matching f, oldest-first (chronological).
func (s *sqliteStore) ListDecisions(ctx context.Context, f Filter) ([]DecisionRecord, error) {
	var (
		conds []string
		args  []interface{}
	)
	if f.SessionID != "" {
		conds = append(conds, "INSTR(session_id, ?) > 0")
		args = append(args, f.SessionID)
	}
	if f.Since > 0 {
		conds = append(conds, "ts > ?")
		args = append(args, time.Now().Add(-f.Since).UTC().Format(time.RFC3339Nano))
	}
	if f.Tool != "" {
		conds = append(conds, "tool_name = ?")
		args = append(args, f.Tool)
	}
	if len(f.Actions) > 0 {
		placeholders := make([]string, len(f.Actions))
		for i, a := range f.Actions {
			placeholders[i] = "?"
			args = append(args, strings.ToLower(a))
		}
		conds = append(conds, "lower(action) IN ("+strings.Join(placeholders, ",")+")")
	}
	if f.Rule != "" {
		conds = append(conds, "INSTR(lower(rule_id), ?) > 0")
		args = append(args, strings.ToLower(f.Rule))
	}
	if f.AfterID > 0 {
		if f.OrderDesc {
			conds = append(conds, "id < ?")
		} else {
			conds = append(conds, "id > ?")
		}
		args = append(args, f.AfterID)
	}
	q := "SELECT id, ts, session_id, agent, tool_name, summary, action, rule_id, reason, impact, elapsed_us, cwd, tool_input_redacted FROM decisions"
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " ORDER BY id " + orderDir(f.OrderDesc)
	q += fmt.Sprintf(" LIMIT %d", clampLimit(f.Limit))
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list decisions: %w", err)
	}
	defer rows.Close()
	var out []DecisionRecord
	for rows.Next() {
		var (
			id        int64
			tsStr     string
			sid       string
			agent     sql.NullString
			toolName  string
			summary   sql.NullString
			action    string
			ruleID    sql.NullString
			reason    sql.NullString
			impact    sql.NullString
			elapsed   sql.NullInt64
			cwd       sql.NullString
			toolInput sql.NullString
		)
		if err := rows.Scan(&id, &tsStr, &sid, &agent, &toolName, &summary, &action, &ruleID, &reason, &impact, &elapsed, &cwd, &toolInput); err != nil {
			return nil, fmt.Errorf("store: scan decision: %w", err)
		}
		ts, _ := time.Parse(time.RFC3339Nano, tsStr)
		out = append(out, DecisionRecord{
			ID:                id,
			Ts:                ts,
			SessionID:         sid,
			Agent:             agent.String,
			ToolName:          toolName,
			Summary:           summary.String,
			Action:            action,
			RuleID:            ruleID.String,
			Reason:            reason.String,
			Impact:            impact.String,
			ElapsedUs:         elapsed.Int64,
			CWD:               cwd.String,
			ToolInputRedacted: toolInput.String,
		})
	}
	return out, rows.Err()
}

// ListAuditEvents returns audit events in chronological order by default.
func (s *sqliteStore) ListAuditEvents(ctx context.Context, f AuditFilter) ([]AuditRecord, error) {
	q := "SELECT id, ts, action, rule_id, user FROM audit_events ORDER BY id " + orderDir(f.OrderDesc)
	q += fmt.Sprintf(" LIMIT %d", clampLimit(f.Limit))
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("store: list audit events: %w", err)
	}
	defer rows.Close()

	var out []AuditRecord
	for rows.Next() {
		var (
			id     int64
			tsStr  string
			action string
			ruleID sql.NullString
			user   sql.NullString
		)
		if err := rows.Scan(&id, &tsStr, &action, &ruleID, &user); err != nil {
			return nil, fmt.Errorf("store: scan audit event: %w", err)
		}
		ts, _ := time.Parse(time.RFC3339Nano, tsStr)
		out = append(out, AuditRecord{
			ID:     id,
			Ts:     ts,
			Action: action,
			RuleID: ruleID.String,
			User:   user.String,
		})
	}
	return out, rows.Err()
}

// ListSessions returns sessions newest-first by start_ts.
func (s *sqliteStore) ListSessions(ctx context.Context) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT session_id, start_ts, end_ts, agent, cwd, decision_count FROM sessions ORDER BY start_ts DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: list sessions: %w", err)
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var (
			sid      string
			startStr string
			endStr   sql.NullString
			agent    sql.NullString
			cwd      sql.NullString
			count    int64
		)
		if err := rows.Scan(&sid, &startStr, &endStr, &agent, &cwd, &count); err != nil {
			return nil, fmt.Errorf("store: scan session: %w", err)
		}
		start, _ := time.Parse(time.RFC3339Nano, startStr)
		var end time.Time
		if endStr.Valid {
			end, _ = time.Parse(time.RFC3339Nano, endStr.String)
		}
		out = append(out, Session{
			SessionID:     sid,
			StartTs:       start,
			EndTs:         end,
			Agent:         agent.String,
			CWD:           cwd.String,
			DecisionCount: int(count),
		})
	}
	return out, rows.Err()
}

func (s *sqliteStore) CountActionsBySession(ctx context.Context) ([]ActionCount, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT session_id, action, COUNT(*) FROM decisions GROUP BY session_id, action`)
	if err != nil {
		return nil, fmt.Errorf("store: count actions: %w", err)
	}
	defer rows.Close()
	var out []ActionCount
	for rows.Next() {
		var ac ActionCount
		if err := rows.Scan(&ac.SessionID, &ac.Action, &ac.Count); err != nil {
			return nil, fmt.Errorf("store: scan action count: %w", err)
		}
		out = append(out, ac)
	}
	return out, rows.Err()
}

// Cleanup deletes decisions and audit_events older than maxAge, removes
// sessions whose start_ts is older than maxAge, and VACUUMs to reclaim space.
func (s *sqliteStore) Cleanup(ctx context.Context, maxAge time.Duration) error {
	cutoff := time.Now().Add(-maxAge).UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: cleanup begin: %w", err)
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM decisions WHERE ts < ?`,
		`DELETE FROM audit_events WHERE ts < ?`,
		`DELETE FROM sessions WHERE start_ts < ?`,
	} {
		if _, err := tx.ExecContext(ctx, q, cutoff); err != nil {
			return fmt.Errorf("store: cleanup delete: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: cleanup commit: %w", err)
	}
	// VACUUM cannot run inside a transaction.
	if _, err := s.db.ExecContext(ctx, `VACUUM`); err != nil {
		return fmt.Errorf("store: vacuum: %w", err)
	}
	return nil
}

// Close closes the database handle.
func (s *sqliteStore) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// sqliteROStore wraps sqliteStore but only exposes ReadOnlyStore methods.
type sqliteROStore struct {
	inner *sqliteStore
}

func (r *sqliteROStore) ListDecisions(ctx context.Context, f Filter) ([]DecisionRecord, error) {
	return r.inner.ListDecisions(ctx, f)
}
func (r *sqliteROStore) ListAuditEvents(ctx context.Context, f AuditFilter) ([]AuditRecord, error) {
	return r.inner.ListAuditEvents(ctx, f)
}
func (r *sqliteROStore) DecisionCount(ctx context.Context) (int64, error) {
	return r.inner.DecisionCount(ctx)
}
func (r *sqliteROStore) ListSessions(ctx context.Context) ([]Session, error) {
	return r.inner.ListSessions(ctx)
}
func (r *sqliteROStore) CountActionsBySession(ctx context.Context) ([]ActionCount, error) {
	return r.inner.CountActionsBySession(ctx)
}
func (r *sqliteROStore) Close() error { return r.inner.Close() }

// OpenReadOnly opens the SQLite store in read-only mode. The DB must already
// exist (created by the daemon via Open). No migration or chmod is attempted.
// Multiple readers can coexist with the daemon's single writer (WAL mode
// allows concurrent readers). Returns a ReadOnlyStore.
func OpenReadOnly(path string) (ReadOnlyStore, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("store: read-only open %s: %w", path, err)
	}
	dsn := fmt.Sprintf(
		"file:%s?mode=ro&_pragma=busy_timeout(5000)&_pragma=cache_size(-1000)&_pragma=mmap_size(0)",
		dsnPathReplacer.Replace(path),
	)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: read-only open: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: read-only ping: %w", err)
	}
	return &sqliteROStore{inner: &sqliteStore{db: db, path: path}}, nil
}
