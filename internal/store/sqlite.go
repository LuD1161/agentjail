package store

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/sqliteutil"
	_ "modernc.org/sqlite"
)

const (
	defaultLimit = 100
	maxLimit     = 10000
)

// clampLimit clamps a query LIMIT to this store's [defaultLimit, maxLimit]
// range via the shared helper.
func clampLimit(n int) int { return sqliteutil.ClampLimit(n, defaultLimit, maxLimit) }

// sqliteStore is the SQLite-backed EventStore.
type sqliteStore struct {
	db      *sql.DB
	queries *Queries
	path    string
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
		"file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)&_pragma=secure_delete(ON)",
		sqliteutil.EscapeDSNPath(path),
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
	s := &sqliteStore{db: db, queries: New(db), path: path}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := sqliteutil.ChmodDBFiles(path, 0o600); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: chmod: %w", err)
	}
	return s, nil
}

func toNullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func toNullInt64(n int64) sql.NullInt64 {
	return sql.NullInt64{Int64: n, Valid: n != 0}
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
			tool_input_redacted TEXT,
			would_action    TEXT    NOT NULL DEFAULT '',
			policy_action      TEXT    NOT NULL DEFAULT '',
			effective_action   TEXT    NOT NULL DEFAULT '',
			adapter            TEXT    NOT NULL DEFAULT '',
			translation_reason TEXT    NOT NULL DEFAULT '',
			tool_use_id     TEXT    NOT NULL DEFAULT '',
			final_action    TEXT    NOT NULL DEFAULT '',
			enforcer        TEXT    NOT NULL DEFAULT ''
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
		`CREATE TABLE IF NOT EXISTS discovered_tools (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			server     TEXT    NOT NULL,
			tool       TEXT    NOT NULL,
			source     TEXT    NOT NULL,
			first_seen TEXT    NOT NULL,
			last_seen  TEXT    NOT NULL,
			UNIQUE(server, tool)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_discovered_tools_server ON discovered_tools(server)`,
		`CREATE TABLE IF NOT EXISTS mcp_discovery_status (
			server    TEXT PRIMARY KEY,
			status    TEXT NOT NULL CHECK(status IN ('connected', 'auth_required', 'unreachable', 'timeout')),
			last_seen TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS discovered_skills (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			name       TEXT    NOT NULL UNIQUE,
			source     TEXT    NOT NULL,
			first_seen TEXT    NOT NULL,
			last_seen  TEXT    NOT NULL,
			use_count  INTEGER NOT NULL DEFAULT 1
		)`,
		`CREATE INDEX IF NOT EXISTS idx_discovered_skills_name ON discovered_skills(name)`,
		`CREATE TABLE IF NOT EXISTS audit_log (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			ts         TEXT    NOT NULL,
			event_type TEXT    NOT NULL,
			entity     TEXT,
			detail     TEXT,
			actor      TEXT,
			session_id TEXT,
			ref_id     TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log(event_type)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_entity ON audit_log(entity)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_session ON audit_log(session_id)`,
	}
	for _, st := range stmts {
		if _, err := s.db.Exec(st); err != nil {
			return fmt.Errorf("store: migrate: %w", err)
		}
	}

	// CREATE TABLE IF NOT EXISTS above is a no-op on a database that predates a
	// column, so additive columns must be ALTERed in separately or every
	// existing install keeps the old shape. Idempotent: guarded on the column
	// not already being there.
	if tableExists(s.db, "decisions") && !columnExists(s.db, "decisions", "would_action") {
		if _, err := s.db.Exec(`ALTER TABLE decisions ADD COLUMN would_action TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("store: migrate: add decisions.would_action: %w", err)
		}
	}
	// Final-outcome columns (ADR 0112): additive, idempotent per column.
	if tableExists(s.db, "decisions") {
		for _, col := range []string{"policy_action", "effective_action", "adapter", "translation_reason", "tool_use_id", "final_action", "enforcer"} {
			if !columnExists(s.db, "decisions", col) {
				if _, err := s.db.Exec(fmt.Sprintf(`ALTER TABLE decisions ADD COLUMN %s TEXT NOT NULL DEFAULT ''`, col)); err != nil {
					return fmt.Errorf("store: migrate: add decisions.%s: %w", col, err)
				}
			}
		}
		s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_decisions_tool_use_id ON decisions(tool_use_id)`)
	}

	// Migrate legacy audit_events into audit_log (idempotent).
	if tableExists(s.db, "audit_events") {
		_, _ = s.db.Exec(`INSERT INTO audit_log (ts, event_type, entity, actor)
			SELECT ts, 'policy.changed', rule_id, user FROM audit_events
			WHERE NOT EXISTS (
				SELECT 1 FROM audit_log
				WHERE audit_log.ts = audit_events.ts
				AND audit_log.event_type = 'policy.changed'
				AND COALESCE(audit_log.entity, '') = COALESCE(audit_events.rule_id, '')
				AND COALESCE(audit_log.actor, '') = COALESCE(audit_events.user, '')
			)`)
		_, _ = s.db.Exec(`DROP TABLE IF EXISTS audit_events`)
	}

	// Import legacy flat-file audit.log (best-effort, idempotent).
	auditLogPath := filepath.Join(filepath.Dir(s.path), "audit.log")
	if f, err := os.Open(auditLogPath); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			var entry struct {
				Ts     string `json:"ts"`
				Action string `json:"action"`
				RuleID string `json:"rule_id"`
				User   string `json:"user"`
			}
			if json.Unmarshal(scanner.Bytes(), &entry) != nil || entry.Ts == "" {
				continue
			}
			// Deterministic ref_id for dedup.
			h := sha256.Sum256([]byte(entry.Ts + "|" + entry.Action + "|" + entry.RuleID + "|" + entry.User))
			refID := fmt.Sprintf("legacy:%x", h[:8])
			_, _ = s.db.Exec(`INSERT INTO audit_log (ts, event_type, entity, actor, ref_id)
				SELECT ?, 'policy.changed', ?, ?, ?
				WHERE NOT EXISTS (SELECT 1 FROM audit_log WHERE ref_id = ?)`,
				entry.Ts, entry.RuleID, entry.User, refID, refID)
		}
	}

	return nil
}

// CountWouldBlock returns the monitor-mode report rows since the given time:
// the rules that fired on calls that ran anyway. Rows with an empty
// would_action are enforce-mode decisions and are excluded by the query.
// See ADR 0091-monitor-mode-tools.
func (s *sqliteStore) CountWouldBlock(ctx context.Context, since time.Time) ([]WouldBlockCount, error) {
	rows, err := s.queries.CountWouldBlockByRule(ctx, since.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("store: count would-block: %w", err)
	}
	out := make([]WouldBlockCount, 0, len(rows))
	for _, r := range rows {
		out = append(out, WouldBlockCount{
			RuleID:      r.RuleID.String,
			WouldAction: r.WouldAction,
			ToolName:    r.ToolName,
			Count:       r.Count,
		})
	}
	return out, nil
}

// ComputeStats assembles the aggregate report for `agentjail stats` from a
// handful of GROUP BY queries plus a client-side percentile pass. since is the
// window start; a zero time means all-time. See AGE-213.
func (s *sqliteStore) ComputeStats(ctx context.Context, since time.Time) (StatsReport, error) {
	cutoff := since.UTC().Format(time.RFC3339Nano)
	rep := StatsReport{Since: since}

	actions, err := s.queries.CountByActionSince(ctx, cutoff)
	if err != nil {
		return rep, fmt.Errorf("store: stats actions: %w", err)
	}
	for _, a := range actions {
		rep.Total += a.Count
		switch a.Action {
		case "allow":
			rep.Allow = a.Count
		case "deny":
			rep.Deny = a.Count
		case "ask":
			rep.Ask = a.Count
		}
	}

	if rep.Sessions, err = s.queries.CountDistinctSessionsSince(ctx, cutoff); err != nil {
		return rep, fmt.Errorf("store: stats sessions: %w", err)
	}

	denyRules, err := s.queries.CountDenyRulesSince(ctx, cutoff)
	if err != nil {
		return rep, fmt.Errorf("store: stats deny rules: %w", err)
	}
	for _, r := range denyRules {
		rep.DenyRules = append(rep.DenyRules, LabeledCount{Label: nullOr(r.RuleID, "(none)"), Count: r.Count})
	}

	agents, err := s.queries.CountByAgentSince(ctx, cutoff)
	if err != nil {
		return rep, fmt.Errorf("store: stats agents: %w", err)
	}
	for _, a := range agents {
		rep.ByAgent = append(rep.ByAgent, LabeledCount{Label: nullOr(a.Agent, "(unknown)"), Count: a.Count})
	}

	surfaces, err := s.queries.CountAuditByTypeSince(ctx, cutoff)
	if err != nil {
		return rep, fmt.Errorf("store: stats surfaces: %w", err)
	}
	for _, sf := range surfaces {
		rep.BySurface = append(rep.BySurface, LabeledCount{Label: sf.EventType, Count: sf.Count})
	}

	elapsed, err := s.queries.ListElapsedMicrosSince(ctx, cutoff)
	if err != nil {
		return rep, fmt.Errorf("store: stats latency: %w", err)
	}
	rep.Latency = percentiles(elapsed) // ordered ASC by the query

	decDays, err := s.queries.DecisionDaysSince(ctx, cutoff)
	if err != nil {
		return rep, fmt.Errorf("store: stats decision days: %w", err)
	}
	rep.ActiveDays = len(decDays)
	decidedDays := make(map[string]struct{}, len(decDays))
	for i, d := range decDays {
		decidedDays[d.Day] = struct{}{}
		rep.Daily = append(rep.Daily, DailyCount{Day: d.Day, Count: d.Count})
		if i == 0 {
			rep.FirstDay = d.Day
		}
		rep.LastDay = d.Day
	}

	shieldDays, err := s.queries.ShieldDaysSince(ctx, cutoff)
	if err != nil {
		return rep, fmt.Errorf("store: stats shield days: %w", err)
	}
	for _, d := range shieldDays {
		if _, ok := decidedDays[d.Day]; !ok {
			// Shield activated that day but nothing was recorded -- the AGE-212
			// under-recording signal, surfaced so the failure self-reports.
			rep.CoverageGaps = append(rep.CoverageGaps, d.Day)
		}
	}

	return rep, nil
}

// percentiles computes p50/p90/p95/p99/max over an ASC-sorted slice of
// nullable microsecond values. NULLs are excluded by the query's WHERE, so
// every value is valid; an empty slice yields a zero LatencyStats.
func percentiles(sorted []sql.NullInt64) LatencyStats {
	n := len(sorted)
	if n == 0 {
		return LatencyStats{}
	}
	at := func(p float64) int64 {
		// Nearest-rank: index of the ceil(p*n)-th value, clamped to [0, n-1].
		idx := int(math.Ceil(p*float64(n))) - 1
		if idx < 0 {
			idx = 0
		}
		if idx >= n {
			idx = n - 1
		}
		return sorted[idx].Int64
	}
	return LatencyStats{
		Count: int64(n),
		P50:   at(0.50),
		P90:   at(0.90),
		P95:   at(0.95),
		P99:   at(0.99),
		Max:   sorted[n-1].Int64,
	}
}

// nullOr returns the string value of a NullString, or dflt when it is NULL or
// empty. Keeps report labels stable rather than blank.
func nullOr(s sql.NullString, dflt string) string {
	if s.Valid && s.String != "" {
		return s.String
	}
	return dflt
}

// tableExists reports whether a table with the given name exists in the DB.
func tableExists(db *sql.DB, name string) bool {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&n)
	return err == nil && n > 0
}

// columnExists reports whether table has the named column. pragma_table_info is
// used as a table-valued function so the name can be bound rather than
// interpolated.
func columnExists(db *sql.DB, table, column string) bool {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`, table, column).Scan(&n)
	return err == nil && n > 0
}

// RecordDecision inserts a decision and upserts its session. The tool_input
// is redacted before persisting (ADR 0019). On the first decision for a
// session (INSERT, not UPDATE), a session.started audit event is emitted
// best-effort.
func (s *sqliteStore) RecordDecision(ctx context.Context, d DecisionRecord) error {
	ts := d.Ts.UTC().Format(time.RFC3339Nano)
	// Keep missing attribution queryable at the store boundary. See AGE-213.
	if d.Agent == "" {
		d.Agent = AgentUnknown
	}
	redacted := RedactToolInput(d.ToolInput)
	summary := RedactText(d.Summary)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, `INSERT INTO decisions
		(ts, session_id, agent, tool_name, summary, action, rule_id, reason, impact, elapsed_us, cwd, tool_input_redacted, would_action, policy_action, effective_action, adapter, translation_reason, tool_use_id, final_action, enforcer)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		ts, d.SessionID, d.Agent, d.ToolName, summary, d.Action, d.RuleID, d.Reason, d.Impact, d.ElapsedUs, d.CWD, redacted, d.WouldAction, d.PolicyAction, d.EffectiveAction, d.Adapter, d.TranslationReason, d.ToolUseID, d.FinalAction, d.Enforcer,
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

		// Check if the upsert was an INSERT (new session).
		var changes int64
		_ = tx.QueryRowContext(ctx, `SELECT changes()`).Scan(&changes)
		if changes == 1 {
			// Could be insert or update — disambiguate by checking decision_count.
			var count int64
			_ = tx.QueryRowContext(ctx, `SELECT decision_count FROM sessions WHERE session_id = ?`, d.SessionID).Scan(&count)
			if count == 1 {
				// First decision for this session — emit session.started.
				txq := New(tx)
				if auditErr := txq.InsertAuditLog(ctx, InsertAuditLogParams{
					Ts:        ts,
					EventType: audit.SessionStarted,
					Entity:    toNullString(d.SessionID),
					SessionID: toNullString(d.SessionID),
					Detail:    toNullString(redactDetail(map[string]string{"agent": d.Agent, "cwd": d.CWD})),
				}); auditErr != nil {
					slog.Warn("audit emit failed for session started", "session", d.SessionID, "error", auditErr)
				}
			}
		}
	}
	return tx.Commit()
}

// RecordAuditEvent inserts an audit event into the unified audit_log.
// Legacy callers that passed Action/RuleID/User are mapped to the new schema.
func (s *sqliteStore) RecordAuditEvent(ctx context.Context, a AuditRecord) error {
	return s.Emit(ctx, audit.Event{
		EventType: audit.PolicyChanged,
		Entity:    a.RuleID,
		Actor:     a.User,
	})
}

// DecisionCount returns the total number of decision rows (used by the daemon
// to decide whether to migrate an existing daemon.log on first run).
func (s *sqliteStore) DecisionCount(ctx context.Context) (int64, error) {
	return s.queries.GetDecisionCount(ctx)
}

// ListDecisions returns decisions matching f in the requested ID order.
func (s *sqliteStore) ListDecisions(ctx context.Context, f Filter) ([]DecisionRecord, error) {
	var (
		conds []string
		args  []any
	)
	if f.DecisionID > 0 {
		conds = append(conds, "id = ?")
		args = append(args, f.DecisionID)
	}
	if f.ExactSessionID != "" {
		conds = append(conds, "session_id = ?")
		args = append(args, f.ExactSessionID)
	} else if f.SessionID != "" {
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
	q := "SELECT id, ts, session_id, agent, tool_name, summary, action, rule_id, reason, impact, elapsed_us, cwd, tool_input_redacted, would_action, policy_action, effective_action, adapter, translation_reason, tool_use_id, final_action, enforcer FROM decisions"
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
			id                int64
			tsStr             string
			sid               string
			agent             sql.NullString
			toolName          string
			summary           sql.NullString
			action            string
			ruleID            sql.NullString
			policyReason      sql.NullString
			impact            sql.NullString
			elapsed           sql.NullInt64
			cwd               sql.NullString
			toolInput         sql.NullString
			wouldAct          sql.NullString
			policyAct         sql.NullString
			effective         sql.NullString
			adapter           sql.NullString
			translationReason sql.NullString
			toolUseID         sql.NullString
			finalAct          sql.NullString
			enforcer          sql.NullString
		)
		if err := rows.Scan(&id, &tsStr, &sid, &agent, &toolName, &summary, &action, &ruleID, &policyReason, &impact, &elapsed, &cwd, &toolInput, &wouldAct, &policyAct, &effective, &adapter, &translationReason, &toolUseID, &finalAct, &enforcer); err != nil {
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
			Reason:            policyReason.String,
			Impact:            impact.String,
			ElapsedUs:         elapsed.Int64,
			CWD:               cwd.String,
			ToolInputRedacted: toolInput.String,
			WouldAction:       wouldAct.String,
			PolicyAction:      policyAct.String,
			EffectiveAction:   effective.String,
			Adapter:           adapter.String,
			TranslationReason: translationReason.String,
			ToolUseID:         toolUseID.String,
			FinalAction:       finalAct.String,
			Enforcer:          enforcer.String,
		})
	}
	return out, rows.Err()
}

// UpdateOutcome records the observed result of a completed tool call against
// the PreToolUse row that shares toolUseID, setting the final outcome and the
// responsible enforcer. Matches the most recent such row (a repeated command
// reuses a hashed id; newest wins). No-op if no row matches. See ADR 0112.
func (s *sqliteStore) UpdateOutcome(ctx context.Context, toolUseID, finalAction, enforcer string) error {
	if toolUseID == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE decisions SET final_action = ?, enforcer = ?
		 WHERE id = (SELECT id FROM decisions WHERE tool_use_id = ? ORDER BY id DESC LIMIT 1)`,
		finalAction, enforcer, toolUseID)
	if err != nil {
		return fmt.Errorf("store: update outcome: %w", err)
	}
	return nil
}

// ListAuditEvents returns policy audit events from the unified audit_log,
// mapped back to the legacy AuditRecord shape for backward compatibility.
func (s *sqliteStore) ListAuditEvents(ctx context.Context, f AuditFilter) ([]AuditRecord, error) {
	q := `SELECT id, ts, event_type, entity, actor FROM audit_log
		  WHERE event_type IN ('policy.changed', 'policy.change_requested')
		  ORDER BY id ` + orderDir(f.OrderDesc)
	q += fmt.Sprintf(" LIMIT %d", clampLimit(f.Limit))
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("store: list audit events: %w", err)
	}
	defer rows.Close()

	var out []AuditRecord
	for rows.Next() {
		var (
			id        int64
			tsStr     string
			eventType string
			entity    sql.NullString
			actor     sql.NullString
		)
		if err := rows.Scan(&id, &tsStr, &eventType, &entity, &actor); err != nil {
			return nil, fmt.Errorf("store: scan audit event: %w", err)
		}
		ts, _ := time.Parse(time.RFC3339Nano, tsStr)
		out = append(out, AuditRecord{
			ID:     id,
			Ts:     ts,
			Action: eventType,
			RuleID: entity.String,
			User:   actor.String,
		})
	}
	return out, rows.Err()
}

// ListSessions returns sessions newest-first by start_ts.
func (s *sqliteStore) ListSessions(ctx context.Context) ([]Session, error) {
	rows, err := s.queries.ListAllSessions(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: list sessions: %w", err)
	}
	return dbSessionsToSessions(rows), nil
}

func dbSessionsToSessions(rows []DBSession) []Session {
	out := make([]Session, 0, len(rows))
	for _, r := range rows {
		start, _ := time.Parse(time.RFC3339Nano, r.StartTs)
		var end time.Time
		if r.EndTs.Valid {
			end, _ = time.Parse(time.RFC3339Nano, r.EndTs.String)
		}
		out = append(out, Session{
			SessionID:     r.SessionID,
			StartTs:       start,
			EndTs:         end,
			Agent:         r.Agent.String,
			CWD:           r.Cwd.String,
			DecisionCount: int(r.DecisionCount),
		})
	}
	return out
}

// ListSessionsFiltered returns sessions matching the filter, newest-first.
func (s *sqliteStore) ListSessionsFiltered(ctx context.Context, f SessionFilter) ([]Session, error) {
	q := `SELECT session_id, start_ts, end_ts, agent, cwd, decision_count FROM sessions`
	var args []any
	if f.Since > 0 {
		cutoff := time.Now().Add(-f.Since).UTC().Format(time.RFC3339Nano)
		q += ` WHERE end_ts > ? OR end_ts IS NULL`
		args = append(args, cutoff)
	}
	q += ` ORDER BY start_ts DESC`
	if f.Limit > 0 {
		q += fmt.Sprintf(` LIMIT %d`, f.Limit)
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list sessions filtered: %w", err)
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
	rows, err := s.queries.CountActionsBySession(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: count actions: %w", err)
	}
	out := make([]ActionCount, 0, len(rows))
	for _, r := range rows {
		out = append(out, ActionCount{
			SessionID: r.SessionID,
			Action:    r.Action,
			Count:     int(r.Count),
		})
	}
	return out, nil
}

func (s *sqliteStore) CountPolicyMatches(ctx context.Context) ([]PolicyMatchCount, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT rule_id,
		       COUNT(*),
		       COUNT(DISTINCT COALESCE(NULLIF(agent, ''), 'unknown')),
		       COUNT(DISTINCT session_id)
		FROM decisions
		WHERE rule_id IS NOT NULL AND rule_id != ''
		GROUP BY rule_id
		ORDER BY COUNT(*) DESC, rule_id ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: count policy matches: %w", err)
	}
	defer rows.Close()

	out := make([]PolicyMatchCount, 0)
	for rows.Next() {
		var match PolicyMatchCount
		if err := rows.Scan(&match.RuleID, &match.Count, &match.AgentCount, &match.SessionCount); err != nil {
			return nil, fmt.Errorf("store: scan policy match: %w", err)
		}
		out = append(out, match)
	}
	return out, rows.Err()
}

func (s *sqliteStore) CountPolicyMatchesBySession(ctx context.Context, limit int) ([]PolicySessionMatch, error) {
	if limit <= 0 || limit > 10_000 {
		limit = 5_000
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT rule_id,
		       COALESCE(NULLIF(agent, ''), 'unknown'),
		       session_id,
		       COALESCE(NULLIF(cwd, ''), ''),
		       COUNT(*)
		FROM decisions
		WHERE rule_id IS NOT NULL AND rule_id != ''
		GROUP BY rule_id, 2, session_id, 4
		ORDER BY COUNT(*) DESC, rule_id ASC, session_id ASC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: count policy matches by session: %w", err)
	}
	defer rows.Close()

	out := make([]PolicySessionMatch, 0)
	for rows.Next() {
		var match PolicySessionMatch
		if err := rows.Scan(&match.RuleID, &match.Agent, &match.SessionID, &match.CWD, &match.Count); err != nil {
			return nil, fmt.Errorf("store: scan policy session match: %w", err)
		}
		out = append(out, match)
	}
	return out, rows.Err()
}

// Cleanup deletes decisions, audit_log entries, and sessions older than
// maxAge, VACUUMs if anything was purged, then checkpoints the WAL
// (ADR 0071). A retention.purged audit event is emitted post-commit
// (best-effort).
func (s *sqliteStore) Cleanup(ctx context.Context, maxAge time.Duration) error {
	cutoff := time.Now().Add(-maxAge).UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: cleanup begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	type deleteResult struct {
		table string
		count int64
	}
	var results []deleteResult
	var totalDeleted int64
	for _, q := range []struct {
		sql   string
		table string
	}{
		{`DELETE FROM decisions WHERE ts < ?`, "decisions"},
		{`DELETE FROM audit_log WHERE ts < ?`, "audit_log"},
		{`DELETE FROM sessions WHERE start_ts < ?`, "sessions"},
	} {
		res, err := tx.ExecContext(ctx, q.sql, cutoff)
		if err != nil {
			return fmt.Errorf("store: cleanup delete: %w", err)
		}
		n, _ := res.RowsAffected()
		totalDeleted += n
		results = append(results, deleteResult{table: q.table, count: n})
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: cleanup commit: %w", err)
	}

	// VACUUM only when rows were purged; nothing deleted, nothing to reclaim
	// (ADR 0071). VACUUM cannot run inside a transaction.
	if totalDeleted > 0 {
		if _, err := s.db.ExecContext(ctx, `VACUUM`); err != nil {
			return fmt.Errorf("store: vacuum: %w", err)
		}
	}

	// Fold the WAL back into the main DB, best-effort (ADR 0071). Owning
	// connection only — never checkpoint this DB from another process.
	var walBusy, walLog, walCheckpointed int
	if err := s.db.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).
		Scan(&walBusy, &walLog, &walCheckpointed); err != nil {
		slog.Warn("store: wal checkpoint failed (non-fatal)", "error", err)
	} else if walBusy != 0 {
		slog.Warn("store: wal checkpoint blocked by an active reader; WAL not truncated", "wal_frames", walLog)
	}

	// Emit retention.purged best-effort (fire-and-forget).
	detail := make(map[string]string, len(results))
	for _, r := range results {
		detail[r.table] = fmt.Sprintf("%d", r.count)
	}
	if auditErr := s.Emit(ctx, audit.Event{
		EventType: audit.RetentionPurged,
		Detail:    detail,
	}); auditErr != nil {
		slog.Warn("audit emit failed for retention purge", "error", auditErr)
	}

	return nil
}

// UpsertDiscoveredTool inserts a discovered MCP tool or updates last_seen and
// source on conflict (server, tool). It emits audit.ToolDiscovered (new) or
// audit.ToolUpdated (existing) best-effort — audit failure is logged but does
// not roll back the upsert.
func (s *sqliteStore) UpsertDiscoveredTool(ctx context.Context, server, tool, source string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	// Check if the row already exists.
	var exists int
	_ = tx.QueryRowContext(ctx, `SELECT 1 FROM discovered_tools WHERE server = ? AND tool = ?`, server, tool).Scan(&exists)

	txq := New(tx)
	if err := txq.UpsertDiscoveredTool(ctx, UpsertDiscoveredToolParams{
		Server:    server,
		Tool:      tool,
		Source:    source,
		FirstSeen: now,
		LastSeen:  now,
	}); err != nil {
		return fmt.Errorf("store: upsert discovered tool: %w", err)
	}

	// Emit audit event best-effort.
	eventType := audit.ToolDiscovered
	if exists == 1 {
		eventType = audit.ToolUpdated
	}
	if auditErr := txq.InsertAuditLog(ctx, InsertAuditLogParams{
		Ts:        now,
		EventType: eventType,
		Entity:    toNullString(server + "/" + tool),
		Detail:    toNullString(redactDetail(map[string]string{"source": source})),
	}); auditErr != nil {
		slog.Warn("audit emit failed for discovered tool", "event", eventType, "error", auditErr)
	}

	return tx.Commit()
}

func (s *sqliteStore) UpsertMCPDiscoveryStatus(ctx context.Context, server string, status MCPDiscoveryStatus) error {
	if server == "" {
		return fmt.Errorf("store: MCP discovery server is empty")
	}
	switch status {
	case MCPDiscoveryConnected, MCPDiscoveryAuthRequired, MCPDiscoveryUnreachable, MCPDiscoveryTimeout:
	default:
		return fmt.Errorf("store: invalid MCP discovery status")
	}
	if err := s.queries.UpsertMCPDiscoveryStatus(ctx, UpsertMCPDiscoveryStatusParams{
		Server: server, Status: string(status), LastSeen: time.Now().UTC().Format(time.RFC3339Nano),
	}); err != nil {
		return fmt.Errorf("store: upsert MCP discovery status: %w", err)
	}
	return nil
}

// UpsertDiscoveredSkill inserts a discovered skill or updates last_seen,
// source, and increments use_count on conflict (name). It emits
// audit.SkillDiscovered only on first insert (use_count bumps are noise).
func (s *sqliteStore) UpsertDiscoveredSkill(ctx context.Context, name, source string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	// Check if the row already exists.
	var exists int
	_ = tx.QueryRowContext(ctx, `SELECT 1 FROM discovered_skills WHERE name = ?`, name).Scan(&exists)

	txq := New(tx)
	if err := txq.UpsertDiscoveredSkill(ctx, UpsertDiscoveredSkillParams{
		Name:      name,
		Source:    source,
		FirstSeen: now,
		LastSeen:  now,
	}); err != nil {
		return fmt.Errorf("store: upsert discovered skill: %w", err)
	}

	// Emit audit event only for new skills (use_count bumps are noise).
	if exists == 0 {
		if auditErr := txq.InsertAuditLog(ctx, InsertAuditLogParams{
			Ts:        now,
			EventType: audit.SkillDiscovered,
			Entity:    toNullString(name),
			Detail:    toNullString(redactDetail(map[string]string{"source": source})),
		}); auditErr != nil {
			slog.Warn("audit emit failed for discovered skill", "event", audit.SkillDiscovered, "error", auditErr)
		}
	}

	return tx.Commit()
}

// ListDiscoveredTools returns all discovered tools. If server is non-empty,
// only tools for that server are returned.
func (s *sqliteStore) ListDiscoveredTools(ctx context.Context, server string) ([]DiscoveredTool, error) {
	var dbRows []DBDiscoveredTool
	var err error
	if server == "" {
		dbRows, err = s.queries.ListDiscoveredToolsAll(ctx)
	} else {
		dbRows, err = s.queries.ListDiscoveredToolsByServer(ctx, server)
	}
	if err != nil {
		return nil, fmt.Errorf("store: list discovered tools: %w", err)
	}
	out := make([]DiscoveredTool, 0, len(dbRows))
	for _, r := range dbRows {
		firstSeen, _ := time.Parse(time.RFC3339Nano, r.FirstSeen)
		lastSeen, _ := time.Parse(time.RFC3339Nano, r.LastSeen)
		out = append(out, DiscoveredTool{
			ID:        r.ID,
			Server:    r.Server,
			Tool:      r.Tool,
			Source:    r.Source,
			FirstSeen: firstSeen,
			LastSeen:  lastSeen,
		})
	}
	return out, nil
}

func (s *sqliteStore) ListMCPDiscoveryStatuses(ctx context.Context) ([]MCPDiscoveryRecord, error) {
	rows, err := s.queries.ListMCPDiscoveryStatuses(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: list MCP discovery statuses: %w", err)
	}
	out := make([]MCPDiscoveryRecord, 0, len(rows))
	for _, row := range rows {
		lastSeen, _ := time.Parse(time.RFC3339Nano, row.LastSeen)
		out = append(out, MCPDiscoveryRecord{Server: row.Server, Status: MCPDiscoveryStatus(row.Status), LastSeen: lastSeen})
	}
	return out, nil
}

// ListDiscoveredSkills returns all discovered skills ordered by name.
func (s *sqliteStore) ListDiscoveredSkills(ctx context.Context) ([]DiscoveredSkill, error) {
	dbRows, err := s.queries.ListDiscoveredSkillsAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: list discovered skills: %w", err)
	}
	out := make([]DiscoveredSkill, 0, len(dbRows))
	for _, r := range dbRows {
		firstSeen, _ := time.Parse(time.RFC3339Nano, r.FirstSeen)
		lastSeen, _ := time.Parse(time.RFC3339Nano, r.LastSeen)
		out = append(out, DiscoveredSkill{
			ID:        r.ID,
			Name:      r.Name,
			Source:    r.Source,
			FirstSeen: firstSeen,
			LastSeen:  lastSeen,
			UseCount:  int(r.UseCount),
		})
	}
	return out, nil
}

// ListDistinctCWDs returns unique non-empty CWD values from the sessions table.
func (s *sqliteStore) ListDistinctCWDs(ctx context.Context) ([]string, error) {
	rows, err := s.queries.ListDistinctCWDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: list distinct cwds: %w", err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if r.Valid {
			out = append(out, r.String)
		}
	}
	return out, nil
}

// ListDistinctMCPToolNames returns distinct MCP tool names (prefixed "mcp__")
// from the decisions table.
func (s *sqliteStore) ListDistinctMCPToolNames(ctx context.Context) ([]string, error) {
	return s.queries.ListDistinctMCPToolNames(ctx)
}

// ListDistinctSkillInputs returns distinct non-empty tool_input_redacted values
// from decisions where tool_name = 'Skill'.
func (s *sqliteStore) ListDistinctSkillInputs(ctx context.Context) ([]string, error) {
	rows, err := s.queries.ListDistinctSkillInputs(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: list distinct skill inputs: %w", err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if r.Valid {
			out = append(out, r.String)
		}
	}
	return out, nil
}

// Emit persists an audit.Event to the audit_log table (Plan 009). The Detail
// map is redacted and serialised to JSON before storage.
func (s *sqliteStore) Emit(ctx context.Context, e audit.Event) error {
	detail := redactDetail(e.Detail)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	err := s.queries.InsertAuditLog(ctx, InsertAuditLogParams{
		Ts:        now,
		EventType: e.EventType,
		Entity:    toNullString(e.Entity),
		Detail:    toNullString(detail),
		Actor:     toNullString(e.Actor),
		SessionID: toNullString(e.SessionID),
		RefID:     toNullString(e.RefID),
	})
	if err != nil {
		return fmt.Errorf("store: emit audit: %w", err)
	}
	return nil
}

// redactDetail serialises a Detail map to JSON, replacing secret-bearing keys
// with "[redacted]", sweeping the remaining values for secret-shaped strings
// (ADR 0084-redact-secret-values), and truncating to maxRedactedLen.
func redactDetail(d map[string]string) string {
	if len(d) == 0 {
		return ""
	}
	redacted := make(map[string]string, len(d))
	for k, v := range d {
		if shouldRedactKey(k) {
			redacted[k] = "[redacted]"
		} else {
			redacted[k] = redactSecretsInText(v)
		}
	}
	b, err := json.Marshal(redacted)
	if err != nil {
		return "{}"
	}
	s := string(b)
	if len(s) <= maxRedactedLen {
		return s
	}
	end := maxRedactedLen
	for end > 0 && (s[end]&0xC0) == 0x80 {
		end--
	}
	return s[:end] + "…"
}

// ListAuditLog returns audit log entries matching the filter.
func (s *sqliteStore) ListAuditLog(ctx context.Context, f AuditLogFilter) ([]AuditLogEntry, error) {
	limit := int64(clampLimit(f.Limit))
	var dbRows []DBAuditLog
	var err error

	switch {
	case f.Entity != "":
		dbRows, err = s.queries.ListAuditLogByEntity(ctx, ListAuditLogByEntityParams{
			Entity: toNullString(f.Entity),
			Limit:  limit,
		})
	case f.EventType != "":
		dbRows, err = s.queries.ListAuditLogByType(ctx, ListAuditLogByTypeParams{
			EventType: f.EventType,
			Limit:     limit,
		})
	case f.SessionID != "":
		dbRows, err = s.queries.ListAuditLogBySession(ctx, ListAuditLogBySessionParams{
			SessionID: toNullString(f.SessionID),
			Limit:     limit,
		})
	default:
		dbRows, err = s.queries.ListAuditLogRecent(ctx, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("store: list audit log: %w", err)
	}

	out := make([]AuditLogEntry, 0, len(dbRows))
	for _, r := range dbRows {
		ts, _ := time.Parse(time.RFC3339Nano, r.Ts)
		out = append(out, AuditLogEntry{
			ID:        r.ID,
			Ts:        ts,
			EventType: r.EventType,
			Entity:    r.Entity.String,
			Detail:    r.Detail.String,
			Actor:     r.Actor.String,
			SessionID: r.SessionID.String,
			RefID:     r.RefID.String,
		})
	}
	return out, nil
}

// grantAuditEventTypes are the audit_log event types that make up the grant
// approval/denial history shown by `agentjail grants --log`. Kept
// in one place so the CLI and store agree on what counts as a "grant event".
var grantAuditEventTypes = []string{
	audit.DaemonGrantRequested,
	audit.DaemonGrantDenied,
	audit.PolicyChangeRequested,
	audit.PolicyChanged,
}

// ListGrantAuditLog returns the most recent grant-related audit_log entries
// (requested/denied/change_requested/changed), newest first. This is a
// manual query (not sqlc) because it needs a dynamic IN-list over
// grantAuditEventTypes plus an OR across ref_id/detail -- the kind of
// variable-shape query AGENTS.md calls out as staying manual, while still
// scanning into the typed AuditLogEntry struct rather than any/interface{}.
func (s *sqliteStore) ListGrantAuditLog(ctx context.Context, limit int) ([]AuditLogEntry, error) {
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(grantAuditEventTypes)), ",")
	q := fmt.Sprintf(`SELECT id, ts, event_type, entity, detail, actor, session_id, ref_id
		FROM audit_log
		WHERE event_type IN (%s)
		  AND (ref_id != '' OR detail LIKE '%%host%%')
		ORDER BY ts DESC LIMIT ?`, placeholders)

	args := make([]interface{}, 0, len(grantAuditEventTypes)+1)
	for _, t := range grantAuditEventTypes {
		args = append(args, t)
	}
	args = append(args, clampLimit(limit))

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list grant audit log: %w", err)
	}
	defer rows.Close()

	var out []AuditLogEntry
	for rows.Next() {
		var (
			id        int64
			tsStr     string
			eventType string
			entity    sql.NullString
			detail    sql.NullString
			actor     sql.NullString
			sessionID sql.NullString
			refID     sql.NullString
		)
		if err := rows.Scan(&id, &tsStr, &eventType, &entity, &detail, &actor, &sessionID, &refID); err != nil {
			return nil, fmt.Errorf("store: scan grant audit log: %w", err)
		}
		ts, _ := time.Parse(time.RFC3339Nano, tsStr)
		out = append(out, AuditLogEntry{
			ID:        id,
			Ts:        ts,
			EventType: eventType,
			Entity:    entity.String,
			Detail:    detail.String,
			Actor:     actor.String,
			SessionID: sessionID.String,
			RefID:     refID.String,
		})
	}
	return out, rows.Err()
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
func (r *sqliteROStore) ListGrantAuditLog(ctx context.Context, limit int) ([]AuditLogEntry, error) {
	return r.inner.ListGrantAuditLog(ctx, limit)
}
func (r *sqliteROStore) DecisionCount(ctx context.Context) (int64, error) {
	return r.inner.DecisionCount(ctx)
}
func (r *sqliteROStore) ListSessions(ctx context.Context) ([]Session, error) {
	return r.inner.ListSessions(ctx)
}
func (r *sqliteROStore) ListSessionsFiltered(ctx context.Context, f SessionFilter) ([]Session, error) {
	return r.inner.ListSessionsFiltered(ctx, f)
}
func (r *sqliteROStore) CountActionsBySession(ctx context.Context) ([]ActionCount, error) {
	return r.inner.CountActionsBySession(ctx)
}
func (r *sqliteROStore) CountPolicyMatches(ctx context.Context) ([]PolicyMatchCount, error) {
	return r.inner.CountPolicyMatches(ctx)
}
func (r *sqliteROStore) CountPolicyMatchesBySession(ctx context.Context, limit int) ([]PolicySessionMatch, error) {
	return r.inner.CountPolicyMatchesBySession(ctx, limit)
}
func (r *sqliteROStore) ListDiscoveredTools(ctx context.Context, server string) ([]DiscoveredTool, error) {
	return r.inner.ListDiscoveredTools(ctx, server)
}
func (r *sqliteROStore) ListMCPDiscoveryStatuses(ctx context.Context) ([]MCPDiscoveryRecord, error) {
	return r.inner.ListMCPDiscoveryStatuses(ctx)
}
func (r *sqliteROStore) ListDiscoveredSkills(ctx context.Context) ([]DiscoveredSkill, error) {
	return r.inner.ListDiscoveredSkills(ctx)
}
func (r *sqliteROStore) ListAuditLog(ctx context.Context, f AuditLogFilter) ([]AuditLogEntry, error) {
	return r.inner.ListAuditLog(ctx, f)
}
func (r *sqliteROStore) ListDistinctCWDs(ctx context.Context) ([]string, error) {
	return r.inner.ListDistinctCWDs(ctx)
}
func (r *sqliteROStore) ListDistinctMCPToolNames(ctx context.Context) ([]string, error) {
	return r.inner.ListDistinctMCPToolNames(ctx)
}
func (r *sqliteROStore) ListDistinctSkillInputs(ctx context.Context) ([]string, error) {
	return r.inner.ListDistinctSkillInputs(ctx)
}
func (r *sqliteROStore) CountWouldBlock(ctx context.Context, since time.Time) ([]WouldBlockCount, error) {
	return r.inner.CountWouldBlock(ctx, since)
}
func (r *sqliteROStore) ComputeStats(ctx context.Context, since time.Time) (StatsReport, error) {
	return r.inner.ComputeStats(ctx, since)
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
		sqliteutil.EscapeDSNPath(path),
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
	return &sqliteROStore{inner: &sqliteStore{db: db, queries: New(db), path: path}}, nil
}
