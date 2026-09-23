// Package mitm provides the SQLite-backed request logging store for
// AgentJail's network inspection feature.
//
// Intercepted HTTP requests are logged to ~/.agentjail/network.db (separate
// from the main agentjail.db to avoid lock contention). The store uses WAL
// mode with a 3000ms busy timeout, matching the project's SQLite conventions.
package mitm

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/LuD1161/agentjail/internal/redact"
	"time"

	"github.com/LuD1161/agentjail/internal/sqliteutil"
	_ "modernc.org/sqlite"
)

// RequestLog represents one intercepted HTTP request/response pair.
type RequestLog struct {
	ID              int64             `json:"id"`
	Ts              time.Time         `json:"ts"`
	Host            string            `json:"host"`
	Method          string            `json:"method"`
	Path            string            `json:"path"`
	URL             string            `json:"url"`
	StatusCode      int               `json:"status_code,omitempty"`
	RequestSize     int64             `json:"request_size,omitempty"`
	ResponseSize    int64             `json:"response_size,omitempty"`
	ElapsedMs       int64             `json:"elapsed_ms,omitempty"`
	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	// Body paths are relative to the BodyStore directory. Empty means no body;
	// a path whose file is gone means absent, not an error.
	// See ADR 0092-persist-request-bodies (D1).
	RequestBodyPath  string           `json:"request_body_path,omitempty"`
	ResponseBodyPath string           `json:"response_body_path,omitempty"`
	EncodingRaw      EncodingRawSides `json:"encoding_raw,omitempty"`
	Error            string           `json:"error,omitempty"`
	SessionID        string           `json:"session_id,omitempty"`
	// ClaudeSessionID is the Claude session this capture belongs to — the
	// same identity the daemon's decisions are keyed on, so one coding
	// session has one id across the whole UI (AGE-111). The shield resolves
	// it a few seconds after launch (the agent must exist first) and
	// backfills earlier rows.
	ClaudeSessionID string `json:"claude_session_id,omitempty"`
	// OwnerPID is the shield process that owns this network session. Every row
	// of one session shares it, so the UI can decide "active" by process
	// liveness instead of joining on the id-space mismatch between the network
	// session id and the daemon session id. See ADR 0100-network-active-pid.
	OwnerPID int `json:"owner_pid,omitempty"`
	// Agent and Cwd identify who this session is: the agent binary's name
	// (e.g. "claude") and the directory it was launched from. Stamped onto
	// every row like OwnerPID, so the UI can label sessions the way the
	// monitor sidebar does instead of showing opaque session ids.
	Agent          string `json:"agent,omitempty"`
	Cwd            string `json:"cwd,omitempty"`
	ToolName       string `json:"tool_name,omitempty"`
	PolicyAction   string `json:"policy_action,omitempty"`
	PolicyTemplate string `json:"policy_template,omitempty"`
	PolicyReason   string `json:"policy_reason,omitempty"`
	Service        string `json:"service,omitempty"`
	Verb           string `json:"verb,omitempty"`
	ResourceType   string `json:"resource_type,omitempty"`

	// bodiesFinished keeps the capture teardown idempotent across the handler's
	// exit paths. Not persisted.
	bodiesFinished bool
}

// RequestOrder selects the direction of request IDs returned by Query.
type RequestOrder uint8

const (
	RequestsNewestFirst RequestOrder = iota
	RequestsOldestFirst
)

// RequestFilter selects requests for Query. Zero-value fields are not filtered on.
type RequestFilter struct {
	Host     string
	Method   string
	Limit    int
	Since    time.Duration
	ID       int64
	AfterID  int64
	Order    RequestOrder
	BeforeID int64
	Session  string
	Status   int
	Policy   string
	Offset   int
}

// HostStats contains per-host aggregated traffic statistics.
type HostStats struct {
	Host         string  `json:"host"`
	RequestCount int64   `json:"request_count"`
	BytesOut     int64   `json:"bytes_out"`
	BytesIn      int64   `json:"bytes_in"`
	AvgLatencyMs float64 `json:"avg_latency_ms"`
}

const (
	defaultLimit = 50
	maxLimit     = 10000
)

// clampLimit clamps a query LIMIT to this store's [defaultLimit, maxLimit]
// range via the shared helper.
func clampLimit(n int) int { return sqliteutil.ClampLimit(n, defaultLimit, maxLimit) }

// RequestStore logs intercepted HTTP requests to SQLite.
type RequestStore struct {
	db *sql.DB
}

// DBFileName is the network store's filename inside ~/.agentjail. Exported so
// the shield derives its deny rule from here rather than keeping a second copy.
// See ADR 0092-persist-request-bodies (D3).
const DBFileName = "network.db"

// DBProtectedFileNames returns the DB and every sidecar SQLite may write beside
// it. The WAL holds uncheckpointed bodies, so denying the .db alone leaves the
// freshest traffic readable. See ADR 0092-persist-request-bodies (D3).
func DBProtectedFileNames() []string {
	return []string{
		DBFileName,
		DBFileName + "-wal",     // write-ahead log: recent, uncheckpointed bodies
		DBFileName + "-shm",     // shared-memory index for the WAL
		DBFileName + "-journal", // rollback journal, if WAL is ever disabled
	}
}

// DefaultDBPath returns the default network request database path:
// ~/.agentjail/network.db.
func DefaultDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/agentjail-network.db"
	}
	return filepath.Join(home, ".agentjail", DBFileName)
}

// NewRequestStore opens (or creates) the network_requests table in the
// given SQLite database file. The directory is created with 0700 permissions;
// the DB file is set to 0600. WAL mode + busy_timeout=3000 are configured.
func NewRequestStore(dbPath string) (*RequestStore, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mitm/store: mkdir %s: %w", dir, err)
	}
	dsn := fmt.Sprintf(
		"file:%s?_pragma=busy_timeout(3000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)",
		sqliteutil.EscapeDSNPath(dbPath),
	)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("mitm/store: open: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("mitm/store: ping: %w", err)
	}
	s := &RequestStore{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	// chmod 0600 on the DB file (defense-in-depth; 0700 dir is primary).
	if err := sqliteutil.ChmodDBFiles(dbPath, 0o600); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("mitm/store: chmod: %w", err)
	}
	return s, nil
}

// OpenReadOnly opens an existing network store for reading. Readers must not
// create, migrate or write the store that holds the transcripts.
// See ADR 0092-persist-request-bodies (D3).
func OpenReadOnly(dbPath string) (*RequestStore, error) {
	if _, err := os.Stat(dbPath); err != nil {
		return nil, fmt.Errorf("mitm/store: read-only open %s: %w", dbPath, err)
	}
	dsn := fmt.Sprintf(
		"file:%s?mode=ro&_pragma=busy_timeout(3000)",
		sqliteutil.EscapeDSNPath(dbPath),
	)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("mitm/store: read-only open: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("mitm/store: read-only ping: %w", err)
	}
	return &RequestStore{db: db}, nil
}

func (s *RequestStore) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS network_requests (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ts TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f','now')),
			host TEXT NOT NULL,
			method TEXT NOT NULL,
			path TEXT NOT NULL,
			url TEXT NOT NULL,
			status_code INTEGER,
			request_size INTEGER,
			response_size INTEGER,
			elapsed_ms INTEGER,
			request_headers TEXT,
			response_headers TEXT,
			request_body_path TEXT,
			response_body_path TEXT,
			encoding_raw TEXT,
			error TEXT,
			session_id TEXT,
			claude_session_id TEXT,
			owner_pid INTEGER,
			agent TEXT,
			cwd TEXT,
			tool_name TEXT,
			policy_action TEXT,
			policy_template TEXT,
			policy_reason TEXT,
			service TEXT,
			verb TEXT,
			resource_type TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_network_ts ON network_requests(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_network_host ON network_requests(host)`,
		`CREATE INDEX IF NOT EXISTS idx_network_policy ON network_requests(policy_action)`,
	}
	for _, st := range stmts {
		if _, err := s.db.Exec(st); err != nil {
			return fmt.Errorf("mitm/store: migrate: %w", err)
		}
	}
	// Idempotent column additions for policy decision tracking and body paths.
	for _, col := range []string{"policy_action", "policy_template", "policy_reason", "service", "verb", "resource_type",
		"request_body_path", "response_body_path", "encoding_raw", "agent", "cwd",
		"claude_session_id"} {
		s.db.Exec(fmt.Sprintf("ALTER TABLE network_requests ADD COLUMN %s TEXT", col))
	}
	// owner_pid is INTEGER (not TEXT like the block above) so an existing DB
	// keeps integer affinity and PIDs round-trip as numbers, not "12345" text.
	// See ADR 0100-network-active-pid.
	s.db.Exec("ALTER TABLE network_requests ADD COLUMN owner_pid INTEGER")
	if _, err := s.db.Exec("CREATE INDEX IF NOT EXISTS idx_network_session_id ON network_requests(" + unifiedSessionExpression + ", id)"); err != nil {
		return fmt.Errorf("mitm/store: session index: %w", err)
	}

	// One-time cleanup for the unified-session-id upgrade (AGE-111): rows
	// written before claude_session_id existed can never join the daemon's
	// sessions, so they would sit in the UI as permanently-anonymous groups.
	// Deliberately dropped rather than carried. Versioned via user_version so
	// this never touches rows written after the upgrade (a live session's
	// first rows are legitimately NULL until the shield backfills them).
	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err == nil && version < 1 {
		s.db.Exec("DELETE FROM network_requests WHERE claude_session_id IS NULL")
		s.db.Exec("PRAGMA user_version = 1")
	}
	return nil
}

// BackfillClaudeSession stamps the resolved Claude session id onto every row
// of one capture session that predates the resolution. Called once by the
// shield when its descendant claude process appears.
func (s *RequestStore) BackfillClaudeSession(ctx context.Context, sessionID, claudeSessionID string) error {
	if sessionID == "" || claudeSessionID == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		"UPDATE network_requests SET claude_session_id = ? WHERE session_id = ? AND claude_session_id IS NULL",
		claudeSessionID, sessionID)
	if err != nil {
		return fmt.Errorf("mitm/store: backfill claude session: %w", err)
	}
	return nil
}

// The rules live in internal/redact. This used to be an exact-match list of
// eight names, which missed every vendor variant: a real session persisted
// "Dd-Api-Key":"pub..." verbatim to network.db, because "dd-api-key" is not
// literally "api-key". Enumerating header names is the thing that failed --
// substring matching is what catches the next vendor's spelling without anyone
// noticing it exists. ADR 0032, AGE-232.

// redactedHeaderValue replaces credential header values on the persistence path.
const redactedHeaderValue = "[REDACTED]"

// redactHeaders returns a copy of h with the values of sensitive header keys
// (see internal/redact) replaced by redactedHeaderValue.
// The input map is never mutated so callers keep the live values in memory;
// only what reaches disk is redacted. Returns nil for a nil/empty input.
func redactHeaders(h map[string]string) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, v := range h {
		if redact.ShouldRedactKey(k) {
			out[k] = redactedHeaderValue
		} else {
			out[k] = v
		}
	}
	return out
}

// marshalHeaders encodes a header map as JSON, returning "" for nil/empty.
func marshalHeaders(h map[string]string) string {
	if len(h) == 0 {
		return ""
	}
	b, err := json.Marshal(h)
	if err != nil {
		return ""
	}
	return string(b)
}

// unmarshalHeaders decodes JSON headers, returning nil on empty/error.
func unmarshalHeaders(s string) map[string]string {
	if s == "" {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil
	}
	return m
}

// Log writes one request/response record.
func (s *RequestStore) Log(entry *RequestLog) error {
	ts := entry.Ts.UTC().Format("2006-01-02T15:04:05.000")
	// Redact credential headers at the store boundary (S-C2 / ADR 0032) so no
	// secret value ever lands in network.db, which the agent can read back.
	reqH := marshalHeaders(redactHeaders(entry.RequestHeaders))
	respH := marshalHeaders(redactHeaders(entry.ResponseHeaders))
	// Bodies are not redacted: a body is arbitrary JSON with no key names to
	// match on. See ADR 0092-persist-request-bodies (D1).
	_, err := s.db.Exec(`INSERT INTO network_requests
		(ts, host, method, path, url, status_code, request_size, response_size,
		 elapsed_ms, request_headers, response_headers,
		 request_body_path, response_body_path, encoding_raw,
		 error, session_id, claude_session_id, owner_pid, agent, cwd, tool_name,
		 policy_action, policy_template, policy_reason, service, verb, resource_type)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		ts, entry.Host, entry.Method, entry.Path, entry.URL,
		nullInt(entry.StatusCode), nullInt64(entry.RequestSize), nullInt64(entry.ResponseSize),
		nullInt64(entry.ElapsedMs),
		nullStr(reqH), nullStr(respH),
		nullStr(entry.RequestBodyPath), nullStr(entry.ResponseBodyPath),
		nullStr(string(entry.EncodingRaw)),
		nullStr(entry.Error),
		nullStr(entry.SessionID), nullStr(entry.ClaudeSessionID), nullInt(entry.OwnerPID),
		nullStr(entry.Agent), nullStr(entry.Cwd), nullStr(entry.ToolName),
		nullStr(entry.PolicyAction), nullStr(entry.PolicyTemplate),
		nullStr(entry.PolicyReason), nullStr(entry.Service),
		nullStr(entry.Verb), nullStr(entry.ResourceType),
	)
	if err != nil {
		return fmt.Errorf("mitm/store: log: %w", err)
	}
	return nil
}

func nullInt(v int) interface{} {
	if v == 0 {
		return nil
	}
	return v
}

func nullInt64(v int64) interface{} {
	if v == 0 {
		return nil
	}
	return v
}

func nullStr(v string) interface{} {
	if v == "" {
		return nil
	}
	return v
}

// hasColumn reports whether network_requests has the named column. Used by
// read-only openers, which must never migrate the schema themselves.
func (s *RequestStore) hasColumn(ctx context.Context, name string) bool {
	rows, err := s.db.QueryContext(ctx, "PRAGMA table_info(network_requests)")
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid     int
			colName string
			colType sql.NullString
			notNull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &colName, &colType, &notNull, &dflt, &pk); err != nil {
			return false
		}
		if colName == name {
			return true
		}
	}
	return false
}

// requestConditions shares filtering between queries and counts.
func (s *RequestStore) requestConditions(ctx context.Context, filter RequestFilter) ([]string, []any) {
	var (
		conds []string
		args  []any
	)
	if filter.ID > 0 {
		conds = append(conds, "id = ?")
		args = append(args, filter.ID)
	}
	if filter.BeforeID > 0 {
		conds = append(conds, "id < ?")
		args = append(args, filter.BeforeID)
	}
	if filter.AfterID > 0 {
		conds = append(conds, "id > ?")
		args = append(args, filter.AfterID)
	}
	if filter.Host != "" {
		conds = append(conds, "host = ?")
		args = append(args, filter.Host)
	}
	if filter.Method != "" {
		conds = append(conds, "method = ?")
		args = append(args, strings.ToUpper(filter.Method))
	}
	if filter.Since > 0 {
		conds = append(conds, "ts > ?")
		args = append(args, time.Now().Add(-filter.Since).UTC().Format("2006-01-02T15:04:05.000"))
	}

	if filter.Session != "" {
		conds = append(conds, s.sessionExpression(ctx)+" = ?")
		args = append(args, filter.Session)
	}
	if filter.Status > 0 {
		conds = append(conds, "status_code = ?")
		args = append(args, filter.Status)
	}
	if filter.Policy != "" {
		conds = append(conds, "policy_action = ?")
		args = append(args, filter.Policy)
	}
	return conds, args
}

// Query returns matching requests in filter.Order, newest first by default.
func (s *RequestStore) Query(ctx context.Context, filter RequestFilter) ([]RequestLog, error) {
	conds, args := s.requestConditions(ctx, filter)

	// agent/cwd exist only after a writer has migrated the DB; the UI opens
	// read-only (ADR 0092 D3) and may be newer than every writer, so select
	// empty literals instead of failing on the missing columns.
	agentCols := "claude_session_id, agent, cwd"
	if !s.hasColumn(ctx, "agent") || !s.hasColumn(ctx, "claude_session_id") {
		agentCols = "'' AS claude_session_id, '' AS agent, '' AS cwd"
	}
	q := `SELECT id, ts, host, method, path, url, status_code, request_size, response_size,
		elapsed_ms, request_headers, response_headers,
		request_body_path, response_body_path, encoding_raw,
		error, session_id, ` + agentCols + `, owner_pid, tool_name,
		policy_action, policy_template, policy_reason, service, verb, resource_type
		FROM network_requests`
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	if filter.Order == RequestsOldestFirst {
		q += " ORDER BY id ASC"
	} else {
		q += " ORDER BY id DESC"
	}
	q += fmt.Sprintf(" LIMIT %d", clampLimit(filter.Limit))
	if filter.Offset > 0 {
		q += " OFFSET ?"
		args = append(args, filter.Offset)
	}

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("mitm/store: query: %w", err)
	}
	defer rows.Close()

	var out []RequestLog
	for rows.Next() {
		var (
			id           int64
			tsStr        string
			host         string
			method       string
			path         string
			url          string
			statusCode   sql.NullInt64
			reqSize      sql.NullInt64
			respSize     sql.NullInt64
			elapsedMs    sql.NullInt64
			reqH         sql.NullString
			respH        sql.NullString
			reqBodyPath  sql.NullString
			respBodyPath sql.NullString
			encodingRaw  sql.NullString
			errStr       sql.NullString
			sessionID    sql.NullString
			claudeSID    sql.NullString
			ownerPID     sql.NullInt64
			agent        sql.NullString
			cwd          sql.NullString
			toolName     sql.NullString
			policyAction sql.NullString
			policyTmpl   sql.NullString
			policyReason sql.NullString
			service      sql.NullString
			verb         sql.NullString
			resourceType sql.NullString
		)
		if err := rows.Scan(&id, &tsStr, &host, &method, &path, &url,
			&statusCode, &reqSize, &respSize, &elapsedMs,
			&reqH, &respH, &reqBodyPath, &respBodyPath, &encodingRaw,
			&errStr, &sessionID, &claudeSID, &agent, &cwd, &ownerPID, &toolName,
			&policyAction, &policyTmpl, &policyReason,
			&service, &verb, &resourceType); err != nil {
			return nil, fmt.Errorf("mitm/store: scan: %w", err)
		}
		ts, _ := time.Parse("2006-01-02T15:04:05.000", tsStr)
		out = append(out, RequestLog{
			ID:               id,
			Ts:               ts,
			Host:             host,
			Method:           method,
			Path:             path,
			URL:              url,
			StatusCode:       int(statusCode.Int64),
			RequestSize:      reqSize.Int64,
			ResponseSize:     respSize.Int64,
			ElapsedMs:        elapsedMs.Int64,
			RequestHeaders:   unmarshalHeaders(reqH.String),
			ResponseHeaders:  unmarshalHeaders(respH.String),
			RequestBodyPath:  reqBodyPath.String,
			ResponseBodyPath: respBodyPath.String,
			EncodingRaw:      EncodingRawSides(encodingRaw.String),
			Error:            errStr.String,
			SessionID:        sessionID.String,
			ClaudeSessionID:  claudeSID.String,
			OwnerPID:         int(ownerPID.Int64),
			Agent:            agent.String,
			Cwd:              cwd.String,
			ToolName:         toolName.String,
			PolicyAction:     policyAction.String,
			PolicyTemplate:   policyTmpl.String,
			PolicyReason:     policyReason.String,
			Service:          service.String,
			Verb:             verb.String,
			ResourceType:     resourceType.String,
		})
	}
	return out, rows.Err()
}

// Stats returns per-host aggregated traffic statistics for requests within
// the given duration (from now). Use 0 for all-time.
func (s *RequestStore) Stats(ctx context.Context, since time.Duration) ([]HostStats, error) {
	var (
		conds []string
		args  []any
	)
	if since > 0 {
		conds = append(conds, "ts > ?")
		args = append(args, time.Now().Add(-since).UTC().Format("2006-01-02T15:04:05.000"))
	}

	q := `SELECT host,
		COUNT(*) as request_count,
		COALESCE(SUM(request_size), 0) as bytes_out,
		COALESCE(SUM(response_size), 0) as bytes_in,
		COALESCE(AVG(elapsed_ms), 0) as avg_latency_ms
		FROM network_requests`
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " GROUP BY host ORDER BY request_count DESC"

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("mitm/store: stats: %w", err)
	}
	defer rows.Close()

	var out []HostStats
	for rows.Next() {
		var hs HostStats
		if err := rows.Scan(&hs.Host, &hs.RequestCount, &hs.BytesOut, &hs.BytesIn, &hs.AvgLatencyMs); err != nil {
			return nil, fmt.Errorf("mitm/store: scan stats: %w", err)
		}
		out = append(out, hs)
	}
	return out, rows.Err()
}

// Count returns the total number of logged requests.
func (s *RequestStore) Count(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM network_requests`).Scan(&n)
	return n, err
}

// Close closes the database.
func (s *RequestStore) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

const unifiedSessionExpression = "COALESCE(NULLIF(claude_session_id, ''), session_id, '')"

func (s *RequestStore) sessionExpression(ctx context.Context) string {
	if s.hasColumn(ctx, "claude_session_id") {
		return unifiedSessionExpression
	}
	return "COALESCE(session_id, '')"
}

// CountMatching returns the full matching count independently of paging boundaries.
func (s *RequestStore) CountMatching(ctx context.Context, filter RequestFilter) (int64, error) {
	filter.BeforeID = 0
	conds, args := s.requestConditions(ctx, filter)
	query := "SELECT COUNT(*) FROM network_requests"
	if len(conds) > 0 {
		query += " WHERE " + strings.Join(conds, " AND ")
	}
	var count int64
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&count)
	return count, err
}

type SessionSummary struct {
	SessionID    string
	FirstSeen    string
	LastSeen     string
	RequestCount int64
	DenyCount    int64
	OwnerPID     int
	Agent        string
	Cwd          string
	UserAgent    string
}

// Sessions aggregates all retained rows without loading request bodies or headers.
func (s *RequestStore) Sessions(ctx context.Context) ([]SessionSummary, error) {
	session := s.sessionExpression(ctx)
	agentIDs := "MAX(CASE WHEN agent <> '' THEN id END) AS agent_id, MAX(CASE WHEN cwd <> '' THEN id END) AS cwd_id"
	agentCols := "COALESCE(a.agent, ''), COALESCE(c.cwd, '')"
	if !s.hasColumn(ctx, "agent") {
		agentIDs = "NULL AS agent_id, NULL AS cwd_id"
		agentCols = "'', ''"
	}
	query := `WITH grouped AS (SELECT ` + session + ` AS sid, MIN(ts) AS first_seen, MAX(ts) AS last_seen, COUNT(*) AS count,
 SUM(CASE WHEN lower(policy_action) = 'deny' THEN 1 ELSE 0 END) AS denies,
 MAX(CASE WHEN owner_pid > 0 THEN id END) AS owner_id, ` + agentIDs + `,
 MAX(CASE WHEN json_valid(request_headers) THEN CASE WHEN json_extract(request_headers, '$."User-Agent"') <> '' THEN id END END) AS header_id,
 MAX(id) AS newest_id FROM network_requests GROUP BY sid HAVING sid <> '')
 SELECT g.sid, g.first_seen, g.last_seen, g.count, g.denies, COALESCE(o.owner_pid, 0), ` + agentCols + `,
 CASE WHEN json_valid(h.request_headers) THEN COALESCE(json_extract(h.request_headers, '$."User-Agent"'), '') ELSE '' END
 FROM grouped g LEFT JOIN network_requests o ON o.id = g.owner_id
 LEFT JOIN network_requests a ON a.id = g.agent_id LEFT JOIN network_requests c ON c.id = g.cwd_id
 LEFT JOIN network_requests h ON h.id = g.header_id ORDER BY g.newest_id DESC`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SessionSummary{}
	for rows.Next() {
		var row SessionSummary
		if err := rows.Scan(&row.SessionID, &row.FirstSeen, &row.LastSeen, &row.RequestCount, &row.DenyCount, &row.OwnerPID, &row.Agent, &row.Cwd, &row.UserAgent); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
