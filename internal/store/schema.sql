CREATE TABLE IF NOT EXISTS decisions (
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
    -- would_action: the verdict policy returned when it differs from `action`
    -- (monitor mode downgraded it). Empty means they matched. `action` is always
    -- what was ACTUALLY enforced -- it must never overstate enforcement.
    -- See ADR 0091-monitor-mode-tools.
    would_action       TEXT    NOT NULL DEFAULT '',
    policy_action      TEXT    NOT NULL DEFAULT '',
    effective_action   TEXT    NOT NULL DEFAULT '',
    adapter            TEXT    NOT NULL DEFAULT '',
    translation_reason TEXT    NOT NULL DEFAULT '',
    tool_use_id        TEXT    NOT NULL DEFAULT '',
    final_action       TEXT    NOT NULL DEFAULT '',
    enforcer           TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_decisions_session_ts ON decisions(session_id, ts);
CREATE INDEX IF NOT EXISTS idx_decisions_ts ON decisions(ts);
CREATE INDEX IF NOT EXISTS idx_decisions_action ON decisions(action);
CREATE INDEX IF NOT EXISTS idx_decisions_tool_name ON decisions(tool_name);
CREATE INDEX IF NOT EXISTS idx_decisions_rule_id ON decisions(rule_id);

CREATE TABLE IF NOT EXISTS audit_events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT    NOT NULL,
    action  TEXT    NOT NULL,
    rule_id TEXT,
    user    TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts);

CREATE TABLE IF NOT EXISTS sessions (
    session_id      TEXT PRIMARY KEY,
    start_ts        TEXT    NOT NULL,
    end_ts          TEXT,
    agent           TEXT,
    cwd             TEXT,
    decision_count  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS discovered_tools (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    server     TEXT    NOT NULL,
    tool       TEXT    NOT NULL,
    source     TEXT    NOT NULL,
    first_seen TEXT    NOT NULL,
    last_seen  TEXT    NOT NULL,
    UNIQUE(server, tool)
);

CREATE INDEX IF NOT EXISTS idx_discovered_tools_server ON discovered_tools(server);

CREATE TABLE IF NOT EXISTS discovered_skills (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL UNIQUE,
    source     TEXT    NOT NULL,
    first_seen TEXT    NOT NULL,
    last_seen  TEXT    NOT NULL,
    use_count  INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_discovered_skills_name ON discovered_skills(name);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT    NOT NULL,
    event_type TEXT    NOT NULL,
    entity     TEXT,
    detail     TEXT,
    actor      TEXT,
    session_id TEXT,
    ref_id     TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_log_entity ON audit_log(entity);
CREATE INDEX IF NOT EXISTS idx_audit_log_session ON audit_log(session_id);

-- Incremental local cost index. Parser state is metadata-only JSON; transcript
-- content is never persisted. See ADR 0142-incremental-cost-index.
CREATE TABLE IF NOT EXISTS cost_source_checkpoints (
    source            TEXT    NOT NULL,
    source_path       TEXT    NOT NULL,
    generation        TEXT    NOT NULL,
    file_identity     TEXT    NOT NULL,
    size_bytes        INTEGER NOT NULL,
    mtime_ns          INTEGER NOT NULL,
    offset_bytes      INTEGER NOT NULL,
    parser_version    INTEGER NOT NULL,
    parser_state_json TEXT    NOT NULL,
    updated_ts        TEXT    NOT NULL,
    PRIMARY KEY(source, source_path)
);

CREATE TABLE IF NOT EXISTS cost_usage_events (
    source                     TEXT    NOT NULL,
    source_path                TEXT    NOT NULL,
    generation                 TEXT    NOT NULL,
    event_key                  TEXT    NOT NULL,
    session_id                 TEXT    NOT NULL,
    parent_session_id          TEXT    NOT NULL DEFAULT '',
    ts                         TEXT    NOT NULL,
    agent                      TEXT    NOT NULL,
    model                      TEXT    NOT NULL,
    project                    TEXT    NOT NULL,
    input_tokens               INTEGER NOT NULL,
    output_tokens              INTEGER NOT NULL,
    cache_read_tokens          INTEGER NOT NULL,
    cache_write_tokens         INTEGER NOT NULL,
    cache_write_5m_tokens      INTEGER NOT NULL,
    cache_write_1h_tokens      INTEGER NOT NULL,
    reasoning_tokens           INTEGER NOT NULL,
    request_input_tokens       INTEGER NOT NULL,
    request_output_tokens      INTEGER NOT NULL,
    request_cache_read_tokens  INTEGER NOT NULL,
    request_cache_write_tokens INTEGER NOT NULL,
    has_request_usage          INTEGER NOT NULL,
    has_cache_ttl              INTEGER NOT NULL,
    recorded_cost_usd          REAL    NOT NULL,
    PRIMARY KEY(source, source_path, generation, event_key)
);

CREATE INDEX IF NOT EXISTS idx_cost_usage_events_ts ON cost_usage_events(ts);
CREATE INDEX IF NOT EXISTS idx_cost_usage_events_session ON cost_usage_events(source, session_id);
CREATE INDEX IF NOT EXISTS idx_cost_usage_events_project_ts ON cost_usage_events(project, ts);
CREATE INDEX IF NOT EXISTS idx_cost_usage_events_model_ts ON cost_usage_events(model, ts);

CREATE TABLE IF NOT EXISTS cost_daily_usage (
    usage_day         TEXT    NOT NULL,
    source            TEXT    NOT NULL,
    source_path       TEXT    NOT NULL,
    generation        TEXT    NOT NULL,
    session_id        TEXT    NOT NULL,
    started_ts        TEXT    NOT NULL,
    agent             TEXT    NOT NULL,
    model             TEXT    NOT NULL,
    project           TEXT    NOT NULL,
    input_tokens      INTEGER NOT NULL,
    output_tokens     INTEGER NOT NULL,
    cache_read_tokens INTEGER NOT NULL,
    cache_write_tokens INTEGER NOT NULL,
    cache_write_5m_tokens INTEGER NOT NULL,
    cache_write_1h_tokens INTEGER NOT NULL,
    reasoning_tokens  INTEGER NOT NULL,
    pricing_mode      TEXT    NOT NULL,
    pricing_revision  TEXT    NOT NULL,
    cost_usd          REAL    NOT NULL,
    event_count       INTEGER NOT NULL,
    PRIMARY KEY(usage_day, source, source_path, generation, session_id, model, project, pricing_mode, pricing_revision)
);

CREATE INDEX IF NOT EXISTS idx_cost_daily_usage_day ON cost_daily_usage(usage_day);
CREATE INDEX IF NOT EXISTS idx_cost_daily_usage_started_ts ON cost_daily_usage(started_ts);
CREATE INDEX IF NOT EXISTS idx_cost_daily_usage_project_day ON cost_daily_usage(project, usage_day);
CREATE INDEX IF NOT EXISTS idx_cost_daily_usage_model_day ON cost_daily_usage(model, usage_day);
CREATE INDEX IF NOT EXISTS idx_cost_daily_usage_session_day ON cost_daily_usage(source, session_id, usage_day);
