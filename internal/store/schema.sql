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
    -- See ADR 0091-monitor-mode-tool-calls.
    would_action    TEXT    NOT NULL DEFAULT ''
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
