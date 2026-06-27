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
    tool_input_redacted TEXT
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
