-- name: InsertDecision :exec
INSERT INTO decisions (ts, session_id, agent, tool_name, summary, action, rule_id, reason, impact, elapsed_us, cwd, tool_input_redacted)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpsertSession :exec
INSERT INTO sessions (session_id, start_ts, end_ts, agent, cwd, decision_count)
VALUES (?, ?, ?, ?, ?, 1)
ON CONFLICT(session_id) DO UPDATE SET
    end_ts = excluded.end_ts,
    agent = COALESCE(excluded.agent, sessions.agent),
    cwd = COALESCE(excluded.cwd, sessions.cwd),
    decision_count = sessions.decision_count + 1;

-- name: InsertAuditEvent :exec
INSERT INTO audit_events (ts, action, rule_id, user) VALUES (?, ?, ?, ?);

-- name: GetDecisionCount :one
SELECT COUNT(*) FROM decisions;

-- name: ListAllSessions :many
SELECT session_id, start_ts, end_ts, agent, cwd, decision_count FROM sessions ORDER BY start_ts DESC;

-- name: CountActionsBySession :many
SELECT session_id, action, COUNT(*) AS count FROM decisions GROUP BY session_id, action;

-- name: DeleteOldDecisions :exec
DELETE FROM decisions WHERE ts < ?;

-- name: DeleteOldAuditEvents :exec
DELETE FROM audit_events WHERE ts < ?;

-- name: DeleteOldSessions :exec
DELETE FROM sessions WHERE start_ts < ?;
