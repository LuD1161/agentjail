-- name: InsertDecision :exec
INSERT INTO decisions (ts, session_id, agent, tool_name, summary, action, rule_id, reason, impact, elapsed_us, cwd, tool_input_redacted, would_action)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: CountWouldBlockByRule :many
-- Monitor-mode report: what policy would have stopped, grouped by rule. Rows
-- where would_action is empty are enforce-mode decisions and are excluded.
-- See ADR 0091-monitor-mode-tools.
SELECT rule_id, would_action, tool_name, COUNT(*) AS count
FROM decisions
WHERE would_action != '' AND ts >= ?
GROUP BY rule_id, would_action, tool_name
ORDER BY count DESC;

-- name: UpsertSession :exec
INSERT INTO sessions (session_id, start_ts, end_ts, agent, cwd, decision_count)
VALUES (?, ?, ?, ?, ?, 1)
ON CONFLICT(session_id) DO UPDATE SET
    end_ts = excluded.end_ts,
    agent = COALESCE(excluded.agent, sessions.agent),
    cwd = COALESCE(excluded.cwd, sessions.cwd),
    decision_count = sessions.decision_count + 1;

-- name: GetDecisionCount :one
SELECT COUNT(*) FROM decisions;

-- name: ListAllSessions :many
SELECT session_id, start_ts, end_ts, agent, cwd, decision_count FROM sessions ORDER BY start_ts DESC;

-- name: CountActionsBySession :many
-- Counts the FINAL outcome (ADR 0112): a policy verdict the OS sandbox
-- overrode is counted as what actually happened, mapped back to the
-- allow/deny/ask vocabulary the totals use. Rows with no observed final
-- outcome fall back to the policy action.
SELECT session_id,
  CASE lower(final_action)
    WHEN 'blocked' THEN 'deny'
    WHEN 'allowed' THEN 'allow'
    WHEN 'ask'     THEN 'ask'
    ELSE action
  END AS action,
  COUNT(*) AS count
FROM decisions GROUP BY session_id, 2;

-- name: DeleteOldDecisions :exec
DELETE FROM decisions WHERE ts < ?;

-- name: DeleteOldSessions :exec
DELETE FROM sessions WHERE start_ts < ?;

-- name: ListDistinctCWDs :many
SELECT DISTINCT cwd FROM sessions WHERE cwd IS NOT NULL AND cwd != '' ORDER BY cwd;

-- name: ListDistinctMCPToolNames :many
SELECT DISTINCT tool_name FROM decisions WHERE tool_name LIKE 'mcp__%' ORDER BY tool_name;

-- name: ListDistinctSkillInputs :many
SELECT DISTINCT tool_input_redacted FROM decisions WHERE tool_name = 'Skill' AND tool_input_redacted IS NOT NULL AND tool_input_redacted != '';

-- name: UpsertDiscoveredTool :exec
INSERT INTO discovered_tools (server, tool, source, first_seen, last_seen)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(server, tool) DO UPDATE SET
    last_seen = excluded.last_seen,
    source = excluded.source;

-- name: UpsertDiscoveredSkill :exec
INSERT INTO discovered_skills (name, source, first_seen, last_seen, use_count)
VALUES (?, ?, ?, ?, 1)
ON CONFLICT(name) DO UPDATE SET
    last_seen = excluded.last_seen,
    source = excluded.source,
    use_count = use_count + 1;

-- name: ListDiscoveredToolsAll :many
SELECT id, server, tool, source, first_seen, last_seen FROM discovered_tools ORDER BY server, tool;

-- name: ListDiscoveredToolsByServer :many
SELECT id, server, tool, source, first_seen, last_seen FROM discovered_tools WHERE server = ? ORDER BY tool;

-- name: ListDiscoveredSkillsAll :many
SELECT id, name, source, first_seen, last_seen, use_count FROM discovered_skills ORDER BY name;

-- name: InsertAuditLog :exec
INSERT INTO audit_log (ts, event_type, entity, detail, actor, session_id, ref_id)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListAuditLogByEntity :many
SELECT id, ts, event_type, entity, detail, actor, session_id, ref_id
FROM audit_log WHERE entity = ? ORDER BY ts DESC LIMIT ?;

-- name: ListAuditLogByType :many
SELECT id, ts, event_type, entity, detail, actor, session_id, ref_id
FROM audit_log WHERE event_type = ? ORDER BY ts DESC LIMIT ?;

-- name: ListAuditLogBySession :many
SELECT id, ts, event_type, entity, detail, actor, session_id, ref_id
FROM audit_log WHERE session_id = ? ORDER BY ts DESC LIMIT ?;

-- name: ListAuditLogRecent :many
SELECT id, ts, event_type, entity, detail, actor, session_id, ref_id
FROM audit_log ORDER BY ts DESC LIMIT ?;

-- name: DeleteOldAuditLog :exec
DELETE FROM audit_log WHERE ts < ?;

