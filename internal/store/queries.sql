-- name: InsertDecision :exec
INSERT INTO decisions (ts, session_id, agent, tool_name, summary, action, rule_id, reason, impact, elapsed_us, cwd, tool_input_redacted, would_action, policy_action, effective_action, adapter, translation_reason)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

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

-- Stats aggregates (agentjail stats). Each is scoped by `ts >= ?`; pass a zero
-- time formatted as RFC3339 for all-time. See AGE-213.

-- name: CountByActionSince :many
SELECT CASE lower(final_action)
    WHEN 'blocked' THEN 'deny'
    WHEN 'allowed' THEN 'allow'
    WHEN 'ask'     THEN 'ask'
    ELSE action
  END AS action,
  COUNT(*) AS count
FROM decisions
WHERE ts >= ?
GROUP BY 1
ORDER BY count DESC;

-- name: CountDenyRulesSince :many
SELECT rule_id, COUNT(*) AS count FROM decisions
WHERE COALESCE(NULLIF(policy_action, ''), action) = 'deny' AND ts >= ?
GROUP BY rule_id
ORDER BY count DESC;

-- name: CountByAgentSince :many
SELECT agent, COUNT(*) AS count FROM decisions
WHERE ts >= ? GROUP BY agent ORDER BY count DESC;

-- name: CountDistinctSessionsSince :one
SELECT COUNT(DISTINCT session_id) AS count FROM decisions WHERE ts >= ?;

-- name: CountAuditByTypeSince :many
SELECT event_type, COUNT(*) AS count FROM audit_log
WHERE ts >= ? GROUP BY event_type ORDER BY count DESC;

-- name: ListElapsedMicrosSince :many
SELECT elapsed_us FROM decisions
WHERE ts >= ? AND elapsed_us IS NOT NULL AND elapsed_us > 0
ORDER BY elapsed_us ASC;

-- name: DecisionDaysSince :many
SELECT CAST(substr(ts, 1, 10) AS TEXT) AS day, COUNT(*) AS count FROM decisions
WHERE ts >= ? GROUP BY day ORDER BY day ASC;

-- name: ShieldDaysSince :many
SELECT CAST(substr(ts, 1, 10) AS TEXT) AS day, COUNT(*) AS count FROM audit_log
WHERE event_type = 'shield.activated' AND ts >= ? GROUP BY day ORDER BY day ASC;

-- Cost index. All writes use these typed queries from the daemon-owned store;
-- CLI/UI callers use the same database through OpenReadOnly.

-- name: GetCostSourceCheckpoint :one
SELECT source, source_path, generation, file_identity, size_bytes, mtime_ns,
       offset_bytes, parser_version, parser_state_json, updated_ts
FROM cost_source_checkpoints
WHERE source = ? AND source_path = ?;

-- name: ListCostSourceCheckpoints :many
SELECT source, source_path, generation, file_identity, size_bytes, mtime_ns,
       offset_bytes, parser_version, parser_state_json, updated_ts
FROM cost_source_checkpoints
WHERE ? = '' OR source = ?
ORDER BY source ASC, source_path ASC;

-- name: UpsertCostSourceCheckpoint :exec
INSERT INTO cost_source_checkpoints
    (source, source_path, generation, file_identity, size_bytes, mtime_ns,
     offset_bytes, parser_version, parser_state_json, updated_ts)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(source, source_path) DO UPDATE SET
    generation = excluded.generation,
    file_identity = excluded.file_identity,
    size_bytes = excluded.size_bytes,
    mtime_ns = excluded.mtime_ns,
    offset_bytes = excluded.offset_bytes,
    parser_version = excluded.parser_version,
    parser_state_json = excluded.parser_state_json,
    updated_ts = excluded.updated_ts;

-- name: InsertCostUsageEvent :exec
INSERT INTO cost_usage_events
    (source, source_path, generation, event_key, session_id, parent_session_id,
     ts, agent, model, project, input_tokens, output_tokens, cache_read_tokens,
     cache_write_tokens, cache_write_5m_tokens, cache_write_1h_tokens,
     reasoning_tokens, request_input_tokens, request_output_tokens,
     request_cache_read_tokens, request_cache_write_tokens, has_request_usage,
     has_cache_ttl, recorded_cost_usd)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(source, source_path, generation, event_key) DO NOTHING;

-- name: DeleteCostUsageEventsGeneration :exec
DELETE FROM cost_usage_events
WHERE source = ? AND source_path = ? AND generation = ?;

-- name: DeleteCostDailyUsageGeneration :exec
DELETE FROM cost_daily_usage
WHERE source = ? AND source_path = ? AND generation = ?;

-- name: DeleteCostSourceCheckpointGeneration :exec
DELETE FROM cost_source_checkpoints
WHERE source = ? AND source_path = ? AND generation = ?;

-- name: DeleteCostDailyUsageGenerationDay :exec
DELETE FROM cost_daily_usage
WHERE source = ? AND source_path = ? AND generation = ? AND usage_day = ?;

-- name: DeleteAllCostDailyUsage :exec
DELETE FROM cost_daily_usage;

-- name: InsertCostDailyUsage :exec
INSERT INTO cost_daily_usage
    (usage_day, source, source_path, generation, session_id, started_ts, agent, model,
     project, input_tokens, output_tokens, cache_read_tokens,
     cache_write_tokens, cache_write_5m_tokens, cache_write_1h_tokens,
     reasoning_tokens, pricing_mode, pricing_revision, cost_usd, event_count)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListCostUsageEventsWindow :many
SELECT source, source_path, generation, event_key, session_id,
       parent_session_id, ts, agent, model, project, input_tokens,
       output_tokens, cache_read_tokens, cache_write_tokens,
       cache_write_5m_tokens, cache_write_1h_tokens, reasoning_tokens,
       request_input_tokens, request_output_tokens, request_cache_read_tokens,
       request_cache_write_tokens, has_request_usage, has_cache_ttl,
       recorded_cost_usd
FROM cost_usage_events
WHERE ts >= ? AND ts < ?
ORDER BY ts ASC, source ASC, session_id ASC, event_key ASC;

-- name: ListCostDailyUsageWindow :many
SELECT usage_day, source, source_path, generation, session_id, started_ts, agent, model,
       project, input_tokens, output_tokens, cache_read_tokens,
       cache_write_tokens, cache_write_5m_tokens, cache_write_1h_tokens,
       reasoning_tokens, pricing_mode, pricing_revision, cost_usd, event_count
FROM cost_daily_usage
WHERE started_ts >= ? AND started_ts < ?
ORDER BY usage_day ASC, source ASC, session_id ASC, model ASC;

-- name: CostIndexStatus :one
SELECT
    (SELECT COUNT(*) FROM cost_source_checkpoints) AS checkpoint_count,
    (SELECT COUNT(*) FROM cost_usage_events) AS event_count,
    (SELECT COUNT(*) FROM cost_daily_usage) AS daily_row_count,
    COALESCE((SELECT MAX(updated_ts) FROM cost_source_checkpoints), '') AS latest_update;
