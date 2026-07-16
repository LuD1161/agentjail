// types.ts -- shared TypeScript types mirroring the Go JSON shapes served by
// cmd/agentjail/ui. Keep in sync with:
//   - internal/mitm/store.go (RequestLog, SessionInfo)
//   - cmd/agentjail/ui/state.go (EvalLine, SessionState, StateSnapshot)

/** Mirrors internal/mitm.RequestLog (GET /api/requests, /api/requests/:id, SSE /api/requests/stream). */
export interface RequestLog {
  id: number
  ts: string
  host: string
  method: string
  path: string
  url: string
  status_code?: number
  request_size?: number
  response_size?: number
  elapsed_ms?: number
  request_headers?: Record<string, string> | null
  response_headers?: Record<string, string> | null
  request_body?: string
  response_body?: string
  body_truncated?: boolean
  error?: string
  session_id?: string
  tool_name?: string
  policy_action?: string
  policy_template?: string
  policy_reason?: string
  service?: string
  verb?: string
  resource_type?: string
}

/** Mirrors internal/mitm.SessionInfo (GET /api/network/sessions). */
export interface SessionInfo {
  session_id: string
  first_seen: string
  last_seen: string
  request_count: number
}

/** Mirrors cmd/agentjail/ui.EvalLine (GET /api/state, SSE /events). */
export interface TimelineEvent {
  time: string
  level: string
  msg: string
  req_id?: string
  tool?: string
  session_id?: string
  agent?: string
  cwd?: string
  summary?: string
  action?: string
  rule_id?: string
  reason?: string
  impact?: string
  elapsed_us?: number
  tool_input_redacted?: string
  err?: string
}

/** Mirrors cmd/agentjail/ui.SessionState (part of GET /api/state). */
export interface DaemonSessionState {
  id: string
  agent?: string
  cwd?: string
  branch?: string
  repo_name?: string
  first_seen: string
  last_seen: string
  active: boolean
  total: number
  allow: number
  deny: number
  ask: number
  last_event?: string
}

/** Mirrors cmd/agentjail/ui.SourceStatus. */
export interface SourceStatus {
  kind: string
  path: string
  live_path?: string
  fallback: boolean
  warning?: string
  modified_at?: string
}

/** Mirrors cmd/agentjail/ui.StateSnapshot (GET /api/state). */
export interface StateSnapshot {
  sessions: DaemonSessionState[]
  recent_events: TimelineEvent[]
  total_allow: number
  total_deny: number
  total_ask: number
  total_decisions: number
  filtered_count: number
  source: SourceStatus
}

/** Rule info from GET /api/rules. */
export interface RuleInfo {
  name: string
  source: string
  enabled: boolean
  editable: boolean
}
