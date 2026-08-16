#!/usr/bin/env bash
# Emit bounded, non-body Darwin tunnel metadata for strict-smoke diagnosis.
set -euo pipefail

db="${AGENTJAIL_NETWORK_DB:-$HOME/.agentjail/network.db}"
[ -f "$db" ] || { printf 'network database is absent\n' >&2; exit 1; }
audit_db="${AGENTJAIL_AUDIT_DB:-$HOME/.agentjail/agentjail.db}"

printf '%s\n' '--- bounded request metadata'
sqlite3 -header -separator '|' "$db" '
select id, session_id, method, host, path, status_code,
       policy_action, policy_template
from network_requests
order by id desc
limit 12;
'

if [ -f "$audit_db" ]; then
    printf '%s\n' '--- bounded tunnel lifecycle'
    sqlite3 -header -separator '|' "$audit_db" '
select ts, event_type, session_id,
       coalesce(json_extract(detail, "$.failure_reason"), "") as failure_reason
from audit_log
where event_type in (
  "tunnel.extension_started", "tunnel.extension_stopped",
  "tunnel.session_registered", "tunnel.session_unregistered"
)
order by id desc
limit 24;
'
    printf '%s\n' '--- bounded host-proxy denials'
    sqlite3 -header -separator '|' "$audit_db" '
select id, event_type,
       coalesce(json_extract(detail, "$.reason"), "") as reason
from audit_log
where event_type = "host_proxy.denied"
order by id desc
limit 8;
'
fi
