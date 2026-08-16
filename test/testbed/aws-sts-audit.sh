#!/usr/bin/env bash
set -euo pipefail
manifest="${1:-/tmp/agentjail-aws-sts-handoff.json}"
output="${2:-/tmp/testbed/results/aws-sts-live.audit.json}"
db="$HOME/.agentjail/agentjail.db"
credential="$(jq -r .credential_name "$manifest")"
session="$(sqlite3 "$db" "select session_id from audit_log where actor='codex' and event_type='credential.access_issued' and entity='$credential' order by id desc limit 1;")"
[ -n "$session" ]
sqlite3 -json "$db" "select id,ts,event_type,entity,actor,session_id,detail from audit_log where session_id='$session' and event_type in ('credential.session_registered','credential.listed','credential.access_requested','credential.access_approved','credential.access_issued','credential.session_revoked') order by id;" >"$output"
chmod 0600 "$output"
