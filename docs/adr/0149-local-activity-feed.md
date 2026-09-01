# ADR 0149: Local activity feed

Status: Accepted

## Context

The unified macOS app needs two read-only operational views: a live window of
intercepted network requests and the actions attributed to one AgentJail
session. The main event store already owns typed decisions and sessions. Network
history intentionally lives in the separate `network.db` store because the
interception path must not contend with the daemon event database.

Opening either SQLite file from Swift would duplicate schema knowledge and
bypass the repository's singleton store boundaries. Repeatedly launching the
CLI to simulate a live feed would add process startup latency every few seconds.
Adding the rows to the dashboard snapshot would also couple a fast activity
poll to the dashboard's slower token aggregation.

Network rows can contain request headers, captured-body references, full working
paths, URLs with query credentials, and other fields that an overview does not
need. Decision rows can contain redacted tool input that is still too detailed
for a default session timeline.

## Decision

The daemon control socket exposes two authenticated, versioned, bounded v1
projections:

- `network_snapshot` returns at most 200 newest traffic events from the typed
  `mitm.RequestStore`.
- `session_log_snapshot` returns at most 50 recent session summaries and 500
  newest decisions for one exact session identifier.

The network projector owns one lazily opened read-only `network.db` handle. An
absent database is a normal typed state (`available: false`) and is retried on
the next poll, so installing the extension or starting the first protected
session does not require an app restart. The main `agentjail.db` continues to be
read only through the daemon's existing singleton `store.EventStore`.

Both projections are server-generated display models. Network events omit
headers, bodies, body paths, full URLs, and full working directories; request
query and fragment data are removed before projection. Session actions omit
tool input and expose only the store-redacted summary and bounded policy/outcome
metadata. The session query uses an exact identifier rather than the CLI's
historical substring filter.

The macOS app polls these small projections only while their destinations are
visible. The Network page separately consumes the existing setup-health model
to explain an absent or disabled Network Extension; the activity projection
does not claim installation authority.

## Consequences

- Swift receives no database path, SQLite dependency, control token value, raw
  request metadata, full project path, or tool input.
- Live refresh avoids spawning CLI processes and does not trigger dashboard
  token collection.
- The feed is a bounded recent window, not an unbounded transcript export. The
  UI must say when a session contains more actions than the 500 projected rows.
- New projection fields require additive protocol evolution; incompatible
  changes require a new protocol version.
- The lazy network handle is closed with the daemon control server.
