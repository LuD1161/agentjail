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
need. Decision rows contain store-redacted tool input that is too detailed for
the default session timeline but is the only durable source for reviewing the
complete recorded shell command from an explicitly opened action.

## Decision

The daemon control socket exposes three authenticated, versioned, bounded v1
projections:

- `network_snapshot` returns at most 200 newest traffic events from the typed
  `mitm.RequestStore`.
- `session_log_snapshot` returns at most 50 recent session summaries and 500
  newest decisions for one exact session identifier, stopping sooner when the
  serialized projection reaches 56 KiB.
- `session_action_detail` returns one exact decision from one exact session
  after the user opens that row.

The network projector owns one lazily opened read-only `network.db` handle. An
absent database is a normal typed state (`available: false`) and is retried on
the next poll, so installing the extension or starting the first protected
session does not require an app restart. The main `agentjail.db` continues to be
read only through the daemon's existing singleton `store.EventStore`.

Both projections are server-generated display models. Network events omit
headers, bodies, body paths, full URLs, and full working directories; request
query and fragment data are removed before projection. Session actions omit
general tool input and expose the store-redacted summary and bounded
policy/outcome metadata. Commands never enter the repeating snapshot. An action
detail request selects both exact decision ID and exact session ID, then a Bash
detail exposes only the `command` field parsed from the already-redacted
persisted JSON and capped at 4096 bytes. The timeline and detail queries use
exact identity rather than the CLI's historical substring filter.

The macOS app polls these small projections only while their destinations are
visible. The Network page separately consumes the existing setup-health model
to explain an absent or disabled Network Extension; the activity projection
does not claim installation authority.

## Consequences

- Swift receives no database path, SQLite dependency, control token value, raw
  request metadata, full project path, or unredacted tool input.
- Live refresh avoids spawning CLI processes and does not trigger dashboard
  token collection.
- The feed is a bounded recent window, not an unbounded transcript export. The
  UI says when an item or byte boundary truncates the projected rows.
- New projection fields require additive protocol evolution; incompatible
  changes require a new protocol version.
- The lazy network handle is closed with the daemon control server.
