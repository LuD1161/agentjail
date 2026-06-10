# Telemetry

agentjail collects **anonymous, opt-out** usage statistics to help us decide what
to improve. This page documents exactly what is and isn't sent, how to see it, and
how to turn it off. If you ever find this page out of date relative to the code,
the source of truth is [`internal/telemetry/event.go`](../internal/telemetry/event.go) —
every field below is constructed there and nowhere else.

## TL;DR

- **Anonymous.** Tied to a random ID generated once on your machine — never your
  name, hostname, username, IP, or any hardware fingerprint.
- **No payloads, ever.** We never send file paths, command text, repo names,
  environment contents, MCP server names, or policy contents.
- **Opt out anytime:**
  ```sh
  agentjail telemetry disable
  # or, per-shell / in CI / in a Dockerfile:
  export AGENTJAIL_SEND_ANONYMOUS_USAGE_STATS=false
  ```
- **Off automatically in CI** (`CI=true` and common CI env vars).
- **See exactly what's queued to send:** `agentjail telemetry view`

## Why we collect it

We want to know which agents people protect, which guardrails actually fire, and
whether the daemon stays fast in the field — so we can prioritize the right work.
None of that requires knowing anything about *you* or *what you're protecting*, so
we don't collect it.

## Controlling telemetry

| Command | What it does |
|---|---|
| `agentjail telemetry status` | Show whether it's on/off and *why* (env var, CI, config, or default), plus your anonymous ID |
| `agentjail telemetry disable` | Turn it off (persisted) |
| `agentjail telemetry enable` | Turn it back on |
| `agentjail telemetry view` | Print the exact JSON currently queued to be sent |
| `agentjail telemetry reset` | Generate a new anonymous ID and clear the queue |

**Resolution order** (first match wins): the `AGENTJAIL_SEND_ANONYMOUS_USAGE_STATS`
env var → CI auto-detection → your `~/.agentjail/telemetry.json` setting → default
(on). The env var accepts `false`/`0`/`no` to disable and `true`/`1`/`yes` to enable.

## Exactly what is sent

Every event carries three common properties:

| Property | Example | Meaning |
|---|---|---|
| `distinct_id` | `"3f9c…"` | Your random anonymous ID (from `~/.agentjail/telemetry.json`) |
| `$insert_id` | `"a1b2…"` | A per-event UUID used only to de-duplicate retried sends |
| `agentjail_version` | `"0.1.0"` | The agentjail version |

The event types are grouped below. **Lifecycle events** (`install`, `uninstall`,
`update`) are sent **immediately and synchronously** the moment they happen — they
do not wait for the daemon's batched flush — so they're captured even if the daemon
never runs or you uninstall moments later. Everything else is spooled locally and
delivered by the daemon (see [How it's delivered](#how-its-delivered)).

### `install` — emitted once, immediately after a successful install
| Property | Example | Notes |
|---|---|---|
| `os` | `"darwin"` / `"linux"` | |
| `arch` | `"arm64"` / `"amd64"` | |
| `install_method` | `"curl"` / `"brew"` | Optional; how agentjail was installed; omitted if unknown |
| `agents` | `["claude-code","cursor"]` | Optional; the agent enums whose hooks were wired |
| `agents_detected` | `3` | How many supported agents were found on the machine (a count) |

### `uninstall` — emitted immediately before a full teardown
Sent **before** `~/.agentjail` is removed, so we can see churn.
| Property | Example | Notes |
|---|---|---|
| `os` | `"darwin"` / `"linux"` | |
| `arch` | `"arm64"` / `"amd64"` | |

### `update` — emitted when you run `agentjail update`
| Property | Example | Notes |
|---|---|---|
| `from_version` | `"0.1.0"` | The version you updated from |
| `to_version` | `"0.2.0"` | The version you updated to |
| `os` | `"darwin"` / `"linux"` | |
| `arch` | `"arm64"` / `"amd64"` | |

### `session_start` — emitted when the daemon starts
| Property | Example | Notes |
|---|---|---|
| `os` | `"darwin"` / `"linux"` | |
| `arch` | `"arm64"` / `"amd64"` | |
| `install_method` | `"curl"` / `"brew"` | Optional; omitted if unknown |

### `feature_used` — emitted when you run a CLI command
| Property | Example | Notes |
|---|---|---|
| `command` | `"install"`, `"logs"`, `"policy"`, `"other"` | A fixed enum. Unknown commands collapse to `"other"` — your arguments are **never** recorded |
| `agents` | `["claude","codex"]` | Optional; a fixed enum of supported agent names |

### `decision_rollup` — aggregated policy decisions for a window (not per-decision)
| Property | Example | Notes |
|---|---|---|
| `action_counts` | `{"allow":120,"deny":3,"ask":1}` | Counts only |
| `rule_counts` | `{"command_policy/rm_rf":3}` | Keys are **rule IDs** — never the matched path/command/repo, but they include your **custom rules' IDs verbatim** (e.g. `custom/<your-name>/<rule>`), so we can see what custom rules people write. See [Custom rule names](#a-note-on-custom-rule-names) below |
| `rule_action_counts` | `{"deny\|command_policy/rm_rf":3}` | Optional; the same counts keyed by `"action\|rule_id"`, so we can see which rules deny vs ask vs allow |
| `tool_counts` | `{"Bash":80,"Edit":40}` | Optional; decisions per tool name (the agent tool enum — never tool arguments) |
| `agent_counts` | `{"cursor":12}` | Optional; decisions per agent identity, when the agent reports one |
| `spool_dropped` | `2` | Optional; how many queued events were dropped if the local queue overflowed |

### `perf_rollup` — aggregated daemon performance for a window
| Property | Example | Notes |
|---|---|---|
| `eval_p50_ms` | `0.4` | Median policy-eval latency |
| `eval_p95_ms` | `1.8` | p95 policy-eval latency |
| `restarts` | `0` | Reserved — always `0` in v0.1.0 (daemon restart tracking not yet wired) |

### `policy_config` — your policy configuration, at daemon start and on reload
Shows what you've configured (intent), as opposed to what fired (`decision_rollup`).
| Property | Example | Notes |
|---|---|---|
| `custom_rule_count` | `2` | How many custom rules you've added (a count; rule *contents* are never sent) |
| `disabled_rules` | `["command_policy/confirm-publish"]` | Which rules you've turned off — your disabled-rules list verbatim, which may include custom rule IDs |

### `fail_open` — emitted when the hook fails open
Security-relevant: if the hook can't reach or parse a daemon decision, it **allows**
the action (fails open) rather than blocking your work — and reports that it did so.
| Property | Example | Notes |
|---|---|---|
| `os` | `"darwin"` | |
| `reason` | `"dial-daemon"` | A fixed enum for *why* it failed open (`dial-daemon`, `read-response`, `parse-response`, `read-stdin`, `parse-input`, `other`) — never the tool input |

### `heartbeat` — best-effort, at most once per ~24h on a CLI run
Emitted by the throttled update-check when you run a CLI command. Best-effort (it may
not send on very short-lived invocations); version currency is also derivable from the
`agentjail_version` on every other event.
| Property | Example | Notes |
|---|---|---|
| `os` | `"darwin"` | |
| `latest_version` | `"0.2.0"` | The latest release seen by the update check; `""` if the check didn't complete |
| `update_available` | `true` | Whether a newer version is available |

### `feedback` — only when you run `agentjail feedback`
Emitted **solely** when you explicitly run the command (see below). Never automatic.
| Property | Example | Notes |
|---|---|---|
| `message` | `"the publish guard is too aggressive"` | Exactly the text you typed |
| `contact` | `"me@example.com"` | Optional; only what you typed, omitted if you skip it |
| `os` | `"darwin"` | |

### Example payload

A real `decision_rollup` looks like this — and this is the *entirety* of what
leaves your machine for that event:

```json
{
  "event": "decision_rollup",
  "properties": {
    "distinct_id": "3f9c2a7e-8b1d-4c5a-9e2f-1a2b3c4d5e6f",
    "$insert_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "agentjail_version": "0.1.0",
    "action_counts": { "allow": 120, "deny": 3, "ask": 1 },
    "rule_counts": { "command_policy/rm_rf": 3, "file_policy/ssh_key_read": 1 }
  }
}
```

## What is **never** sent

File paths · command text · repository names or URLs · environment variable
contents · MCP server names · policy file contents · IP addresses · hostnames ·
usernames · timestamps finer than the day · any hardware identifier.

This isn't a promise enforced by review alone: telemetry events are built from
fixed Go structs in `event.go`, never by serializing arbitrary data, so a payload
**cannot** be attached by accident.

## A note on custom rule names

We **do** send the **IDs of your custom rules** (e.g. `custom/<name>/<rule>`) in
`rule_counts` and your `disabled_rules` list, so we can understand what kinds of
custom rules people build and prioritize accordingly. We do **not** send the
*contents* of any rule, nor the paths/commands they match.

If you'd rather not share custom rule IDs, name your rules generically, or turn
telemetry off entirely with `agentjail telemetry disable` (or
`AGENTJAIL_SEND_ANONYMOUS_USAGE_STATS=false`). Run `agentjail telemetry view` to
see exactly what's queued before anything is sent.

## Sending feedback

```sh
agentjail feedback "the publish guard fires too often"
# or run it with no message and it'll prompt you, plus an optional contact
```

`agentjail feedback` sends a one-off `feedback` event with your message, an optional
contact you may provide, your OS, version, and the random anonymous ID. Because it's
an explicit action you took, it sends **even if usage telemetry is disabled** — and
it never includes anything beyond what you typed plus version/OS. If the build has no
backend configured, it prints a GitHub issue link instead.

## How it's delivered

Most events are aggregated/queued locally and delivered by the daemon in a single
batched HTTPS request. The daemon flushes shortly after it starts (a couple of
minutes, so short-lived daemons still report) and then roughly every 6 hours, plus
on graceful shutdown. CLI commands only write a local event to
`~/.agentjail/telemetry-spool.jsonl`, which the daemon picks up on its next flush.

The exception is the **lifecycle events** (`install`, `uninstall`, `update`) and
`feedback`: because they describe one-off moments that may happen when no daemon is
running (or right before teardown), the CLI sends them **immediately and
synchronously** over a single HTTPS request, rather than waiting for the daemon
flush. If you're offline or a send fails, spooled events stay queued and are retried
later; the local queue is capped so it can't grow without bound.

## Backend

We currently use **PostHog** (US cloud, `us.i.posthog.com`) as our analytics
backend. This may change; the data we send — listed above — will not. The
telemetry host is included in the default `agentjail-netproxy` egress allowlist so
agentjail doesn't block its own telemetry — you're free to remove it.

## Files (all under `~/.agentjail/`)

- `telemetry.json` — your consent setting + anonymous ID (mode 0600)
- `telemetry-spool.jsonl` — events queued to send
- `telemetry-spool.dropped` — counter of dropped events (if the queue overflowed)
- `telemetry-rollup.partial.json` — in-progress decision counts (crash-recovery checkpoint)

Deleting these is harmless; they're recreated as needed.
