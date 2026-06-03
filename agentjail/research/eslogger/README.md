# eslogger spike

Install + capture spike for macOS `eslogger(1)`. NOTIFY-only Endpoint Security
events, used as a tamper-evidence cross-check against the user-space PATH
shim. We will never run AUTH from `eslogger` (it does not support AUTH events;
see manpage's "By design, eslogger does not support any auth events").

This is a spike. Wire-up into the daemon is a follow-on task.

## Files

| Path | Purpose |
|---|---|
| `capture.sh` | 20-line bash: subscribes to `exec` + `fork` + `exit`, writes JSON Lines |
| `samples/exec-sample.jsonl` | Sanitized structure-reference sample (4 events) |

## Requirements

- macOS (tested intent: arm64, macOS 14+)
- `/usr/bin/eslogger` (ships with macOS since Ventura)
- Root: `sudo` (Endpoint Security clients require superuser)
- TCC Full Disk Access for the responsible process (Terminal.app, iTerm, etc.).
  See `man eslogger` § TCC AUTHORIZATION.

## Usage

```sh
sudo ./capture.sh 30 samples/my-capture.jsonl
```

Then, in another terminal, generate some events:

```sh
ls /; cat /etc/hosts; /bin/echo hi
```

Stop after `SECS` seconds; one JSON Lines file results.

## Why these events

`exec` is the load-bearing signal for the shim-vs-ES diff. `fork`
gives us parent/child reconstruction (PATH shim sees argv, not the kernel-
level fork). `exit` lets us close the lifecycle so the daemon can match
windows without unbounded retention.

We skip the noisier classes (`mmap`, `open`, `close`, `lookup`) for the spike
— they easily dominate event volume and are not needed for tamper-evidence
of exec-class actions.

## Sample is synthetic (sanitized)

The committed `samples/exec-sample.jsonl` is a **structure-reference** sample,
not a live capture. The collecting agent for this spike did not have sudo in
its sandbox. The structure matches Apple's `es_message_t` JSON projection at
`schema_version: 1` (per `man eslogger` and the public example pipeline
`eslogger exec | jq -r 'select(.process.executable.path == "/bin/zsh")|...'`).
Field names, types, and nesting are stable enough to develop the daemon parser against.

A future run on a real laptop should replace `samples/exec-sample.jsonl`
with a live, sanitized capture (strip `/Users/<name>/`, team IDs, cdhashes).
See "Sanitization checklist" below.

## Sanitization checklist

Before committing a real capture, replace:

- `/Users/<actual-username>/` → `/Users/REDACTED/`
- `team_id` values → `"REDACTED_TEAMID"`
- `cdhash` / `cdhash_str` → `"REDACTED_CDHASH_40HEX"`
- Strip any in-`env` values matching `*KEY*`, `*TOKEN*`, `*SECRET*`, `*PASS*`
- Strip any `args` containing the same patterns

A simple `jq` pipeline can do this — defer until the daemon wire-up needs it.

## See also

- `man eslogger`, `man EndpointSecurity` (man 7)
- `tasks/findings/` — volume estimate, format notes, NOTIFY-only rationale
