# Linux CLI regression report

A self-contained HTML report for the **Linux/Lima** clean-VM run — the twin of
[`mac-cli-report/`](../mac-cli-report/). Every `agentjail` CLI command exercised,
each of the 15 scenarios with its own inline **asciinema player**, a summary
table that jumps to each scenario, and a findings section.

- **`index.html`** — open directly in a browser; fully self-contained (player
  JS/CSS inlined, every cast embedded as base64, no external requests).
- **`casts/*.cast`** — the raw asciinema recordings, one per scenario.

## How it was produced

Unlike the mac report (hand-assembled by mac-side tooling), this one is
generated end-to-end by two committed scripts:

- **`../record-cli-report.sh <testbed>`** records the 15 single-mode scenarios
  under `asciinema rec` inside a provisioned Lima guest and pulls the casts back.
- **`../gen-cli-report.sh <casts-dir> linux-cli-report`** derives every
  pass/fail/skip/finding count **live** from the recorded casts (it reconstructs
  the terminal stream from each cast's `o` events, strips ANSI, and counts the
  `PASS`/`FAIL`/`SKIP`/`FINDING` lines) and emits this `index.html`.

Re-generate the whole thing on a provisioned `linux-tour` testbed with:

```
./record-cli-report.sh linux-tour
```

## Recording notes

- The anti-self-approval guards (`mcp allow`/`block`, `skill ask`/`clear`,
  `policy disable`) open `/dev/tty` directly (`cmd/agentjail/confirm.go`) and
  block on a typed `y`. Under asciinema's PTY a controlling terminal exists, so
  those commands would hang. Each scenario is therefore recorded under
  **`setsid`** — a fresh session with **no controlling terminal** — so opening
  `/dev/tty` fails and agentjail refuses immediately, exactly as in headless CI.
  (macOS ships no `setsid`, which is why the mac side keeps its own recorder.)
- **`cli-tour` records last.** Its finale runs a real `agentjail uninstall`
  (the DEFECT-1 teardown), which removes `~/.agentjail`; recording it before the
  others would tear the install out from under them. The report still shows
  `cli-tour` first — display order is independent of capture order.

## Findings on Linux (dev-f83d1ef)

- **14 / 15 scenarios green** (128 pass · 1 fail · 10 skip).
- **Shield read gate is cwd-dependent (the 1 fail).** `agentjail run -- cat
  ~/.ssh/id_rsa` **blocks** the read from a project cwd (`run-shield` passes all
  5 checks) but **leaks** it from `$HOME` — the shield prints
  "sandbox ready … secured throughout" yet the key content is returned. macOS
  Seatbelt blocks in both contexts, so this is a Linux parity gap.
- **`agentjail-secrets` vault binary not shipped** (packaging gap, same as the
  mac's DEFECT-2). `cmd/agentjail-secrets` exists in source but the dist tarball
  ships only 5 binaries, so `secret set`/`remove` cannot function. Surfaced by
  the `secret` and `cli-tour` suites as a FINDING, not silently skipped.
