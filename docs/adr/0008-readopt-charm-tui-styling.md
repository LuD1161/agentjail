# ADR 0008 — Re-adopt Charm TUI stack for styled installer/status output

- **Status:** Accepted (reverses the TUI-dependency removal implied by commit `0b34328`)
- **Date:** 2026-06-01
- **Deciders:** agentjail-core
- **Related:** commit `0b34328` (dropped bubbletea + charm); commit `e226bc5`; ADR 0007

## Context

`agentjail install` and `agentjail status` emitted plain, monochrome
`fmt.Println` output — a log dump rather than a polished security-tool UI.
Only the agent picker was interactive; everything else was unstyled.

### The `curl | sh` bug and what it actually was

Commit `0b34328` dropped `bubbletea` and the Charm libraries, citing a
silent-install-all bug triggered when the installer ran under `curl | sh`.
Investigation during the 2026-06-01 session established that this bug was a
**wrapper-contract bug, not a Bubble Tea or TTY-reading limitation**:

- The old picker already read input and output from `/dev/tty` correctly via
  `tea.NewProgram(m, tea.WithInput(tty), tea.WithOutput(tty))`, so the
  `curl | sh` pipe on stdin was never the issue.
- The real defect: `RunPicker` returned **all checked items** whenever the
  program exited for any reason other than an explicit user cancel. The model
  was initialized with every agent `Checked: true`, so any non-error early
  exit fell through to "install all." There was no distinction between "user
  pressed Enter to confirm" and "program quit without input."
- The fix that mattered — **confirm-only semantics** — is library-agnostic.
  Reverting to a hand-rolled picker did not eliminate the risk; it just moved
  it.

Current Bubble Tea (`v1.3.10`) additionally auto-opens `/dev/tty` when stdin
is not interactive, making it more robust than the version that was removed.

### Goal

Deliver colorful, consistent, visually polished output across both the
interactive picker and the linear install/status output, using a single shared
style authority so the two surfaces look identical.

## Decision

Re-adopt the **full Charm stack** for the TUI layer:

1. **`lipgloss`** — style the linear install + status output (header banners,
   `Section`/`Box`/`Table`/`Badge`/`Step` helpers) from a new
   `internal/ui` package that is the single source of visual truth. No other
   package may define ANSI codes or Lip Gloss styles directly.

2. **`bubbletea` + `bubbles`** — revert the agent picker to the Bubble Tea
   framework, styled via `internal/ui`.

The confirm-only contract is **non-negotiable and preserved**:
- Explicit Enter → return checked IDs.
- `q` / Ctrl-C → `ErrCancelled` (install nothing).
- Anything else → one of two distinct sentinels (see below); never
  install-all.

**Three distinct error sentinels** replace the former single `ErrNoTTY`
bucket, so the orchestrator can react correctly to each case:

| Sentinel | When | Orchestrator action |
|---|---|---|
| `ErrNoTTY` | `/dev/tty` could not be **opened** | Non-interactive fallback: install all detected agents (the safe guardrail for `curl \| sh` with no TTY) |
| `ErrCancelled` | User pressed `q` / Ctrl-C | Install nothing; exit 0 |
| `ErrAborted` | Abnormal failure after tty opened (raw-mode failure, `tea.Program.Run()` error, or program ended without a decision) | Print error to stderr; `os.Exit(1)`. **Never** install-all on an abnormal exit |

**Capability handling** treats color and glyphs as independent axes:
- `NO_COLOR` disables *color only*; glyphs stay Unicode.
- `TERM=dumb` or a non-UTF-8 locale downgrades glyphs and borders to ASCII.
- Detection lives in one function (`detectGlyphs()` in `internal/ui`),
  overridable in tests, and is the single place capability is decided.

**Untrusted-text sanitization** — dynamic strings from the filesystem (agent
display names, detection evidence, status notes) are run through a
`sanitize()` helper before styling: C0/C1 control characters and ESC sequences
are stripped; `\r`, `\n`, and `\t` are converted to spaces. Layout newlines
are added *after* sanitization by the renderer, so a crafted name or note
cannot inject extra rows or fake status lines.

**Pinned versions** in `go.mod` for the re-added modules (Codex requirement):
`github.com/charmbracelet/lipgloss`, `github.com/charmbracelet/bubbletea`,
`github.com/charmbracelet/bubbles`.

## Consequences

**Positive:**

- Linear install/status output is colorful and structured (branded header,
  section headings, aligned tables, colored badge pills) rather than a plain
  log dump.
- The picker and the linear output share a single palette from `internal/ui`
  — visually consistent and maintainable.
- Capability handling is explicit and tested across `NO_COLOR`, `TERM=dumb`,
  non-UTF-8 locale, and piped-writer profiles — no accidental regressions in
  CI or other non-interactive contexts.
- Dynamic text sanitization closes an ANSI-injection / row-spoofing vector
  that existed in the plain-string output as well.
- The three error sentinels make the fail-closed guarantee explicit and
  testable: `ErrAborted` can never trigger an install-all path.

**Negative:**

- Re-adds the dependencies removed in commit `0b34328`: `lipgloss`,
  `bubbletea`, `bubbles`, and their transitive tree (`muesli/termenv`,
  `mattn/go-runewidth`, `rivo/uniseg`, `lucasb-eyer/go-colorful`, etc.).
  This widens the supply-chain surface.
- Mitigations: versions are pinned in `go.mod`; the confirm-only contract +
  `ErrAborted` fail-closed sentinel ensure a TTY regression cannot silently
  install-all; `make licenses` regenerates `THIRD_PARTY_LICENSES` and is a
  CI gate.
- **Clean rollback path:** the picker (Bubble Tea) and the linear output
  styling (Lip Gloss) were committed separately. If a TTY regression surfaces
  in the picker, revert only the picker commit — the styled linear output is
  unaffected. A build-time feature flag was intentionally not added (YAGNI).

## Rejected alternative

**Lip Gloss only; keep the hand-rolled picker.** Lower dependency surface and
achieves most of the visual improvement. Declined because the user explicitly
chose the full Charm stack, and the confirm-only contract + distinct error
sentinels neutralize the main TTY-behavior risk that the previous hand-rolled
picker was meant to address.
