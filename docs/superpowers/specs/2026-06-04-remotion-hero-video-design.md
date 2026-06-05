# Design Spec — Remotion hero video (landing-page loop)

**Date:** 2026-06-04
**Status:** Approved (brainstorming → spec)
**Owner:** Aseem
**Related:** `README.md` (scenario table, install one-liner), install-UI style
(terracotta accent on dark, semantic green/yellow/red badges)

## Goal

A short, autoplay-muted, seamlessly-looping hero video for the agentjail
landing page / README top that makes a first-time viewer understand the product
in one watch: *you're working in your coding agent, the agent tries to do
something dangerous, agentjail blocks it before it fires, and a live log shows
the block as it happens.*

Success = a viewer who has never heard of agentjail watches the loop once and
can say "oh — it stops my agent from doing dangerous stuff, and I can see it
working."

## Constraints

- **Length:** ~20s, seamless loop (last frame crossfades into first).
- **No audio / no narration** — autoplay-muted on the web; everything is
  conveyed visually.
- **Legible at hero size** and degraded thumbnail/poster size.
- **Honesty rule (hard):** every verdict string shown on screen is copied
  verbatim from a real `agentjail try` / `agentjail logs` run. We never display
  a DENY the real tool would not produce. Both denial beats use the shipped
  default rule `file_policy/sensitive_credential`.
- **Isolation:** the video project must not touch the Go build, `internal/`,
  `cmd/`, or any security surface. It lives in its own workspace with its own
  `node_modules` (gitignored).

## Audience & venue

Primary: landing-page hero + README top. Secondary reuse: the same render
(or its gif poster) can be dropped into social posts. Designed wordless so it
works in both contexts without a soundtrack.

## Chosen approach

**Synthetic terminal rendered in Remotion, sourcing real strings.**

- The terminal panes are React components, not screen recordings. Commands type
  out char-by-char with a blinking cursor; the DENY stamp and the log line
  animate in under our control. This gives deterministic timing, a pixel-perfect
  seamless loop, and trivial restyling.
- To stay honest, every on-screen verdict line is copy-pasted from real runs of
  `agentjail try "<cmd>"` and `agentjail logs` (the C-in-"hybrid" technique):
  synthetic rendering, real text.

Rejected alternatives:
- **Record real CLI (asciinema) and composite** — most authentic, but real
  output is verbose and hard to time to a tight 20s loop, and seamless looping
  is much harder. Used only as the *source of truth* for exact strings.
- **Fully authored text with no real source** — rejected; violates the honesty
  rule.

## Composition layout

Single Remotion composition, 1920×1080, 30fps, ~600 frames (~20s).

Two-pane stage for the denial beats:

```
┌──────────────────────────────────────────────┬───────────────────────────┐
│  ◤ Claude Code — ~/acme-api                   │  agentjail logs ▸ watching │
│  › clean up my Downloads, it's huge           │  TIME     ACTION  TOOL    │
│  ● I'll clear out the contents.               │  19:24:01 ✓ALLOW  Bash    │
│    ⏺ Bash(rm -rf ~/Downloads/*)               │  19:24:03 ✓ALLOW  Read    │
│      ✗ Blocked by agentjail                   │  ┌─────────────────────┐  │
│        DENY · file_policy/sensitive_credential│  │19:24:07 ✗DENY  Bash │◀─┐│
│  ● That's blocked by your policy — I won't    │  │ sensitive path      │  ││
│    touch those files.                         │  │ ↳ rm -rf ~/Downloads│  ││
│                                               │  └─────────────────────┘  ││
│                                               │  🟢 4 ·  🔴 1 ·  🟡 0     ││
└──────────────────────────────────────────────┴───────────────────────────┘┘
   agentjail · your agent literally can't do that · curl -fsSL …/install.sh | sh
```

- Left pane ≈ 62% width: Claude Code TUI session.
- Right pane ≈ 38% width: a terminal tailing `agentjail logs`.
- **The signature beat is the sync:** the frame the inline `✗ Blocked` lands in
  the left pane, the matching red `DENY` row slides into the right pane and the
  counter ticks. That visual coupling is the product.
- Background: dark (install-UI dark), terracotta accent, semantic green/red.

## Timeline (~20s, 30fps)

| Beat | Frames (approx) | Content |
|------|-----------------|---------|
| Settle-in | 0–30 | Both panes fade in; logs pane shows two prior `✓ALLOW` rows. |
| **Beat 1 — Foot-gun** | 30–210 | User: "clean up my Downloads, it's huge". Agent types `rm -rf ~/Downloads/*`. Inline `✗ Blocked by agentjail · DENY · file_policy/sensitive_credential`. Synced red row slides into logs pane; counter → `🔴 1`. Agent recovers in one line. |
| **Beat 2 — Secret exfil** | 210–390 | User: "summarize my project for an LLM". Agent types `cat .env ~/.aws/credentials`. Inline DENY (same rule). Second red row stacks; counter → `🔴 2`. |
| **Beat 3 — Endless possibilities** | 390–540 | Panes dissolve into a centered card: headline **"Write a policy for anything."**, a staggered float-in of monochrome logos (aws, k8s, docker, github, stripe, twilio, npm, slack, gcp), then tagline + `curl … | sh`. |
| Loop seam | 540–600 | Install card holds, then crossfades back into the Beat-1 settle-in frame. |

Frame numbers are a starting point for the implementation plan, not contractual;
final timing is tuned by watching renders.

## Component breakdown

Each component has one job, a typed props interface, and is renderable in
isolation (so it can be previewed in the Remotion Studio sidebar):

- `<Stage>` — root composition; sequences the beats, owns the dark background,
  brand palette tokens, and the loop crossfade.
- `<ClaudeCodePane>` — renders a Claude Code session from a typed transcript
  (user prompt, assistant lines, a tool-call block, an inline block result).
  Props: `transcript`, `revealUpToFrame`.
- `<LogsPane>` — renders the `agentjail logs` table; rows append on cue. Props:
  `rows`, `counters`, `appendSchedule`.
- `<Typewriter>` — char-by-char reveal with blinking cursor, driven by frame.
- `<DenyStamp>` — the inline `✗ Blocked … DENY · <rule>` treatment with a
  spring-in. Props: `rule`, `enterFrame`.
- `<LogoMontage>` — staggered float-in grid of simple-icons SVGs, brand-tinted.
  Props: `icons`, `stagger`.
- `<InstallCard>` — headline + tagline + `curl | sh` line.

Shared data: a single `script.ts` holding the typed transcripts and the exact
log rows (sourced from real runs) so the "honesty rule" has one source of truth.

## Assets

- **Logos:** `simple-icons` (npm) — monochrome SVG paths, tinted at render time.
  Nominative use to indicate "you can write policies governing these tools."
  Set: aws, kubernetes, docker, github, stripe, twilio, npm, slack,
  googlecloud (final set tunable).
- **Fonts:** a monospace for the terminals (e.g. the repo/brand mono) loaded via
  `@remotion/fonts` for deterministic rendering.
- **Palette:** reuse the install-UI tokens (dark bg, terracotta accent,
  semantic green `✓ALLOW` / red `✗DENY` / yellow `ASK`).

## Project location & tooling

- New workspace at repo-root **`video/`** (sibling of `cmd/`, `docs/`), with its
  own `package.json`, `node_modules` (gitignored), and Remotion config.
- Stack: Remotion + React + TypeScript. `npm run preview` opens Remotion Studio;
  `npm run render` outputs to `video/out/`.
- Outputs: `agentjail-hero.mp4` (H.264), `agentjail-hero.webm` (VP9, web hero),
  and a poster `agentjail-hero.gif` (or static poster frame).
- A short `video/README.md` documents preview/render and where to refresh the
  real log strings.
- `.gitignore`: add `video/node_modules/` and `video/out/`.

## Verification / acceptance

This is judged by watching, not by unit tests. Acceptance criteria for the plan:

1. `npm run preview` opens Remotion Studio showing the composition without error.
2. `npm run render` produces `agentjail-hero.mp4`, `.webm`, and the poster, each
   ~20s, no render warnings.
3. **Legibility:** at 1280px-wide playback every terminal line and the install
   one-liner are readable; the poster frame is recognizable as "agent blocked."
4. **Seamless loop:** played on repeat, the seam (frame 600→0) shows no visible
   jump or flash.
5. **Honesty:** every verdict string in `script.ts` matches the output of the
   corresponding real `agentjail try` / `agentjail logs` run (documented in
   `video/README.md`).
6. **Isolation:** `go build ./... && go vet ./... && go test ./...` are
   unaffected (no Go files touched); `video/node_modules` and `video/out` are
   gitignored.

## Out of scope (YAGNI)

- Narration / voiceover / soundtrack.
- A longer (60–90s) deep-dive cut — can reuse these components later.
- Install→try CLI walkthrough as its own beat (the install one-liner lives on
  the closing card instead).
- Adding any new agentjail policy rule (beat 2 stays on a default rule; the
  cloud-destroy idea became the wordless "possibilities" montage).
- Localization / multiple language cuts.

## Open questions (non-blocking; default chosen)

- Exact final logo set and order — default list above; tune during build.
- Pane ratio 62/38 — tune for legibility during build.
- Whether to also export a 1:1 / 9:16 social crop — deferred; design the 16:9
  master first.
