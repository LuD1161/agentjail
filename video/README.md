# agentjail hero video

A ~36s autoplay-muted, looping [Remotion](https://www.remotion.dev/) video for
the landing page / README: an AGENTJAIL title card, two beats where a coding
agent's dangerous action is blocked in real time (with a synced live-log pane),
then a closing card — the agentjail wordmark, "Agent guardrails for your full
stack.", governable-tool logos, and the install one-liner.

## Develop

    npm install
    npm run preview     # Remotion Studio at http://localhost:3000

## Render

    npm run render      # mp4 + webm + gif into out/

Single frame for review: `npm run still` or
`npx remotion still Hero out/f.png --frame=150`.

### Browser executable

Remotion renders with headless Chrome. If it can't auto-locate a working
browser (e.g. a broken `chromium` shim on `PATH`), point it at an explicit
binary — `remotion.config.ts` honors `REMOTION_BROWSER_EXECUTABLE`:

    export REMOTION_BROWSER_EXECUTABLE="/path/to/chrome-headless-shell"
    npm run render

Any recent Chrome / Chromium / `chrome-headless-shell` works.

## Honesty rule

Every verdict string shown on screen lives in `src/script.ts` and must match
real tool output. To refresh after a policy change:

    agentjail try "rm -rf ~/Downloads/*"
    agentjail try "cat .env ~/.aws/credentials"

Copy the exact verdict line / rule id into `src/script.ts`. The current strings
use the documented default rule `file_policy/sensitive_credential`.

## Structure

- `src/Root.tsx` — composition registration (1920×1080, 30fps, 1080 frames = 36s)
- `src/Stage.tsx` — sequences the two beats + montage + loop-seam fades
- `src/components/` — Typewriter, ClaudeCodePane, LogsPane, DenyStamp,
  LogoMontage, InstallCard
- `src/script.ts` — transcripts + log rows (single source of truth for strings)
- `src/theme.ts` — brand tokens (terracotta accent on warm dark)

Logos are monochrome SVG paths from [`simple-icons`](https://simpleicons.org/),
tinted at render time.
