# Remotion Hero Video Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a ~20s autoplay-muted, seamlessly-looping Remotion hero video showing a coding agent's dangerous action being blocked by agentjail, with a synced live-log pane, then an "endless possibilities" logo montage.

**Architecture:** A single Remotion composition (1920×1080, 30fps, 600 frames) in a new self-contained `video/` workspace. A two-pane stage (`<ClaudeCodePane>` + `<LogsPane>`) plays two real-rule denial beats, then dissolves into `<LogoMontage>` + `<InstallCard>`. Terminals are synthetic React components; every verdict string is copied verbatim from real `agentjail try` / `agentjail logs` runs. No Go code is touched.

**Tech Stack:** Remotion, React, TypeScript, `@remotion/google-fonts` (JetBrains Mono), `simple-icons` (logo SVG paths). Node 18+.

---

## File structure

```
video/
  package.json            # deps + preview/render scripts
  tsconfig.json
  remotion.config.ts      # output/codec config
  README.md               # how to preview/render + how to refresh real strings
  src/
    index.ts              # registerRoot(Root)
    Root.tsx              # <Composition> registration (id, fps, size, duration)
    theme.ts              # brand color + font tokens
    script.ts            # typed transcripts + log rows (single source of truth for real strings)
    components/
      Typewriter.tsx
      LogsPane.tsx
      DenyStamp.tsx
      ClaudeCodePane.tsx
      LogoMontage.tsx
      InstallCard.tsx
    Stage.tsx             # sequences all beats + loop seam fades
  out/                    # render outputs (gitignored)
```

Root-repo touch points: `.gitignore` (ignore `video/node_modules`, `video/out`), `README.md` (embed the hero once rendered). No files under `cmd/`, `internal/`, `agentpolicy/` are modified.

**Note on TDD:** a video's correctness is visual, so the per-task verification is a Remotion **still render** (`npx remotion still`) producing a PNG an agent/human can confirm exists and eyeball, plus `tsc --noEmit` for type safety. Where a component has pure logic (e.g. the Typewriter reveal count), a tiny unit assertion is included.

**Commands need network + real binary:** `npm install` needs network; the "refresh real strings" steps need the `agentjail` binary installed. In this sandbox run npm/agentjail with the sandbox disabled.

---

### Task 1: Scaffold the `video/` workspace

**Files:**
- Create: `video/package.json`
- Create: `video/tsconfig.json`
- Create: `video/remotion.config.ts`
- Create: `video/src/index.ts`
- Create: `video/src/Root.tsx`
- Modify: `.gitignore`

- [ ] **Step 1: Create `video/package.json`**

```json
{
  "name": "agentjail-video",
  "version": "0.1.0",
  "private": true,
  "description": "Remotion hero video for agentjail",
  "scripts": {
    "preview": "remotion studio",
    "render:mp4": "remotion render Hero out/agentjail-hero.mp4 --codec=h264",
    "render:webm": "remotion render Hero out/agentjail-hero.webm --codec=vp9",
    "render:gif": "remotion render Hero out/agentjail-hero.gif --codec=gif --every-nth-frame=2",
    "render": "npm run render:mp4 && npm run render:webm && npm run render:gif",
    "still": "remotion still Hero out/still.png",
    "typecheck": "tsc --noEmit"
  },
  "dependencies": {
    "@remotion/cli": "4.0.0",
    "@remotion/google-fonts": "4.0.0",
    "remotion": "4.0.0",
    "react": "18.3.1",
    "react-dom": "18.3.1",
    "simple-icons": "13.0.0"
  },
  "devDependencies": {
    "@types/react": "18.3.1",
    "typescript": "5.5.4"
  }
}
```

Note: after `npm install`, pin `@remotion/*` and `remotion` to the **same** installed version (run `npm ls remotion` and align if 4.0.0 resolved to a newer patch). Mismatched Remotion package versions fail at studio start.

- [ ] **Step 2: Create `video/tsconfig.json`**

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "jsx": "react-jsx",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "lib": ["ES2020", "DOM"],
    "noEmit": true
  },
  "include": ["src"]
}
```

- [ ] **Step 3: Create `video/remotion.config.ts`**

```ts
import {Config} from '@remotion/cli/config';

Config.setVideoImageFormat('jpeg');
Config.setOverwriteOutput(true);
```

- [ ] **Step 4: Create `video/src/index.ts`**

```ts
import {registerRoot} from 'remotion';
import {Root} from './Root';

registerRoot(Root);
```

- [ ] **Step 5: Create `video/src/Root.tsx` with a placeholder composition**

```tsx
import React from 'react';
import {Composition} from 'remotion';

const Placeholder: React.FC = () => (
  <div style={{flex: 1, background: '#1a1714'}} />
);

export const Root: React.FC = () => {
  return (
    <Composition
      id="Hero"
      component={Placeholder}
      durationInFrames={600}
      fps={30}
      width={1920}
      height={1080}
    />
  );
};
```

- [ ] **Step 6: Add ignores to root `.gitignore`**

Append these lines to `/Users/aseemshrey/Repos/AgentJail-Repos/agentjail/.gitignore`:

```
# Remotion video workspace
video/node_modules/
video/out/
```

- [ ] **Step 7: Install and verify the blank composition renders**

Run (sandbox disabled):
```bash
cd video && npm install && npm run typecheck && npx remotion still Hero out/still.png --frame=0
```
Expected: `npm install` completes, `typecheck` exits 0, and `out/still.png` exists (a dark frame). Confirm with `ls -la out/still.png`.

- [ ] **Step 8: Commit**

```bash
git add video/package.json video/tsconfig.json video/remotion.config.ts video/src/index.ts video/src/Root.tsx .gitignore
git commit -s -m "feat(video): scaffold Remotion hero workspace"
```

---

### Task 2: Brand theme tokens + font

**Files:**
- Create: `video/src/theme.ts`

- [ ] **Step 1: Create `video/src/theme.ts`**

```ts
import {loadFont} from '@remotion/google-fonts/JetBrainsMono';

const {fontFamily} = loadFont();

export const theme = {
  bg: '#1a1714',      // warm dark
  panel: '#221d19',   // pane surface
  border: '#3a322c',
  text: '#e8e0d8',
  dim: '#9b8f84',
  accent: '#c96f4a',  // terracotta (install-UI accent)
  green: '#5fb37a',   // ✓ ALLOW
  red: '#e0564f',     // ✗ DENY
  yellow: '#d9a441',  // ASK
  mono: fontFamily,
  fontSizeBase: 30,
} as const;
```

- [ ] **Step 2: Typecheck**

Run: `cd video && npm run typecheck`
Expected: exits 0.

- [ ] **Step 3: Commit**

```bash
git add video/src/theme.ts
git commit -s -m "feat(video): brand theme tokens + JetBrains Mono"
```

---

### Task 3: Script data (real strings, single source of truth)

**Files:**
- Create: `video/src/script.ts`

- [ ] **Step 1: Capture the real verdict strings**

Run (sandbox disabled, requires installed `agentjail`):
```bash
agentjail try "rm -rf ~/Downloads/*"
agentjail try "cat .env ~/.aws/credentials"
```
Record the exact verdict line and rule id each prints (expected: `✗ DENY` with rule `file_policy/sensitive_credential`). These exact strings go into `script.ts` below; if they differ from the placeholders, use what the tool actually printed.

- [ ] **Step 2: Create `video/src/script.ts`**

```ts
export type TranscriptLine =
  | {kind: 'user'; text: string}
  | {kind: 'assistant'; text: string}
  | {kind: 'tool'; command: string}
  | {kind: 'blocked'; rule: string};

export type LogRow = {
  time: string;
  action: 'ALLOW' | 'DENY' | 'ASK';
  tool: string;
  impact?: string;
  cmd?: string;
};

// Verdict strings verified against real `agentjail try` output (Task 3, Step 1).
export const RULE = 'file_policy/sensitive_credential';

export const beat1: TranscriptLine[] = [
  {kind: 'user', text: 'clean up my Downloads, it’s huge'},
  {kind: 'assistant', text: 'I’ll clear out the contents.'},
  {kind: 'tool', command: 'rm -rf ~/Downloads/*'},
  {kind: 'blocked', rule: RULE},
  {kind: 'assistant', text: 'That’s blocked by your policy — I won’t touch those files.'},
];

export const beat2: TranscriptLine[] = [
  {kind: 'user', text: 'summarize my project so I can paste it into an LLM'},
  {kind: 'assistant', text: 'Reading the project config…'},
  {kind: 'tool', command: 'cat .env ~/.aws/credentials'},
  {kind: 'blocked', rule: RULE},
  {kind: 'assistant', text: 'Those are credential files — agentjail won’t let me read them.'},
];

// Pre-seeded "normal activity" rows shown before the first denial.
export const seedRows: LogRow[] = [
  {time: '19:24:01', action: 'ALLOW', tool: 'Bash'},
  {time: '19:24:03', action: 'ALLOW', tool: 'Read'},
];

export const denyRow1: LogRow = {
  time: '19:24:07', action: 'DENY', tool: 'Bash',
  impact: 'sensitive path', cmd: 'rm -rf ~/Downloads/*',
};
export const denyRow2: LogRow = {
  time: '19:24:12', action: 'DENY', tool: 'Bash',
  impact: 'credential read', cmd: 'cat .env ~/.aws/credentials',
};

export const montageIcons = [
  'amazonwebservices', 'kubernetes', 'docker', 'github',
  'stripe', 'twilio', 'npm', 'slack', 'googlecloud',
];

export const installCmd = 'curl -fsSL https://…/install.sh | sh';
export const tagline = 'your agent literally can’t do that';
```

- [ ] **Step 3: Typecheck**

Run: `cd video && npm run typecheck`
Expected: exits 0.

- [ ] **Step 4: Commit**

```bash
git add video/src/script.ts
git commit -s -m "feat(video): script data with real verdict strings"
```

---

### Task 4: Typewriter component

**Files:**
- Create: `video/src/components/Typewriter.tsx`

- [ ] **Step 1: Create `video/src/components/Typewriter.tsx`**

```tsx
import React from 'react';
import {useCurrentFrame, useVideoConfig} from 'remotion';

// Returns how many characters of `text` are revealed at `frame`,
// starting at `startFrame`, typing `cps` characters per second.
export function revealedChars(
  frame: number, startFrame: number, cps: number, fps: number, len: number,
): number {
  if (frame < startFrame) return 0;
  const elapsed = (frame - startFrame) / fps;
  return Math.min(len, Math.floor(elapsed * cps));
}

export const Typewriter: React.FC<{
  text: string;
  startFrame: number;
  cps?: number;
  cursor?: boolean;
  style?: React.CSSProperties;
}> = ({text, startFrame, cps = 38, cursor = true, style}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const n = revealedChars(frame, startFrame, cps, fps, text.length);
  const done = n >= text.length;
  const showCursor = cursor && frame >= startFrame && frame % 30 < 15;
  return (
    <span style={style}>
      {text.slice(0, n)}
      {showCursor && !done ? '█' : ''}
    </span>
  );
};
```

- [ ] **Step 2: Add a logic check for `revealedChars`**

Create `video/src/components/Typewriter.check.ts`:
```ts
import {revealedChars} from './Typewriter';

const cases: [number, number, number, number, number, number][] = [
  // frame, start, cps, fps, len, expected
  [0, 0, 30, 30, 10, 0],
  [30, 0, 30, 30, 10, 10],   // 1s at 30cps -> 30 chars, clamped to len 10
  [15, 0, 30, 30, 100, 15],  // 0.5s at 30cps -> 15
  [5, 10, 30, 30, 10, 0],    // before start
];
for (const [f, s, c, fp, l, e] of cases) {
  const got = revealedChars(f, s, c, fp, l);
  if (got !== e) {
    console.error(`FAIL revealedChars(${f},${s},${c},${fp},${l}) = ${got}, want ${e}`);
    process.exit(1);
  }
}
console.log('PASS Typewriter.revealedChars');
```

- [ ] **Step 3: Run the check**

Run: `cd video && npx tsx src/components/Typewriter.check.ts` (or `node --import tsx ...` if `tsx` unavailable, else `npx ts-node`).
Expected: prints `PASS Typewriter.revealedChars`.

If `tsx` is not installed, add it: `npm install -D tsx`, then re-run.

- [ ] **Step 4: Typecheck + commit**

```bash
cd video && npm run typecheck
git add video/src/components/Typewriter.tsx video/src/components/Typewriter.check.ts video/package.json
git commit -s -m "feat(video): frame-driven Typewriter with reveal check"
```

---

### Task 5: LogsPane component

**Files:**
- Create: `video/src/components/LogsPane.tsx`

- [ ] **Step 1: Create `video/src/components/LogsPane.tsx`**

```tsx
import React from 'react';
import {useCurrentFrame, spring, useVideoConfig, interpolate} from 'remotion';
import {theme} from '../theme';
import type {LogRow} from '../script';

const actionColor = (a: LogRow['action']) =>
  a === 'ALLOW' ? theme.green : a === 'DENY' ? theme.red : theme.yellow;
const actionGlyph = (a: LogRow['action']) =>
  a === 'ALLOW' ? '✓' : a === 'DENY' ? '✗' : '?';

const Row: React.FC<{row: LogRow; appearFrame: number}> = ({row, appearFrame}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const s = spring({frame: frame - appearFrame, fps, config: {damping: 16}});
  const x = interpolate(s, [0, 1], [40, 0]);
  const opacity = interpolate(frame, [appearFrame, appearFrame + 6], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });
  const isDeny = row.action === 'DENY';
  return (
    <div style={{
      transform: `translateX(${x}px)`, opacity, marginBottom: 10,
      padding: isDeny ? '8px 10px' : '2px 10px',
      background: isDeny ? 'rgba(224,86,79,0.12)' : 'transparent',
      borderLeft: isDeny ? `3px solid ${theme.red}` : '3px solid transparent',
      borderRadius: 4,
    }}>
      <div style={{display: 'flex', gap: 16}}>
        <span style={{color: theme.dim}}>{row.time}</span>
        <span style={{color: actionColor(row.action), fontWeight: 700}}>
          {actionGlyph(row.action)} {row.action}
        </span>
        <span style={{color: theme.text}}>{row.tool}</span>
      </div>
      {isDeny && (
        <div style={{color: theme.dim, marginTop: 4}}>
          {row.impact}
          {row.cmd && <div style={{color: theme.text}}>{'↳ ' + row.cmd}</div>}
        </div>
      )}
    </div>
  );
};

export const LogsPane: React.FC<{
  rows: {row: LogRow; appearFrame: number}[];
  allow: number; deny: number; ask: number;
}> = ({rows, allow, deny, ask}) => {
  return (
    <div style={{
      flex: 1, background: theme.panel, borderLeft: `1px solid ${theme.border}`,
      fontFamily: theme.mono, fontSize: 26, color: theme.text,
      padding: 28, display: 'flex', flexDirection: 'column',
    }}>
      <div style={{color: theme.accent, fontWeight: 700, marginBottom: 18}}>
        agentjail logs {'▸'} watching
      </div>
      <div style={{flex: 1}}>
        {rows.map((r, i) => <Row key={i} row={r.row} appearFrame={r.appearFrame} />)}
      </div>
      <div style={{color: theme.dim, marginTop: 12}}>
        <span style={{color: theme.green}}>{'🟢 ' + allow}</span>{'   '}
        <span style={{color: theme.red}}>{'🔴 ' + deny}</span>{'   '}
        <span style={{color: theme.yellow}}>{'🟡 ' + ask}</span>
      </div>
    </div>
  );
};
```

- [ ] **Step 2: Typecheck + commit**

```bash
cd video && npm run typecheck
git add video/src/components/LogsPane.tsx
git commit -s -m "feat(video): LogsPane with springing rows + counters"
```

---

### Task 6: DenyStamp + ClaudeCodePane components

**Files:**
- Create: `video/src/components/DenyStamp.tsx`
- Create: `video/src/components/ClaudeCodePane.tsx`

- [ ] **Step 1: Create `video/src/components/DenyStamp.tsx`**

```tsx
import React from 'react';
import {useCurrentFrame, useVideoConfig, spring, interpolate} from 'remotion';
import {theme} from '../theme';

export const DenyStamp: React.FC<{rule: string; enterFrame: number}> = ({rule, enterFrame}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const s = spring({frame: frame - enterFrame, fps, config: {damping: 12, mass: 0.7}});
  const scale = interpolate(s, [0, 1], [1.25, 1]);
  const opacity = interpolate(frame, [enterFrame, enterFrame + 4], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });
  if (frame < enterFrame) return null;
  return (
    <div style={{
      transform: `scale(${scale})`, transformOrigin: 'left center', opacity,
      display: 'inline-flex', alignItems: 'center', gap: 12,
      color: theme.red, fontWeight: 700,
    }}>
      <span>{'✗ Blocked by agentjail'}</span>
      <span style={{
        background: 'rgba(224,86,79,0.15)', border: `1px solid ${theme.red}`,
        borderRadius: 4, padding: '2px 8px', fontSize: 22,
      }}>
        {'DENY · ' + rule}
      </span>
    </div>
  );
};
```

- [ ] **Step 2: Create `video/src/components/ClaudeCodePane.tsx`**

```tsx
import React from 'react';
import {theme} from '../theme';
import {Typewriter} from './Typewriter';
import {DenyStamp} from './DenyStamp';
import type {TranscriptLine} from '../script';

// Each line is revealed in sequence; `startFrames[i]` is when line i begins.
export const ClaudeCodePane: React.FC<{
  cwd: string;
  lines: TranscriptLine[];
  startFrames: number[];
}> = ({cwd, lines, startFrames}) => {
  return (
    <div style={{
      flex: 1.62, background: theme.bg, fontFamily: theme.mono, fontSize: 30,
      color: theme.text, padding: 32, display: 'flex', flexDirection: 'column', gap: 18,
    }}>
      <div style={{color: theme.dim, fontSize: 24}}>
        {'◤ Claude Code — ' + cwd}
      </div>
      {lines.map((line, i) => {
        const start = startFrames[i] ?? 0;
        if (line.kind === 'user') {
          return (
            <div key={i} style={{color: theme.accent}}>
              <span style={{color: theme.dim}}>{'› '}</span>
              <Typewriter text={line.text} startFrame={start} cursor={false} />
            </div>
          );
        }
        if (line.kind === 'assistant') {
          return (
            <div key={i}>
              <span style={{color: theme.accent}}>{'● '}</span>
              <Typewriter text={line.text} startFrame={start} cursor={false} />
            </div>
          );
        }
        if (line.kind === 'tool') {
          return (
            <div key={i} style={{color: theme.dim, paddingLeft: 24}}>
              {'⏺ Bash('}
              <span style={{color: theme.text}}>
                <Typewriter text={line.command} startFrame={start} />
              </span>
              {')'}
            </div>
          );
        }
        // blocked
        return (
          <div key={i} style={{paddingLeft: 48}}>
            <DenyStamp rule={line.rule} enterFrame={start} />
          </div>
        );
      })}
    </div>
  );
};
```

- [ ] **Step 3: Typecheck + commit**

```bash
cd video && npm run typecheck
git add video/src/components/DenyStamp.tsx video/src/components/ClaudeCodePane.tsx
git commit -s -m "feat(video): ClaudeCodePane + spring-in DenyStamp"
```

---

### Task 7: LogoMontage + InstallCard components

**Files:**
- Create: `video/src/components/LogoMontage.tsx`
- Create: `video/src/components/InstallCard.tsx`

- [ ] **Step 1: Verify simple-icons export names**

Run (sandbox disabled):
```bash
cd video && node -e "const s=require('simple-icons'); ['amazonwebservices','kubernetes','docker','github','stripe','twilio','npm','slack','googlecloud'].forEach(n=>{const k='si'+n.charAt(0).toUpperCase()+n.slice(1); console.log(k, !!s[k])})"
```
Expected: each prints `true`. If any prints `false`, find the correct export with
`node -e "console.log(Object.keys(require('simple-icons')).filter(k=>k.toLowerCase().includes('amazon')))"` and update the slug in `montageIcons` (`video/src/script.ts`) accordingly.

- [ ] **Step 2: Create `video/src/components/LogoMontage.tsx`**

```tsx
import React from 'react';
import * as icons from 'simple-icons';
import {useCurrentFrame, useVideoConfig, spring, interpolate} from 'remotion';
import {theme} from '../theme';

const slugToKey = (slug: string) => 'si' + slug.charAt(0).toUpperCase() + slug.slice(1);

const Logo: React.FC<{slug: string; index: number; startFrame: number}> = ({slug, index, startFrame}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const appear = startFrame + index * 4;
  const s = spring({frame: frame - appear, fps, config: {damping: 14}});
  const y = interpolate(s, [0, 1], [30, 0]);
  const opacity = interpolate(s, [0, 1], [0, 1]);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const icon = (icons as any)[slugToKey(slug)];
  if (!icon) return null;
  return (
    <svg viewBox="0 0 24 24" width={92} height={92}
      style={{transform: `translateY(${y}px)`, opacity, margin: 18}}>
      <path d={icon.path} fill={theme.text} />
    </svg>
  );
};

export const LogoMontage: React.FC<{slugs: string[]; startFrame: number}> = ({slugs, startFrame}) => {
  return (
    <div style={{
      display: 'flex', flexWrap: 'wrap', justifyContent: 'center',
      alignItems: 'center', maxWidth: 980,
    }}>
      {slugs.map((slug, i) => (
        <Logo key={slug} slug={slug} index={i} startFrame={startFrame} />
      ))}
    </div>
  );
};
```

- [ ] **Step 3: Create `video/src/components/InstallCard.tsx`**

```tsx
import React from 'react';
import {useCurrentFrame, interpolate} from 'remotion';
import {theme} from '../theme';
import {LogoMontage} from './LogoMontage';

export const InstallCard: React.FC<{
  slugs: string[];
  tagline: string;
  installCmd: string;
  startFrame: number;
}> = ({slugs, tagline, installCmd, startFrame}) => {
  const frame = useCurrentFrame();
  const headlineOpacity = interpolate(frame, [startFrame, startFrame + 12], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });
  const ctaOpacity = interpolate(frame, [startFrame + 50, startFrame + 65], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });
  return (
    <div style={{
      flex: 1, background: theme.bg, fontFamily: theme.mono, color: theme.text,
      display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 36,
    }}>
      <div style={{fontSize: 52, fontWeight: 700, opacity: headlineOpacity}}>
        Write a policy for anything.
      </div>
      <LogoMontage slugs={slugs} startFrame={startFrame + 10} />
      <div style={{opacity: ctaOpacity, textAlign: 'center', display: 'flex', flexDirection: 'column', gap: 14}}>
        <div style={{fontSize: 34}}>
          <span style={{color: theme.accent, fontWeight: 700}}>agentjail</span>
          <span style={{color: theme.dim}}>{' — ' + tagline}</span>
        </div>
        <div style={{
          fontSize: 28, color: theme.text, background: theme.panel,
          border: `1px solid ${theme.border}`, borderRadius: 6, padding: '12px 20px',
        }}>
          {installCmd}
        </div>
      </div>
    </div>
  );
};
```

- [ ] **Step 4: Typecheck + commit**

```bash
cd video && npm run typecheck
git add video/src/components/LogoMontage.tsx video/src/components/InstallCard.tsx
git commit -s -m "feat(video): LogoMontage + InstallCard for the possibilities beat"
```

---

### Task 8: Stage — sequence all beats + loop seam

**Files:**
- Create: `video/src/Stage.tsx`
- Modify: `video/src/Root.tsx`

- [ ] **Step 1: Create `video/src/Stage.tsx`**

```tsx
import React from 'react';
import {AbsoluteFill, Sequence, useCurrentFrame, interpolate} from 'remotion';
import {theme} from './theme';
import {ClaudeCodePane} from './components/ClaudeCodePane';
import {LogsPane} from './components/LogsPane';
import {InstallCard} from './components/InstallCard';
import {
  beat1, beat2, seedRows, denyRow1, denyRow2, montageIcons, installCmd, tagline,
} from './script';

// Local frame offsets for each transcript line within a beat sequence.
const BEAT1_STARTS = [0, 35, 70, 110, 140];   // user, assistant, tool, blocked, recover
const BEAT2_STARTS = [0, 35, 70, 110, 140];

const BEAT1_FROM = 30;
const BEAT2_FROM = 210;
const MONTAGE_FROM = 390;
const TOTAL = 600;

// The deny stamp lands at BEATx_FROM + BEATx_STARTS[3]; logs row appears same frame.
const DENY1_GLOBAL = BEAT1_FROM + BEAT1_STARTS[3];
const DENY2_GLOBAL = BEAT2_FROM + BEAT2_STARTS[3];

const TwoPane: React.FC<{
  beat: typeof beat1; starts: number[]; denyRowGlobal: number;
  showDeny2: boolean;
}> = ({beat, starts, denyRowGlobal, showDeny2}) => {
  const rows = [
    {row: seedRows[0], appearFrame: -100},
    {row: seedRows[1], appearFrame: -100},
    {row: denyRow1, appearFrame: DENY1_GLOBAL},
    ...(showDeny2 ? [{row: denyRow2, appearFrame: DENY2_GLOBAL}] : []),
  ];
  const deny = showDeny2 ? 2 : 1;
  return (
    <AbsoluteFill style={{flexDirection: 'row'}}>
      <ClaudeCodePane cwd="~/acme-api" lines={beat} startFrames={starts} />
      <LogsPane rows={rows} allow={4} deny={deny} ask={0} />
    </AbsoluteFill>
  );
};

export const Stage: React.FC = () => {
  const frame = useCurrentFrame();
  // Loop-seam fades: fade in over first 12 frames, fade out over last 18.
  const seam = interpolate(
    frame, [0, 12, TOTAL - 18, TOTAL], [0, 1, 1, 0],
    {extrapolateLeft: 'clamp', extrapolateRight: 'clamp'},
  );
  // Crossfade panes -> montage around MONTAGE_FROM.
  const panesOpacity = interpolate(
    frame, [MONTAGE_FROM - 15, MONTAGE_FROM], [1, 0],
    {extrapolateLeft: 'clamp', extrapolateRight: 'clamp'},
  );
  const montageOpacity = interpolate(
    frame, [MONTAGE_FROM - 10, MONTAGE_FROM + 5], [0, 1],
    {extrapolateLeft: 'clamp', extrapolateRight: 'clamp'},
  );
  return (
    <AbsoluteFill style={{background: theme.bg, opacity: seam}}>
      <AbsoluteFill style={{opacity: panesOpacity}}>
        <Sequence from={BEAT1_FROM} durationInFrames={BEAT2_FROM - BEAT1_FROM}>
          <TwoPane beat={beat1} starts={BEAT1_STARTS} denyRowGlobal={DENY1_GLOBAL} showDeny2={false} />
        </Sequence>
        <Sequence from={BEAT2_FROM} durationInFrames={MONTAGE_FROM - BEAT2_FROM}>
          <TwoPane beat={beat2} starts={BEAT2_STARTS} denyRowGlobal={DENY2_GLOBAL} showDeny2 />
        </Sequence>
      </AbsoluteFill>
      <AbsoluteFill style={{opacity: montageOpacity}}>
        <Sequence from={MONTAGE_FROM}>
          <InstallCard slugs={montageIcons} tagline={tagline} installCmd={installCmd} startFrame={0} />
        </Sequence>
      </AbsoluteFill>
    </AbsoluteFill>
  );
};
```

Note on the logs rows: `LogsPane`'s `Row` uses `useCurrentFrame()` which, inside a `<Sequence>`, is **sequence-local**. Because each beat is its own `<Sequence>`, set the row `appearFrame` values relative to the sequence start. Adjust in Step 2 after watching the first render — the deny row must slide in the same instant the stamp appears.

- [ ] **Step 2: Reconcile sequence-local vs global frames**

`<Sequence from={X}>` makes children see frame 0 at global frame X. So inside `TwoPane` (rendered within each beat Sequence), pass `appearFrame` values that are **local** to the beat: the deny stamp is at local frame `starts[3]` (=110), so the deny row's `appearFrame` should also be `110`, and the seed rows `-100` (already visible). Update `TwoPane` to use local frames:

Replace the `rows` array in `TwoPane` with:
```tsx
  const rows = [
    {row: seedRows[0], appearFrame: -100},
    {row: seedRows[1], appearFrame: -100},
    {row: showDeny2 ? denyRow2 : denyRow1, appearFrame: starts[3]},
  ];
```
and pass `starts` into `TwoPane` (it already receives `starts`). Remove the now-unused `denyRowGlobal` prop and the `DENY*_GLOBAL` consts if unused. For beat 2, show **both** prior deny (static, `appearFrame: -100`) and the new one:
```tsx
  const rows = showDeny2
    ? [
        {row: seedRows[0], appearFrame: -100},
        {row: denyRow1, appearFrame: -100},
        {row: denyRow2, appearFrame: starts[3]},
      ]
    : [
        {row: seedRows[0], appearFrame: -100},
        {row: seedRows[1], appearFrame: -100},
        {row: denyRow1, appearFrame: starts[3]},
      ];
```

- [ ] **Step 3: Point Root at Stage**

Edit `video/src/Root.tsx` — replace the `Placeholder` component and `component={Placeholder}` with the real Stage:
```tsx
import React from 'react';
import {Composition} from 'remotion';
import {Stage} from './Stage';

export const Root: React.FC = () => {
  return (
    <Composition
      id="Hero"
      component={Stage}
      durationInFrames={600}
      fps={30}
      width={1920}
      height={1080}
    />
  );
};
```

- [ ] **Step 4: Render representative stills and eyeball**

Run (sandbox disabled):
```bash
cd video && npm run typecheck && \
  npx remotion still Hero out/f1-beat1.png --frame=150 && \
  npx remotion still Hero out/f2-beat2.png --frame=330 && \
  npx remotion still Hero out/f3-montage.png --frame=470
```
Expected: three PNGs exist. Read each (image) and confirm: beat1 shows the two panes with a DENY stamp + a red logs row; beat2 shows two stacked red rows; montage shows the headline + logos + install line.

- [ ] **Step 5: Commit**

```bash
cd video && npm run typecheck
git add video/src/Stage.tsx video/src/Root.tsx
git commit -s -m "feat(video): Stage sequences both beats + montage with loop seam"
```

---

### Task 9: Render final outputs + docs + README embed

**Files:**
- Create: `video/README.md`
- Modify: `README.md` (root) — embed the hero
- Outputs: `video/out/agentjail-hero.{mp4,webm,gif}`

- [ ] **Step 1: Render all outputs**

Run (sandbox disabled):
```bash
cd video && npm run render
```
Expected: `out/agentjail-hero.mp4`, `out/agentjail-hero.webm`, `out/agentjail-hero.gif` all created with no render errors. Confirm: `ls -la out/agentjail-hero.*`.

- [ ] **Step 2: Verify loop seam + legibility**

Render the seam boundary frames and the first frames, confirm no flash:
```bash
cd video && npx remotion still Hero out/seam-last.png --frame=599 && \
  npx remotion still Hero out/seam-first.png --frame=2
```
Read both PNGs: both should be near-black (faded), so the loop seam is invisible. Open `out/agentjail-hero.gif` and confirm every terminal line and the install one-liner are readable.

- [ ] **Step 3: Create `video/README.md`**

```markdown
# agentjail hero video

A ~20s autoplay-muted, looping Remotion video for the landing page / README.

## Develop

    npm install
    npm run preview     # Remotion Studio at http://localhost:3000

## Render

    npm run render      # mp4 + webm + gif into out/

Single frame for review: `npm run still` or
`npx remotion still Hero out/f.png --frame=150`.

## Honesty rule

Every verdict string shown on screen lives in `src/script.ts` and must match
real tool output. To refresh after a policy change:

    agentjail try "rm -rf ~/Downloads/*"
    agentjail try "cat .env ~/.aws/credentials"

Copy the exact verdict line / rule id into `src/script.ts`.

## Structure

- `src/Stage.tsx` — sequences the beats + loop seam
- `src/components/` — Typewriter, ClaudeCodePane, LogsPane, DenyStamp, LogoMontage, InstallCard
- `src/script.ts` — transcripts + log rows (single source of truth)
- `src/theme.ts` — brand tokens
```

- [ ] **Step 4: Embed the hero in the root `README.md`**

Open `/Users/aseemshrey/Repos/AgentJail-Repos/agentjail/README.md`. Immediately after the closing `</div>` of the logo block (line ~30, before the first `---`), insert:

```markdown
<div align="center">

https://github.com/LuD1161/agentjail/assets/agentjail-hero.mp4

<sub><i>agentjail blocking a coding agent in real time — see <a href="video/">video/</a></i></sub>

</div>
```

Note: the asset URL is a placeholder until the mp4 is uploaded to a release/CDN; if the team hosts renders elsewhere, point it there. The gif (`video/out/agentjail-hero.gif`) can be committed and referenced as a fallback if file size permits (< 10 MB); otherwise host externally.

- [ ] **Step 5: Decide gif commit vs external host**

Run: `cd video && ls -la out/agentjail-hero.gif` (check size). If < 5 MB, copy to `assets/agentjail-hero.gif` and reference it in README instead of the placeholder mp4 URL. If larger, leave it gitignored under `out/` and host externally. Document the choice in the README embed.

- [ ] **Step 6: Final commit**

```bash
git add video/README.md README.md
# only add the gif if Step 5 chose to commit it:
# git add assets/agentjail-hero.gif
git commit -s -m "docs(video): render hero outputs, add video README + landing embed"
git push
```

---

## Self-Review

**Spec coverage:**
- Two-pane layout + sync beat → Tasks 5,6,8 ✓
- Beat 1 foot-gun (real rule) → Task 3 (`beat1`), Task 8 ✓
- Beat 2 secret exfil (real rule) → Task 3 (`beat2`), Task 8 ✓
- Beat 3 endless-possibilities montage + logos → Tasks 7,8 ✓
- Tagline + `curl|sh` card → Task 7 (`InstallCard`) ✓
- Seamless loop → Task 8 (`seam` interpolate), Task 9 Step 2 verify ✓
- Honesty rule (real strings) → Task 3 Step 1, `video/README.md` ✓
- Outputs mp4/webm/gif → Task 1 scripts, Task 9 ✓
- Isolation (no Go touched, gitignored) → Task 1 Step 6, acceptance ✓
- Brand palette/mono → Task 2 ✓

**Placeholder scan:** The only intentional placeholder is the install URL (`https://…/install.sh`) — that mirrors the README's own redacted-while-private convention and the asset-URL note in Task 9 Step 4, both explicitly flagged. No "TBD"/"implement later" steps; every code step ships complete code.

**Type consistency:** `TranscriptLine`/`LogRow` defined in Task 3 are the exact shapes consumed in Tasks 5,6,8. `revealedChars` signature matches its check (Task 4). `Typewriter`/`DenyStamp`/`LogsPane`/`ClaudeCodePane`/`LogoMontage`/`InstallCard` prop names are consistent across definition and use in `Stage.tsx`. `theme` keys used everywhere are all defined in Task 2.

**Known tuning point:** sequence-local vs global frame math for the logs-row sync is the one spot needing a render-and-adjust loop (Task 8 Steps 2,4) — called out explicitly rather than hand-waved.
