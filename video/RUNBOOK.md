# Runbook: generate & ship the demo video

End-to-end steps to regenerate the agentjail demo video and get it live on the
website and in the GitHub README. For project structure and dev-loop details,
see [`README.md`](./README.md).

The video is a Remotion composition: **1920×1080, 30fps, 1080 frames (= 36s)**.

---

## 0. What ships where

There is **one** rendered file that two places consume. Keep them in sync.

| Consumer | Path | Notes |
|----------|------|-------|
| Website "See it in action" section | `agentjail.io/public/video/agentjail-demo.mp4` | autoplay-muted-loop + sound toggle; deployed via Cloudflare Pages |
| Website poster (still shown before play) | `agentjail.io/public/video/agentjail-demo-poster.jpg` | a mid-demo frame; only regenerate if the *terminal demo* visuals change |
| GitHub README thumbnail link | `agentjail/assets/agentjail-demo.mp4` | committed to the repo; GitHub's blob view plays it inline with sound |

The canonical render lives at `video/out/agentjail-hero-mac-music.mp4`.
`video/out/` is **git-ignored** — renders are never committed there; only the two
consumer copies above are tracked.

## 1. Pick the composition

`src/Root.tsx` registers the base visuals plus one composition per audio track:

| Composition id | Visuals | Audio | Use |
|----------------|---------|-------|-----|
| `Hero` | Stage | none | silent base (the `npm run render` scripts target this) |
| `HeroSoundSynth` | Stage | synth SFX | A/B option |
| `HeroSoundLicensed` | Stage | licensed SFX | A/B option |
| `HeroSoundElevenLabs` | Stage | ElevenLabs SFX | A/B option |
| **`HeroSoundMusic`** | Stage | ElevenLabs SFX **+ music bed** | **the variant that ships** ("mac-music") |

`Stage` is the same for all of them (the macOS-framed terminal demo, title and
install cards). The SFX assets live under `public/sfx/<pack>/`.

> **Ship `HeroSoundMusic`** unless you're deliberately A/B-testing a soundtrack.

## 2. Edit copy (if needed)

All on-screen strings are source-controlled — never hand-edit a render.

- **Title / closing taglines:** `src/components/IntroCard.tsx` (opening) and
  `src/components/InstallCard.tsx` (closing). Current text:
  - Intro: `Policy guardrails for coding agents`
  - Outro: `Agent guardrails for your full stack.`
- **Terminal transcript + log rows:** `src/script.ts` (single source of truth).
  These must match **real** tool output — see the **Honesty rule** in
  `README.md`. Refresh with `agentjail try "<cmd>"` and paste the exact
  verdict/rule id.

Preview changes live before rendering: `npm run preview` (Remotion Studio).

## 3. Render

```sh
cd video
npm install                      # first time / after dep changes

# Ship variant (mp4 with music). ~50s on an M-series Mac.
npx remotion render HeroSoundMusic out/agentjail-hero-mac-music.mp4 --codec=h264
```

**Browser gotcha:** Remotion needs headless Chrome. If a broken `chromium` shim
is on `PATH` (Homebrew sometimes leaves a dangling symlink), the render fails to
locate a browser. Point it at any real Chrome — `remotion.config.ts` honors
`REMOTION_BROWSER_EXECUTABLE`:

```sh
export REMOTION_BROWSER_EXECUTABLE="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
```

(Silent base variant + webm + gif, if you ever need them: `npm run render`.)

## 4. Verify before shipping

```sh
# duration ~36s, 1920x1080, AND an audio stream present
ffprobe -v error -show_entries format=duration:stream=codec_type,width,height \
  -of default=noprint_wrappers=1 out/agentjail-hero-mac-music.mp4

# eyeball the taglines (open these PNGs)
ffmpeg -y -ss 3  -i out/agentjail-hero-mac-music.mp4 -frames:v 1 /tmp/intro.png
ffmpeg -y -ss 33 -i out/agentjail-hero-mac-music.mp4 -frames:v 1 /tmp/outro.png
```

Confirm: intro reads the expected tagline, outro reads the expected tagline,
and there **is** an audio stream (a silent ship is the most common mistake).

## 5. Copy into the two consumers

```sh
cp out/agentjail-hero-mac-music.mp4 ../../agentjail.io/public/video/agentjail-demo.mp4
cp out/agentjail-hero-mac-music.mp4 assets/agentjail-demo.mp4
```

Only regenerate the website poster if the **terminal demo** visuals changed
(tagline-only edits don't affect it — the poster is a mid-demo DENY frame):

```sh
ffmpeg -y -ss 13 -i out/agentjail-hero-mac-music.mp4 -q:v 3 \
  ../../agentjail.io/public/video/agentjail-demo-poster.jpg
```

## 6. Commit & deploy

Two repos, two commits (conventional + `-s`):

```sh
# website → triggers Cloudflare Pages build (live a few min after push to main)
cd ../../agentjail.io
git add public/video/agentjail-demo.mp4 public/video/agentjail-demo-poster.jpg
git commit -s -m "chore(home): re-render demo video"
git push origin main

# product README
cd ../agentjail   # adjust to your checkout path
git add assets/agentjail-demo.mp4
git commit -s -m "chore(readme): re-render demo video"
git push
```

## 7. Confirm live

- Website: load the homepage, scroll to **"See it in action"**, confirm the new
  cut autoplays and the sound toggle unmutes. (Until the `agentjail.io` custom
  domain is wired in Cloudflare Pages, verify on the `*.pages.dev` URL.)
- README: open the repo on GitHub, click the hero GIF → GitHub blob view should
  play the mp4 with sound.
