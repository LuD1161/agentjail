# assets/

Visual + branding assets for the agentjail project.

## `agentjail-logo.png`

The top-of-README logo. Target style: **pixelated retro 8-bit bitmap**, black
glyphs on light cream (`#faf6ef`), matching the visual language of
projects like vibe-kanban — readable at 520 px wide, scales down cleanly to
a favicon.

### How to generate one

**Option A — Online ASCII/pixel-text generator (fastest, free):**

1. Go to <https://patorjk.com/software/taag/>
2. Set font to `Big`, `Block`, or `Pixel`
3. Type `AGENTJAIL`
4. Copy the ASCII art, paste into a tool like <https://carbon.now.sh/> with a monospace pixel font (Press Start 2P) on a cream background
5. Export as PNG, drop here as `assets/agentjail-logo.png`

**Option B — Google Fonts + Figma/Canva/Photoshop:**

Fonts that produce the right look:
- [Press Start 2P](https://fonts.google.com/specimen/Press+Start+2P) — official 8-bit arcade look
- [VT323](https://fonts.google.com/specimen/VT323) — CRT terminal
- [Silkscreen](https://fonts.google.com/specimen/Silkscreen) — Mac OS Classic pixel
- [Pixelify Sans](https://fonts.google.com/specimen/Pixelify+Sans) — modern pixelated

Layout: word `AGENTJAIL` centred, all caps, ~520×120 px, black on
`#faf6ef`, no other text. Optional: faint dotted-grid background like
graph paper for the vibe-kanban aesthetic.

**Option C — AI image generator:**

Prompt:
> "pixelated retro 8-bit bitmap-font logo of the word AGENTJAIL in bold black pixels, centred on a light cream background (#faf6ef), faint dotted graph-paper grid behind it, monospace pixel font like Press Start 2P, 520 pixels wide, transparent margins"

### Fallback (no logo)

The README's `<img>` tag will silently 404 if the file is missing. The text
tagline below it carries the project regardless. Once the logo lands here
(filename **must** be `agentjail-logo.png` for the README link to resolve),
push it and the README renders correctly on github.com.

### License

Whatever you ship here goes under the same Apache-2.0 license as the rest of
the repo unless you note otherwise.
