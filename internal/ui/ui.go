// Package ui provides Lip Gloss styling helpers for agentjail's installer and
// status output. It is the single source of visual truth: no other package
// defines ANSI codes or Lip Gloss styles directly.
//
// # Capability model
//
// Color and glyphs are independent axes:
//   - Color: driven by the Lip Gloss / termenv profile + NO_COLOR. NO_COLOR=1
//     disables color only.
//   - Glyphs/borders: determined by detectGlyphs(). UTF-8 glyphs and rounded
//     borders are used when the locale advertises UTF-8 and TERM != "dumb".
//     Otherwise, ASCII fallback glyphs and NormalBorder are used.
//
// # Untrusted-text sanitization
//
// All dynamic strings (titles, values, badge text, etc.) are routed through
// sanitize() before styling.  sanitize strips C0/C1 control bytes and ESC
// sequences, and converts \r, \n, \t to spaces so that crafted agent names or
// notes cannot inject extra rows or fake status lines.
package ui

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// --------------------------------------------------------------------------
// Glyph sets
// --------------------------------------------------------------------------

// glyphs holds the active glyph set chosen by detectGlyphs.
type glyphs struct {
	ok      string // ✓ or [x]
	fail    string // ✗ or [ ]
	arrow   string // ❯ or >
	bullet  string // ● or *
	diamond string // ◆ or #
	corner  string // └ or `
	useUTF8 bool   // whether UTF-8 glyphs are active
}

var utf8Glyphs = glyphs{
	ok:      "✓",
	fail:    "✗",
	arrow:   "❯",
	bullet:  "●",
	diamond: "◆",
	corner:  "└",
	useUTF8: true,
}

var asciiGlyphs = glyphs{
	ok:      "[x]",
	fail:    "[ ]",
	arrow:   ">",
	bullet:  "*",
	diamond: "#",
	corner:  "`",
	useUTF8: false,
}

// envLookup is the environment variable lookup function used by detectGlyphs.
// Tests replace this to inject arbitrary environments without touching os.Getenv.
var envLookup func(string) string = os.Getenv

// detectGlyphs returns the appropriate glyph set based on the environment.
// The axes are:
//   - UTF-8 capable: LC_ALL/LC_CTYPE/LANG contains "UTF-8" or "utf8", AND TERM != "dumb".
//   - ASCII fallback: non-UTF-8 locale OR TERM=dumb.
func detectGlyphs() glyphs {
	term := envLookup("TERM")
	if term == "dumb" {
		return asciiGlyphs
	}
	for _, key := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		val := envLookup(key)
		if strings.Contains(val, "UTF-8") || strings.Contains(val, "utf8") {
			return utf8Glyphs
		}
	}
	return asciiGlyphs
}

// --------------------------------------------------------------------------
// Sanitization
// --------------------------------------------------------------------------

// escSeqRe matches ESC followed by an optional ANSI/OSC sequence.
// It handles:
//   - CSI sequences: ESC [ ... <letter>
//   - OSC sequences: ESC ] ... BEL or ST (ESC \)
//   - All other ESC sequences: ESC <any-non-[> char
var escSeqRe = regexp.MustCompile(`\x1b(\[[0-9;]*[a-zA-Z]|\][^\x07\x1b]*(\x07|\x1b\\)|[^\[])`)

// sanitize strips C0 (0x00–0x1F) and C1 (0x80–0x9F) control characters plus
// any ESC sequences, and replaces \r, \n, \t with single spaces.  Layout
// newlines are added by the renderer after sanitization.
func sanitize(s string) string {
	// Strip ESC sequences first so subsequent passes don't see lone ESC bytes.
	s = escSeqRe.ReplaceAllString(s, "")

	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		if r == utf8.RuneError && size == 1 {
			// Skip invalid UTF-8 bytes.
			continue
		}
		switch r {
		case '\r', '\n', '\t':
			b.WriteByte(' ')
		default:
			cp := rune(r)
			// C0: 0x00–0x1F (excluding space 0x20)
			// C1: 0x80–0x9F
			// ESC (0x1b) is already removed above, but guard here too.
			if cp == 0x1b || unicode.Is(unicode.C, cp) && cp != 0x20 {
				// Skip control characters.
				continue
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Sanitize strips terminal control sequences and control characters from s.
// Use this for all untrusted strings (DB-sourced tool names, summaries, etc.)
// before rendering in the TUI.
func (u *UI) Sanitize(s string) string {
	return sanitize(s)
}

// sanitizeLines sanitizes a renderer-composed multi-line string.  Unlike
// sanitize, it preserves the '\n' separators that the renderer itself added
// (trusted layout newlines), while still stripping ESC sequences and C0/C1
// control bytes within each individual line.
//
// Use this for Box bodies, which are assembled from already-sanitized leaf
// strings joined with '\n'.  Leaf helpers (Badge, KeyValue, etc.) strip '\n'
// from untrusted input, so by the time rows are joined the '\n' characters are
// trusted and must not be flattened.
func sanitizeLines(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = sanitize(l)
	}
	return strings.Join(lines, "\n")
}

// --------------------------------------------------------------------------
// Brand palette constants (hex strings for TrueColor; lipgloss downgrades).
// Palette mirrors agentjail.io global.css CSS custom properties.
// --------------------------------------------------------------------------

const (
	colorAccent = "#be5b3a" // --color-accent  (terracotta brand)
	colorBrand  = "#f59264" // bright terracotta, used only for the wordmark
	colorGreen  = "#4d7c52" // --color-allow
	colorYellow = "#b8862e" // --color-ask
	colorRed    = "#be5b3a" // --color-deny    (same as accent)
	colorDim    = "#a59889" // --color-dim
	colorWhite  = "#fcf7f4" // --color-bg      (cream)
	colorTitle  = "#fdebe2" // --color-accent-soft
)

// --------------------------------------------------------------------------
// UI — the main type
// --------------------------------------------------------------------------

// UI holds a Lip Gloss renderer bound to a specific io.Writer and the glyph
// set selected for the environment.  Callers obtain one via New().
type UI struct {
	r *lipgloss.Renderer
	g glyphs
}

// New creates a UI bound to w. The color profile is detected from w (so piped
// writers automatically get the ASCII/plain profile) and the glyph set is
// detected from the environment via detectGlyphs().
func New(w io.Writer) *UI {
	r := lipgloss.NewRenderer(w)
	return &UI{r: r, g: detectGlyphs()}
}

// newWithProfile creates a UI with the given color profile and glyph set
// forced.  Used in package-internal tests for deterministic output.
func newWithProfile(w io.Writer, p termenv.Profile, g glyphs) *UI {
	r := lipgloss.NewRenderer(w, termenv.WithProfile(p))
	// SetColorProfile marks the profile as explicit so that Renderer.ColorProfile()
	// returns p directly rather than re-detecting via EnvColorProfile(). This is
	// required for deterministic test output: without it, lipgloss ignores the
	// WithProfile option and re-detects from the environment.
	r.SetColorProfile(p)
	return &UI{r: r, g: g}
}

// NewWithProfile creates a UI with the given termenv color profile and the
// glyph set auto-detected from the environment.  Use this in tests (or other
// packages) that need deterministic color output without writing to a real TTY.
func NewWithProfile(w io.Writer, p termenv.Profile) *UI {
	return newWithProfile(w, p, detectGlyphs())
}

// NewNoColor creates a UI with color disabled (termenv.Ascii profile) while
// keeping Unicode glyphs. Use when NO_COLOR is set but the TUI is still
// interactive.
func NewNoColor(w io.Writer) *UI {
	return newWithProfile(w, termenv.Ascii, detectGlyphs())
}

// --------------------------------------------------------------------------
// Render helpers
// --------------------------------------------------------------------------

// Header renders the brand banner with an optional set of meta lines
// (version, path, etc.). For the "agentjail" title it draws a slim three-row
// jail mark beside the wordmark, subtitle, and meta line:
//
//	█ █ █  AgentJail
//	█ █ █  policy guardrails for agents
//	█ █ █  v1.2.3 · /usr/local/bin/agentjail
func (u *UI) Header(title string, meta ...string) string {
	title = sanitize(title)
	for i, m := range meta {
		meta[i] = sanitize(m)
	}

	if !strings.EqualFold(title, "agentjail") {
		titleStyle := u.r.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color(colorAccent))

		diamond := u.r.NewStyle().
			Foreground(lipgloss.Color(colorAccent)).
			Render(u.g.diamond)

		heading := diamond + " " + titleStyle.Render(title)

		var lines []string
		lines = append(lines, heading)
		if len(meta) > 0 {
			dimStyle := u.r.NewStyle().Foreground(lipgloss.Color(colorDim))
			lines = append(lines, dimStyle.Render(strings.Join(meta, " · ")))
		}
		content := strings.Join(lines, "\n")

		var boxStyle lipgloss.Style
		if u.g.useUTF8 {
			boxStyle = u.r.NewStyle().
				BorderStyle(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color(colorAccent)).
				Padding(0, 1)
		} else {
			boxStyle = u.r.NewStyle().
				BorderStyle(lipgloss.NormalBorder()).
				BorderForeground(lipgloss.Color(colorDim)).
				Padding(0, 1)
		}
		return boxStyle.Render(content)
	}

	titleStyle := u.r.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(colorBrand))

	iconStyle := u.r.NewStyle().
		Foreground(lipgloss.Color(colorAccent)).
		Bold(true)

	// Slim three-row jail mark: one narrow bar column per text line, so the
	// brand sits at the same height as the three lines of text beside it.
	var icon string
	if u.g.useUTF8 {
		icon = iconStyle.Render("█ █ █")
	} else {
		icon = iconStyle.Render("| | |")
	}

	dimStyle := u.r.NewStyle().Foreground(lipgloss.Color(colorDim))

	var lines []string
	lines = append(lines, icon+"  "+titleStyle.Render("AgentJail"))
	lines = append(lines, icon+"  "+dimStyle.Render("policy guardrails for agents"))
	if len(meta) > 0 {
		lines = append(lines, icon+"  "+dimStyle.Render(strings.Join(meta, " · ")))
	} else {
		lines = append(lines, icon)
	}
	content := strings.Join(lines, "\n")
	// Breathing room on all sides: a blank line above/below and a left indent.
	return u.r.NewStyle().Padding(1, 2).Render(content)
}

// Emoji returns e only when the active glyph set is UTF-8 (modern terminals),
// and the empty string otherwise. Use it to prefix a line with a decorative
// emoji that degrades cleanly to plain text on ASCII-only terminals. Include
// any trailing spacing inside e so the ASCII fallback leaves no stray gap:
//
//	u.Section(u.Emoji("🔍  ") + "Discovering agents")
func (u *UI) Emoji(e string) string {
	if u.g.useUTF8 {
		return e
	}
	return ""
}

// Section renders a section heading.
//
//	❯ Infrastructure
func (u *UI) Section(title string) string {
	title = sanitize(title)
	arrowStyle := u.r.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(colorAccent))
	textStyle := u.r.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(colorTitle))

	return arrowStyle.Render(u.g.arrow) + " " + textStyle.Render(title)
}

// Box renders a titled bordered box containing body text.
//
//	╭─ Install summary ────╮
//	│ …body…               │
//	╰──────────────────────╯
func (u *UI) Box(title, body string) string {
	title = sanitize(title)
	body = sanitizeLines(body)

	titleStyle := u.r.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(colorAccent))

	heading := titleStyle.Render(title)
	content := heading + "\n" + body

	var boxStyle lipgloss.Style
	if u.g.useUTF8 {
		boxStyle = u.r.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color(colorAccent)).
			Padding(0, 1)
	} else {
		boxStyle = u.r.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color(colorDim)).
			Padding(0, 1)
	}
	return boxStyle.Render(content)
}

// Badge renders a colored pill. Supported kinds:
//   - "ok"   → green ✓ glyph
//   - "warn" → amber ● glyph
//   - "fail" → red ✗ glyph
//   - "info" → accent, bold, NO glyph (info/progress lines are clean)
//   - "dim"  → gray, no glyph (any other value also maps here)
func (u *UI) Badge(kind, text string) string {
	text = sanitize(text)

	var fg string
	var glyph string
	switch kind {
	case "ok":
		fg = colorGreen
		glyph = u.g.ok + " "
	case "warn":
		fg = colorYellow
		glyph = u.g.bullet + " "
	case "fail":
		fg = colorRed
		glyph = u.g.fail + " "
	case "info":
		fg = colorAccent
		glyph = "" // no bullet — info/progress lines don't need glyph noise
	default:
		fg = colorDim
		glyph = ""
	}

	style := u.r.NewStyle().
		Foreground(lipgloss.Color(fg)).
		Bold(kind != "dim")

	return style.Render(glyph + text)
}

// Step renders a single install step line:
//
//	[1/6] ✓ Installing hooks
//	[2/6] ❯ Writing config   (not done)
func (u *UI) Step(n, total int, text string, done bool) string {
	text = sanitize(text)

	counterStyle := u.r.NewStyle().Foreground(lipgloss.Color(colorDim))
	counter := counterStyle.Render(fmt.Sprintf("[%d/%d]", n, total))

	var glyphStr string
	var glyphStyle lipgloss.Style
	if done {
		glyphStyle = u.r.NewStyle().Foreground(lipgloss.Color(colorGreen))
		glyphStr = u.g.ok
	} else {
		glyphStyle = u.r.NewStyle().Foreground(lipgloss.Color(colorAccent))
		glyphStr = u.g.arrow
	}

	return counter + " " + glyphStyle.Render(glyphStr) + " " + text
}

// KeyValue renders a single label = value row with an optional badge appended.
//
//	daemon path    /usr/local/bin/agentjail-daemon   ● ok
func (u *UI) KeyValue(label, value, badge string) string {
	label = sanitize(label)
	value = sanitize(value)

	labelStyle := u.r.NewStyle().
		Foreground(lipgloss.Color(colorDim)).
		Width(16)
	valueStyle := u.r.NewStyle().
		Foreground(lipgloss.Color(colorWhite))

	row := labelStyle.Render(label) + "  " + valueStyle.Render(value)
	if badge != "" {
		// badge is already sanitized inside Badge(); pass it as-is.
		row += "  " + badge
	}
	return row
}

// Option renders a single selectable row for an interactive picker list.
// It is intended to be used inside a Bubble Tea View() method.
//
// When highlighted is true the cursor indicator (❯ / >) and the label are
// styled with the brand accent colour.  When checked is true the checkbox
// shows the ok glyph (✓ / [x]); otherwise it shows the empty-box glyph
// (✗ / [ ]).  The detail string, if non-empty, is rendered dimmed after the
// label in parentheses.
//
// Example output (UTF-8, colour):
//
//	❯ [✓] Claude Code  (~/.claude/ found)
//	  [✓] Codex        (codex on PATH)
func (u *UI) Option(label, detail string, checked, highlighted bool) string {
	label = sanitize(label)
	detail = sanitize(detail)

	// Cursor indicator.
	var cursor string
	if highlighted {
		cursorStyle := u.r.NewStyle().Bold(true).Foreground(lipgloss.Color(colorAccent))
		cursor = cursorStyle.Render(u.g.arrow) + " "
	} else {
		cursor = "  "
	}

	// Checkbox.
	var checkbox string
	if checked {
		cbStyle := u.r.NewStyle().Foreground(lipgloss.Color(colorGreen))
		if u.g.useUTF8 {
			checkbox = cbStyle.Render("[✓]")
		} else {
			checkbox = cbStyle.Render("[x]")
		}
	} else {
		cbStyle := u.r.NewStyle().Foreground(lipgloss.Color(colorDim))
		checkbox = cbStyle.Render("[ ]")
	}

	// Label — accent + bold when highlighted, plain otherwise.
	var lbl string
	if highlighted {
		lbl = u.r.NewStyle().Bold(true).Foreground(lipgloss.Color(colorAccent)).Render(label)
	} else {
		lbl = label
	}

	// Detail — always dimmed.
	var det string
	if detail != "" {
		det = " " + u.r.NewStyle().Foreground(lipgloss.Color(colorDim)).Render("("+detail+")")
	}

	return cursor + checkbox + " " + lbl + det
}
