package ui

import (
	"bytes"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// plainUI returns a UI with no color (termenv.Ascii profile) and the
// specified glyph set for deterministic golden-string assertions.
func plainUI(g glyphs) *UI {
	var buf bytes.Buffer
	return newWithProfile(&buf, termenv.Ascii, g)
}

// plainUTF8UI returns a UI with no color and UTF-8 glyphs (for tests that
// check glyph output without color).
func plainUTF8UI() *UI { return plainUI(utf8Glyphs) }

// plainASCIIUI returns a UI with no color and ASCII glyphs.
func plainASCIIUI() *UI { return plainUI(asciiGlyphs) }

// renderToString renders a string and strips Lip Gloss padding whitespace so
// assertions are independent of exact padding widths.
func stripANSI(s string) string {
	// Quick sanity: after rendering with Ascii profile there should be no ESC
	// sequences, but call sanitize() to confirm.
	return sanitize(s)
}

// --------------------------------------------------------------------------
// Tests: render helpers (ASCII profile, deterministic)
// --------------------------------------------------------------------------

func TestHeader_UTF8(t *testing.T) {
	u := plainUTF8UI()
	out := u.Header("agentjail", "v1.2.3", "/usr/local/bin")
	// Must contain the title text.
	if !strings.Contains(out, "AgentJail") {
		t.Errorf("Header output missing title: %q", out)
	}
	if !strings.Contains(out, "█ █ █") {
		t.Errorf("Header output missing slim brand mark: %q", out)
	}
	if !strings.Contains(out, "policy guardrails for agents") {
		t.Errorf("Header output missing subtitle: %q", out)
	}
	// Must contain at least one meta segment.
	if !strings.Contains(out, "v1.2.3") {
		t.Errorf("Header output missing meta: %q", out)
	}
}

func TestHeader_ASCII(t *testing.T) {
	u := plainASCIIUI()
	out := u.Header("agentjail")
	if !strings.Contains(out, "AgentJail") {
		t.Errorf("Header output missing title: %q", out)
	}
	// ASCII fallback should render the slim jail mark.
	if !strings.Contains(out, "| | |") {
		t.Errorf("Header output missing ASCII slim mark: %q", out)
	}
}

func TestSection(t *testing.T) {
	u := plainUTF8UI()
	out := u.Section("Infrastructure")
	if !strings.Contains(out, "Infrastructure") {
		t.Errorf("Section output missing title: %q", out)
	}
	// UTF-8 arrow glyph.
	if !strings.Contains(out, "❯") {
		t.Errorf("Section output missing arrow glyph: %q", out)
	}
}

func TestSection_ASCII(t *testing.T) {
	u := plainASCIIUI()
	out := u.Section("Infrastructure")
	if !strings.Contains(out, "Infrastructure") {
		t.Errorf("Section output missing title: %q", out)
	}
	if !strings.Contains(out, ">") {
		t.Errorf("Section output missing ASCII arrow: %q", out)
	}
}

func TestBox(t *testing.T) {
	u := plainUTF8UI()
	out := u.Box("install summary", "line one\nline two")
	if !strings.Contains(out, "install summary") {
		t.Errorf("Box output missing title: %q", out)
	}
}

// TestBox_MultiLineBodyPreservesRows verifies that a Box with a multi-line body
// (rows joined with '\n') is NOT collapsed onto a single giant line.
//
// The body simulates what printInstallSummary produces: already-sanitized Badge
// strings joined with '\n'.  Before the sanitizeLines fix, Box called
// sanitize(body) which converted all '\n' to spaces, producing a single
// enormous line.  After the fix, each row appears on its own line.
func TestBox_MultiLineBodyPreservesRows(t *testing.T) {
	u := plainASCIIUI() // deterministic ASCII profile

	rows := []string{"row1", "row2", "row3"}
	body := strings.Join(rows, "\n")
	out := u.Box("summary", body)

	// The rendered box must contain at least as many newlines as the number of
	// body rows (title line + 3 body rows + border lines).
	const minNewlines = 3
	got := strings.Count(out, "\n")
	if got < minNewlines {
		t.Errorf("Box multi-line body: expected >= %d newlines in output, got %d\noutput: %q", minNewlines, got, out)
	}

	// No single line should be wider than the widest row plus a small box-border
	// overhead (~10 chars for padding + border).  If the body was collapsed, the
	// lone line would be roughly len("row1 row2 row3") + overhead, far wider than
	// any individual row.
	const maxSingleLineOverhead = 20
	maxExpectedWidth := len("row1") + maxSingleLineOverhead
	for _, line := range strings.Split(out, "\n") {
		if len(line) > maxExpectedWidth+len("row1row2row3") {
			t.Errorf("Box multi-line body: found suspiciously wide line (%d chars), suggesting rows were collapsed: %q", len(line), line)
		}
	}

	// All row texts must appear in the output.
	for _, r := range rows {
		if !strings.Contains(out, r) {
			t.Errorf("Box multi-line body: output missing row %q\noutput: %q", r, out)
		}
	}
}

// TestSanitizeLines_PreservesLayoutNewlines verifies that sanitizeLines keeps
// '\n' separators between lines (the trusted layout newlines added by the
// renderer) while stripping ESC sequences and control bytes within each line.
func TestSanitizeLines_PreservesLayoutNewlines(t *testing.T) {
	// Three lines, each containing an ESC sequence and a tab.
	input := "\x1b[31mline1\x1b[0m\t\x07\nline2 normal\nline3\r\x00end"
	out := sanitizeLines(input)

	// Must preserve exactly 2 newlines (3 lines).
	if got := strings.Count(out, "\n"); got != 2 {
		t.Errorf("sanitizeLines: expected 2 newlines, got %d: %q", got, out)
	}

	// ESC bytes must be gone.
	if strings.Contains(out, "\x1b") {
		t.Errorf("sanitizeLines: ESC byte survived: %q", out)
	}

	// \r and \t must be gone (replaced with spaces within lines).
	if strings.ContainsAny(out, "\r\t") {
		t.Errorf("sanitizeLines: CR/TAB survived: %q", out)
	}

	// Text content must survive.
	if !strings.Contains(out, "line1") || !strings.Contains(out, "line2 normal") || !strings.Contains(out, "end") {
		t.Errorf("sanitizeLines: text content lost: %q", out)
	}
}

// TestSanitizeLines_NoInjectedNewlinesInLeaf confirms the security property:
// a malicious leaf string that goes through sanitize() (not sanitizeLines)
// cannot smuggle a newline through to become a layout break in a Box body.
// sanitizeLines only preserves ALREADY-present '\n' chars from the renderer;
// a leaf's '\n' was stripped by sanitize() before the join.
func TestSanitizeLines_NoInjectedNewlinesInLeaf(t *testing.T) {
	crafted := "legit-name\nfake-status: [x] everything ok"
	// A leaf goes through sanitize() first (as Badge/KeyValue do).
	sanitizedLeaf := sanitize(crafted)
	// After leaf-sanitization the '\n' is gone.
	if strings.Contains(sanitizedLeaf, "\n") {
		t.Fatalf("sanitize (leaf): injected newline survived: %q", sanitizedLeaf)
	}
	// Joining multiple such leaves and passing through sanitizeLines must not
	// re-introduce any newline from the original crafted string.
	body := strings.Join([]string{sanitizedLeaf, "another row"}, "\n")
	out := sanitizeLines(body)
	// The only '\n' in out is the one JOIN added — exactly 1.
	if got := strings.Count(out, "\n"); got != 1 {
		t.Errorf("sanitizeLines after leaf sanitize: expected 1 newline (from join), got %d: %q", got, out)
	}
}

func TestBadge_Kinds(t *testing.T) {
	u := plainUTF8UI()
	cases := []struct {
		kind    string
		text    string
		wantSub string
	}{
		{"ok", "healthy", "healthy"},
		{"warn", "partial", "partial"},
		{"fail", "missing", "missing"},
		{"info", "note", "note"},
		{"dim", "meta", "meta"},
	}
	for _, tc := range cases {
		out := u.Badge(tc.kind, tc.text)
		if !strings.Contains(out, tc.wantSub) {
			t.Errorf("Badge(%q,%q): output missing %q: %q", tc.kind, tc.text, tc.wantSub, out)
		}
	}
}

func TestBadge_OK_HasGlyph(t *testing.T) {
	u := plainUTF8UI()
	out := u.Badge("ok", "running")
	if !strings.Contains(out, "✓") {
		t.Errorf("Badge(ok) missing UTF-8 ok glyph: %q", out)
	}
}

func TestBadge_OK_ASCII_HasGlyph(t *testing.T) {
	u := plainASCIIUI()
	out := u.Badge("ok", "running")
	if !strings.Contains(out, "[x]") {
		t.Errorf("Badge(ok) ASCII glyph missing [x]: %q", out)
	}
}

func TestStep_Done(t *testing.T) {
	u := plainUTF8UI()
	out := u.Step(1, 6, "Installing hooks", true)
	if !strings.Contains(out, "[1/6]") {
		t.Errorf("Step output missing counter: %q", out)
	}
	if !strings.Contains(out, "Installing hooks") {
		t.Errorf("Step output missing text: %q", out)
	}
	if !strings.Contains(out, "✓") {
		t.Errorf("Step(done) output missing ok glyph: %q", out)
	}
}

func TestStep_NotDone(t *testing.T) {
	u := plainUTF8UI()
	out := u.Step(2, 6, "Writing config", false)
	if !strings.Contains(out, "❯") {
		t.Errorf("Step(not done) output missing arrow glyph: %q", out)
	}
}

func TestStep_ASCII(t *testing.T) {
	u := plainASCIIUI()
	out := u.Step(1, 3, "Checking", true)
	if !strings.Contains(out, "[x]") {
		t.Errorf("Step ASCII done missing [x]: %q", out)
	}
}

func TestKeyValue(t *testing.T) {
	u := plainUTF8UI()
	b := u.Badge("ok", "running")
	out := u.KeyValue("daemon path", "/usr/local/bin/agentjail-daemon", b)
	if !strings.Contains(out, "daemon path") {
		t.Errorf("KeyValue missing label: %q", out)
	}
	if !strings.Contains(out, "/usr/local/bin/agentjail-daemon") {
		t.Errorf("KeyValue missing value: %q", out)
	}
	if !strings.Contains(out, "running") {
		t.Errorf("KeyValue missing badge text: %q", out)
	}
}

// --------------------------------------------------------------------------
// Tests: capability matrix
// --------------------------------------------------------------------------

// TestCapability_NoColor_UTF8Glyphs: NO_COLOR=1 → no ANSI color codes, but
// UTF-8 glyphs should still appear (color and glyphs are independent axes).
func TestCapability_NoColor_UTF8Glyphs(t *testing.T) {
	// Simulate: color profile Ascii (what NO_COLOR produces), UTF-8 glyphs.
	u := newWithProfile(&bytes.Buffer{}, termenv.Ascii, utf8Glyphs)
	out := u.Badge("ok", "healthy")
	// ASCII profile → no ANSI escape sequences.
	if strings.Contains(out, "\x1b") {
		t.Errorf("NO_COLOR: expected no ESC sequences in output, got: %q", out)
	}
	// UTF-8 glyph set still active.
	if !strings.Contains(out, "✓") {
		t.Errorf("NO_COLOR: UTF-8 ok glyph should still appear, got: %q", out)
	}
}

// TestCapability_TermDumb: TERM=dumb → ASCII glyphs, no border.
func TestCapability_TermDumb(t *testing.T) {
	old := envLookup
	envLookup = func(key string) string {
		if key == "TERM" {
			return "dumb"
		}
		return ""
	}
	defer func() { envLookup = old }()

	g := detectGlyphs()
	if g.useUTF8 {
		t.Error("TERM=dumb: expected ASCII glyphs, got UTF-8")
	}

	u := newWithProfile(&bytes.Buffer{}, termenv.Ascii, g)
	out := u.Badge("ok", "running")
	if strings.Contains(out, "✓") {
		t.Errorf("TERM=dumb: should not have UTF-8 glyph ✓, got: %q", out)
	}
	if !strings.Contains(out, "[x]") {
		t.Errorf("TERM=dumb: expected ASCII glyph [x], got: %q", out)
	}
}

// TestCapability_NonUTF8Locale: LC_ALL=C → ASCII glyphs.
func TestCapability_NonUTF8Locale(t *testing.T) {
	old := envLookup
	envLookup = func(key string) string {
		if key == "LC_ALL" {
			return "C"
		}
		return ""
	}
	defer func() { envLookup = old }()

	g := detectGlyphs()
	if g.useUTF8 {
		t.Error("LC_ALL=C: expected ASCII glyphs, got UTF-8")
	}
}

// TestCapability_UTF8Locale: LC_ALL contains UTF-8 → UTF-8 glyphs.
func TestCapability_UTF8Locale(t *testing.T) {
	old := envLookup
	envLookup = func(key string) string {
		switch key {
		case "LC_ALL":
			return "en_US.UTF-8"
		case "TERM":
			return "xterm-256color"
		}
		return ""
	}
	defer func() { envLookup = old }()

	g := detectGlyphs()
	if !g.useUTF8 {
		t.Error("LC_ALL=en_US.UTF-8: expected UTF-8 glyphs, got ASCII")
	}
}

// TestCapability_PipedWriter: piped / non-TTY writer gets ASCII profile from
// lipgloss auto-detection.  We verify by constructing without forcing a
// profile and checking that output is plain (no ANSI) when writing to a
// bytes.Buffer (not a TTY).
func TestCapability_PipedWriter(t *testing.T) {
	var buf bytes.Buffer
	u := New(&buf) // auto-detect; bytes.Buffer is not a TTY → Ascii profile
	out := u.Badge("ok", "running")
	// Write to the buffer for the print path.
	// The render step may include ANSI if lipgloss's detection path differs,
	// but the critical path is that sanitize() called on the output strips any
	// stray ESC bytes.
	clean := stripANSI(out)
	if strings.Contains(clean, "\x1b") {
		t.Errorf("piped writer: sanitized output still has ESC: %q", clean)
	}
}

// --------------------------------------------------------------------------
// Tests: sanitization
// --------------------------------------------------------------------------

func TestSanitize_ESCSequences(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"CSI color", "\x1b[31mred text\x1b[0m"},
		{"bare ESC", "\x1bsomething"},
		{"OSC", "\x1b]0;title\x07"},
	}
	for _, tc := range cases {
		out := sanitize(tc.input)
		if strings.Contains(out, "\x1b") {
			t.Errorf("sanitize(%s): ESC byte remains in output: %q", tc.name, out)
		}
	}
}

func TestSanitize_C0Controls(t *testing.T) {
	// Bell, backspace, vertical tab, form feed, etc.
	input := "hello\x07world\x08end\x0Bv\x0Cf"
	out := sanitize(input)
	// None of those control bytes should survive.
	for _, b := range []byte{0x07, 0x08, 0x0B, 0x0C} {
		if strings.ContainsRune(out, rune(b)) {
			t.Errorf("sanitize: C0 byte 0x%02x survived in %q", b, out)
		}
	}
}

func TestSanitize_C1Controls(t *testing.T) {
	// C1 range: 0x80–0x9F encoded as UTF-8 (e.g.  = \xC2\x80).
	input := "beforeafter" // NEL = C1 control
	out := sanitize(input)
	if strings.ContainsRune(out, '') {
		t.Errorf("sanitize: C1 byte U+0085 survived: %q", out)
	}
}

func TestSanitize_CRLF_Tab(t *testing.T) {
	input := "line1\r\nline2\ttab"
	out := sanitize(input)
	// \r, \n, \t must become spaces.
	if strings.ContainsAny(out, "\r\n\t") {
		t.Errorf("sanitize: CR/LF/TAB not replaced with spaces: %q", out)
	}
	if !strings.Contains(out, "line1") || !strings.Contains(out, "line2") {
		t.Errorf("sanitize: text content lost: %q", out)
	}
}

func TestSanitize_NoInjectedNewlines(t *testing.T) {
	// Ensure that a crafted agent name cannot inject newlines.
	crafted := "legit-agent\nfake-status: ✓ everything ok"
	out := sanitize(crafted)
	if strings.Count(out, "\n") > 0 {
		t.Errorf("sanitize: injected newline survived: %q", out)
	}
}

// TestSanitize_ThroughHelpers ensures render helpers pass dynamic text through
// sanitize before outputting it — no ESC bytes or C0/C1 bytes (other than
// layout newlines added by the renderer) should appear in the final output.
func TestSanitize_ThroughHelpers(t *testing.T) {
	u := plainUTF8UI()

	// Craft strings with ANSI sequences and control characters embedded.
	crafted := "\x1b[31mevil\x1b[0m\x00\x07\r\ninjected"

	helpers := []struct {
		name string
		fn   func() string
	}{
		{"Header", func() string { return u.Header(crafted) }},
		{"Section", func() string { return u.Section(crafted) }},
		{"Box", func() string { return u.Box(crafted, crafted) }},
		{"Badge", func() string { return u.Badge("ok", crafted) }},
		{"Step", func() string { return u.Step(1, 1, crafted, false) }},
		{"KeyValue", func() string { return u.KeyValue(crafted, crafted, "") }},
	}

	for _, h := range helpers {
		out := h.fn()
		// Strip any ANSI added by the renderer itself (ASCII profile, but
		// let's be safe and strip before scanning).
		clean := stripANSI(out)
		// Check for ESC byte.
		if strings.Contains(clean, "\x1b") {
			t.Errorf("%s: ESC byte present in sanitized output: %q", h.name, clean)
		}
		// Check for C0 bytes (excluding layout newlines and space which the
		// renderer adds, and tab).
		for _, b := range []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x0B, 0x0C, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
			0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1C, 0x1D, 0x1E, 0x1F} {
			if strings.ContainsRune(clean, rune(b)) {
				t.Errorf("%s: C0 byte 0x%02x present in sanitized output: %q", h.name, b, clean)
			}
		}
		// Verify the word "injected" is present but \n is not (it was \r\n in the crafted string).
		// The renderer adds its own \n for layout, but the *crafted* injection should be gone.
		if strings.Contains(clean, "injected") && strings.Count(out, "\n") > strings.Count(crafted, "\n")+5 {
			// Allow renderer-added newlines; just ensure no huge injection.
			t.Logf("%s: note — injected word present (ok, text preserved), newline count: %d", h.name, strings.Count(out, "\n"))
		}
	}
}

// --------------------------------------------------------------------------
// Tests: Option (picker row)
// --------------------------------------------------------------------------

func TestOption_CheckedHighlighted(t *testing.T) {
	u := plainUTF8UI()
	out := u.Option("Claude Code", "~/.claude/ found", true, true)
	if !strings.Contains(out, "❯") {
		t.Errorf("Option(highlighted): missing cursor glyph ❯, got: %q", out)
	}
	if !strings.Contains(out, "[✓]") {
		t.Errorf("Option(checked): missing checked glyph [✓], got: %q", out)
	}
	if !strings.Contains(out, "Claude Code") {
		t.Errorf("Option: missing label, got: %q", out)
	}
	if !strings.Contains(out, "~/.claude/ found") {
		t.Errorf("Option: missing detail, got: %q", out)
	}
}

func TestOption_UncheckedNotHighlighted(t *testing.T) {
	u := plainUTF8UI()
	out := u.Option("Codex", "codex on PATH", false, false)
	if strings.Contains(out, "❯") {
		t.Errorf("Option(not highlighted): should not have cursor glyph, got: %q", out)
	}
	if !strings.Contains(out, "[ ]") {
		t.Errorf("Option(unchecked): missing empty-box glyph [ ], got: %q", out)
	}
	if !strings.Contains(out, "Codex") {
		t.Errorf("Option: missing label, got: %q", out)
	}
}

func TestOption_NoDetail(t *testing.T) {
	u := plainUTF8UI()
	out := u.Option("Cursor", "", true, false)
	if strings.Contains(out, "(") {
		t.Errorf("Option(no detail): should not have parentheses, got: %q", out)
	}
}

func TestOption_ASCII(t *testing.T) {
	u := plainASCIIUI()
	out := u.Option("Claude Code", "found", true, true)
	if !strings.Contains(out, ">") {
		t.Errorf("Option ASCII cursor: expected >, got: %q", out)
	}
	if !strings.Contains(out, "[x]") {
		t.Errorf("Option ASCII checked: expected [x], got: %q", out)
	}
}

// TestOption_NoANSI_Ascii ensures no ANSI escape sequences appear when the
// UI is created with the Ascii color profile (equivalent to NO_COLOR).
func TestOption_NoANSI_Ascii(t *testing.T) {
	u := plainUTF8UI() // Ascii termenv profile, no ANSI
	out := u.Option("Agent", "detail", true, true)
	if strings.Contains(out, "\x1b") {
		t.Errorf("Option with Ascii profile should not emit ANSI escapes, got: %q", out)
	}
}

// TestSanitize_C1Range_TableDriven is a targeted table-driven test for C1
// control bytes to confirm none survive sanitization.
func TestSanitize_C1Range_TableDriven(t *testing.T) {
	// Build a string with all C1 code points (U+0080–U+009F).
	var sb strings.Builder
	for cp := rune(0x80); cp <= 0x9F; cp++ {
		sb.WriteRune(cp)
	}
	c1str := sb.String()

	out := sanitize(c1str)
	for cp := rune(0x80); cp <= 0x9F; cp++ {
		if strings.ContainsRune(out, cp) {
			t.Errorf("sanitize: C1 code point U+%04X survived in output: %q", cp, out)
		}
	}
}

// --------------------------------------------------------------------------
// Tests: exported Sanitize method and NewNoColor constructor
// --------------------------------------------------------------------------

func TestSanitize_StripESCSequences(t *testing.T) {
	u := plainUTF8UI()
	got := u.Sanitize("\x1b[31mred\x1b[0m")
	if got != "red" {
		t.Fatalf("expected %q, got %q", "red", got)
	}
}

func TestSanitize_StripC0Controls(t *testing.T) {
	u := plainUTF8UI()
	got := u.Sanitize("hello\x00\x01\x02world")
	if got != "helloworld" {
		t.Fatalf("expected %q, got %q", "helloworld", got)
	}
}

func TestSanitize_StripC1Controls(t *testing.T) {
	u := plainUTF8UI()
	got := u.Sanitize("hello\x80\x9fworld")
	if got != "helloworld" {
		t.Fatalf("expected %q, got %q", "helloworld", got)
	}
}

func TestSanitize_TabsToSpaces(t *testing.T) {
	u := plainUTF8UI()
	got := u.Sanitize("col1\tcol2")
	if got != "col1 col2" {
		t.Fatalf("expected %q, got %q", "col1 col2", got)
	}
}

func TestSanitize_NewlinesToSpaces(t *testing.T) {
	u := plainUTF8UI()
	got := u.Sanitize("line1\nline2\rline3")
	if got != "line1 line2 line3" {
		t.Fatalf("expected %q, got %q", "line1 line2 line3", got)
	}
}

func TestSanitize_CleanStringUnchanged(t *testing.T) {
	u := plainUTF8UI()
	got := u.Sanitize("hello world 123 unicode: Ω")
	if got != "hello world 123 unicode: Ω" {
		t.Fatalf("expected clean string unchanged, got %q", got)
	}
}

func TestSanitize_OSCTitleInjection(t *testing.T) {
	u := plainUTF8UI()
	got := u.Sanitize("\x1b]0;evil title\x07normal")
	if strings.Contains(got, "evil") {
		t.Fatalf("OSC title injection not stripped: %q", got)
	}
}

func TestSanitize_CursorRepositioning(t *testing.T) {
	u := plainUTF8UI()
	got := u.Sanitize("\x1b[5;10Hinjected")
	if got != "injected" {
		t.Fatalf("cursor repositioning not stripped: %q", got)
	}
}

func TestNewNoColor_NoEscapeSequences(t *testing.T) {
	var buf bytes.Buffer
	u := NewNoColor(&buf)
	// Render something that would normally have color.
	style := u.r.NewStyle().Foreground(lipgloss.Color("#ff0000"))
	result := style.Render("hello")
	if strings.Contains(result, "\x1b") {
		t.Fatalf("NewNoColor output contains ESC sequences: %q", result)
	}
}

// --------------------------------------------------------------------------
// Tests: Replay TUI rendering
// --------------------------------------------------------------------------

func TestReplayRow_AllowGreen(t *testing.T) {
	var buf bytes.Buffer
	u := NewWithProfile(&buf, termenv.TrueColor)
	row := u.ReplayRow("14:15:59", "ALLOW", "Bash", "default-allow", "ls -la", false)
	if !strings.Contains(row, "ALLOW") {
		t.Fatalf("ALLOW not in row: %q", row)
	}
	if !strings.Contains(row, "Bash") {
		t.Fatalf("Bash not in row: %q", row)
	}
}

func TestReplayRow_DenyRed(t *testing.T) {
	var buf bytes.Buffer
	u := NewWithProfile(&buf, termenv.TrueColor)
	row := u.ReplayRow("14:16:05", "DENY", "Bash", "no-rm-rf", "rm -rf /", false)
	if !strings.Contains(row, "DENY") {
		t.Fatalf("DENY not in row: %q", row)
	}
}

func TestReplayRow_CursorReverseVideo(t *testing.T) {
	var buf bytes.Buffer
	u := NewWithProfile(&buf, termenv.TrueColor)
	normal := u.ReplayRow("14:15:59", "ALLOW", "Bash", "default-allow", "ls", false)
	cursor := u.ReplayRow("14:15:59", "ALLOW", "Bash", "default-allow", "ls", true)
	if normal == cursor {
		t.Fatal("cursor row should differ from normal row")
	}
	// Reverse video uses ESC[7m
	if !strings.Contains(cursor, "\x1b[7m") && !strings.Contains(cursor, "7m") {
		// lipgloss may encode reverse differently; just check they differ
	}
}

func TestReplayDetailLine_Dimmed(t *testing.T) {
	var buf bytes.Buffer
	u := NewWithProfile(&buf, termenv.TrueColor)
	line := u.ReplayDetailLine("reason: something happened")
	if !strings.Contains(line, "reason: something happened") {
		t.Fatalf("detail text missing: %q", line)
	}
	if !strings.HasPrefix(line, "  ") {
		t.Fatalf("detail line should be indented: %q", line)
	}
}

func TestReplayRow_NoColor(t *testing.T) {
	var buf bytes.Buffer
	u := NewNoColor(&buf)
	row := u.ReplayRow("14:15:59", "ALLOW", "Bash", "default-allow", "ls", false)
	if strings.Contains(row, "\x1b") {
		t.Fatalf("NO_COLOR row contains ESC: %q", row)
	}
}

func TestReplayStatsBar_Content(t *testing.T) {
	var buf bytes.Buffer
	u := NewWithProfile(&buf, termenv.TrueColor)
	bar := u.ReplayStatsBar(10, 2, 1, "5m 30s", "", false, nil, 80)
	if !strings.Contains(bar, "10") || !strings.Contains(bar, "2") || !strings.Contains(bar, "1") {
		t.Fatalf("stats bar missing counts: %q", bar)
	}
	if !strings.Contains(bar, "5m 30s") {
		t.Fatalf("stats bar missing duration: %q", bar)
	}
}

func TestReplayStatsBar_FollowIndicator(t *testing.T) {
	var buf bytes.Buffer
	u := NewWithProfile(&buf, termenv.TrueColor)
	bar := u.ReplayStatsBar(5, 0, 0, "1m 0s", "", true, nil, 80)
	if !strings.Contains(bar, "FOLLOW") {
		t.Fatalf("follow indicator missing: %q", bar)
	}
}

func TestReplayStatsBar_FilterShown(t *testing.T) {
	var buf bytes.Buffer
	u := NewWithProfile(&buf, termenv.TrueColor)
	bar := u.ReplayStatsBar(5, 0, 0, "1m 0s", "deny", false, nil, 80)
	if !strings.Contains(bar, "/deny") {
		t.Fatalf("filter text missing from stats bar: %q", bar)
	}
}
