// Package picker provides an interactive multi-select terminal UI built on
// Bubble Tea for install flows where stdin may be a pipe (e.g. curl | sh).
//
// Input is handled via tea.WithInputTTY() — Bubble Tea opens /dev/tty for
// keyboard input itself. Output goes to a /dev/tty handle opened by RunPicker.
// This means the picker works correctly under `curl | sh` or `bash | sh` even
// though os.Stdin is a pipe: the shell script carries on stdin, but the picker
// reads keystrokes directly from the controlling terminal.
//
// ErrNoTTY is returned only when /dev/tty cannot be opened at all (headless
// CI, cron, a container without a controlling terminal). In that case the
// install orchestrator falls back to install-all without user interaction.
//
// Typical usage:
//
//	items := []picker.Item{
//	    {ID: "claude-code", Label: "Claude Code", Detail: "~/.claude/ found", Checked: true},
//	    {ID: "codex",       Label: "Codex",       Detail: "codex on PATH",    Checked: true},
//	}
//	ids, err := picker.RunPicker(items)
//	switch {
//	case errors.Is(err, picker.ErrNoTTY):
//	    // no controlling terminal — fall back to install-all
//	case errors.Is(err, picker.ErrCancelled):
//	    // user pressed q/Ctrl-C — install nothing
//	case errors.Is(err, picker.ErrAborted):
//	    // abnormal failure after tty open — surface and exit non-zero
//	}
package picker

import (
	"errors"
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/LuD1161/agentjail/internal/ui"
)

// ── Error sentinels ────────────────────────────────────────────────────────────

// ErrNoTTY is returned by RunPicker when openTTY() cannot open /dev/tty —
// meaning there is no controlling terminal (headless CI, cron, containers).
// This is the sole sentinel that the install orchestrator maps to the
// non-interactive "select all" fallback. It is NOT related to stdin; the
// picker uses tea.WithInputTTY() and does not inspect os.Stdin at all.
var ErrNoTTY = errors.New("picker: /dev/tty unavailable")

// ErrCancelled is returned by RunPicker when the user presses q or Ctrl-C.
// The orchestrator should treat a cancelled picker as "install nothing".
var ErrCancelled = errors.New("picker: cancelled")

// ErrAborted is returned by RunPicker for any abnormal failure AFTER the tty
// was successfully opened: raw-mode/program setup failure, tea.Program.Run()
// returned an error, or the program ended without an explicit confirm or cancel
// decision (e.g. unexpected EOF mid-session). A raw-mode failure on an opened
// tty is NOT "no terminal" — it must be ErrAborted, never ErrNoTTY. The
// orchestrator should surface the error and exit non-zero.
var ErrAborted = errors.New("picker: aborted")

// Item represents a single selectable entry in the picker list.
type Item struct {
	ID      string // machine identifier, e.g. "claude-code"
	Label   string // human-readable name, e.g. "Claude Code"
	Detail  string // discovery evidence shown after the label, e.g. "~/.claude/ found"
	Checked bool   // whether this item is currently selected
}

// openTTY is the /dev/tty opener, factored out so tests can override it to
// simulate the ErrNoTTY path without requiring a real terminal.
var openTTY = func() (*os.File, error) {
	return os.OpenFile("/dev/tty", os.O_RDWR, 0)
}

// ── Pure state machine ────────────────────────────────────────────────────────

// pickerState is the pure state of the picker. All mutation functions return a
// new value rather than mutating in place, making them directly unit-testable.
type pickerState struct {
	items  []Item
	cursor int
}

// newPickerState constructs a pickerState with a deep copy of the item slice so
// the caller's slice is never mutated.
func newPickerState(items []Item) pickerState {
	cp := make([]Item, len(items))
	copy(cp, items)
	return pickerState{items: cp, cursor: 0}
}

// cloneItems returns a fresh backing-array copy of the items slice so that
// mutations never alias the caller's slice.
func cloneItems(items []Item) []Item {
	cp := make([]Item, len(items))
	copy(cp, items)
	return cp
}

// moveUp returns a new state with the cursor moved up by one (clamped at 0).
func moveUp(s pickerState) pickerState {
	if s.cursor > 0 {
		s.cursor--
	}
	return s
}

// moveDown returns a new state with the cursor moved down by one (clamped at
// len(items)-1).
func moveDown(s pickerState) pickerState {
	if s.cursor < len(s.items)-1 {
		s.cursor++
	}
	return s
}

// toggle returns a new state with the Checked flag of the highlighted item
// flipped.
func toggle(s pickerState) pickerState {
	if len(s.items) == 0 {
		return s
	}
	s.items = cloneItems(s.items)
	s.items[s.cursor].Checked = !s.items[s.cursor].Checked
	return s
}

// toggleAll checks all items if any are unchecked, otherwise unchecks all.
func toggleAll(s pickerState) pickerState {
	anyUnchecked := false
	for _, it := range s.items {
		if !it.Checked {
			anyUnchecked = true
			break
		}
	}
	s.items = cloneItems(s.items)
	for i := range s.items {
		s.items[i].Checked = anyUnchecked
	}
	return s
}

// action is the semantic result of processing a single key event.
type action int

const (
	actionNone    action = iota
	actionConfirm        // user pressed Enter
	actionCancel         // user pressed q or Ctrl-C
)

// keyKind enumerates the distinct logical keys the picker handles.
type keyKind int

const (
	keyUp      keyKind = iota // ↑ or k
	keyDown                   // ↓ or j
	keySpace                  // space — toggle
	keyToggleA                // a — toggle all
	keyEnter                  // enter — confirm
	keyCancel                 // q or ctrl+c — cancel
	keyUnknown                // anything else — ignore
)

// keyEvent is a decoded key press passed to applyKey.
type keyEvent struct {
	kind keyKind
}

// applyKey dispatches a key event to the pure state machine, returning the new
// state and the resulting action. It never touches I/O and is directly
// unit-testable.
func applyKey(s pickerState, ev keyEvent) (pickerState, action) {
	switch ev.kind {
	case keyUp:
		return moveUp(s), actionNone
	case keyDown:
		return moveDown(s), actionNone
	case keySpace:
		return toggle(s), actionNone
	case keyToggleA:
		return toggleAll(s), actionNone
	case keyEnter:
		return s, actionConfirm
	case keyCancel:
		return s, actionCancel
	default:
		return s, actionNone
	}
}

// ── Rendering ─────────────────────────────────────────────────────────────────

// render produces the full picker UI as a string using the internal/ui styling
// helpers. The u parameter is bound to the tty writer so Lip Gloss detects the
// correct color profile. The output is designed for Bubble Tea's full-screen
// redraw: the framework manages clearing and redrawing on every key press.
func render(s pickerState, u *ui.UI) string {
	var sb strings.Builder

	// Title line — styled as a Section heading (violet accent arrow + bold text).
	sb.WriteString(u.Section(u.Emoji("🧩  ") + "Select coding agents to protect"))
	sb.WriteString("\n\n")

	for i, item := range s.items {
		highlighted := i == s.cursor
		sb.WriteString(u.Option(item.Label, item.Detail, item.Checked, highlighted))
		sb.WriteString("\n")
	}

	// Footer hint — dimmed, set off by a blank line.
	sb.WriteString("\n")
	hint := u.Badge("dim", "↑/↓ move · space toggle · a all/none · enter confirm · q cancel")
	sb.WriteString(hint)

	// Return plain "\n"-separated content: Bubble Tea's renderer owns cursor and
	// line positioning. (The previous code converted "\n"→"\r\n", a leftover from
	// the old raw-mode picker; the injected carriage returns sent the cursor to
	// column 0 right before Bubble Tea's per-line erase, blanking every line.)
	return sb.String()
}

// ── Bubble Tea model ──────────────────────────────────────────────────────────

// pickerModel is the Bubble Tea model for the multi-select picker.
// The confirmed/cancelled fields track the explicit decision state:
//   - neither set → program ended without explicit user decision → ErrAborted
//   - confirmed = true → user pressed Enter → return checked IDs
//   - cancelled = true → user pressed q/Ctrl-C → ErrCancelled
type pickerModel struct {
	state     pickerState
	ui        *ui.UI // styling helper bound to the tty writer
	confirmed bool
	cancelled bool
}

// Init is called once when the program starts; no I/O commands needed.
func (m pickerModel) Init() tea.Cmd {
	return nil
}

// Update handles Bubble Tea messages (key events, window size, etc.).
func (m pickerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		ev := teaKeyToEvent(msg)
		newState, act := applyKey(m.state, ev)
		m.state = newState
		switch act {
		case actionConfirm:
			m.confirmed = true
			return m, tea.Quit
		case actionCancel:
			m.cancelled = true
			return m, tea.Quit
		}
	}
	return m, nil
}

// View renders the picker UI for Bubble Tea. Bubble Tea manages the redraw
// cycle, so we return the full rendered string on every call.
func (m pickerModel) View() string {
	return render(m.state, m.ui)
}

// teaKeyToEvent maps a tea.KeyMsg to our internal keyEvent type.
func teaKeyToEvent(msg tea.KeyMsg) keyEvent {
	switch msg.Type {
	case tea.KeyUp:
		return keyEvent{keyUp}
	case tea.KeyDown:
		return keyEvent{keyDown}
	case tea.KeyEnter:
		return keyEvent{keyEnter}
	case tea.KeyCtrlC:
		return keyEvent{keyCancel}
	case tea.KeySpace:
		return keyEvent{keySpace}
	case tea.KeyRunes:
		switch string(msg.Runes) {
		case "k":
			return keyEvent{keyUp}
		case "j":
			return keyEvent{keyDown}
		case "a":
			return keyEvent{keyToggleA}
		case "q":
			return keyEvent{keyCancel}
		}
	}
	return keyEvent{keyUnknown}
}

// ── RunPicker ─────────────────────────────────────────────────────────────────

// RunPicker opens /dev/tty and displays an interactive multi-select picker
// powered by Bubble Tea.
//
// Confirm-only contract (non-negotiable): selected IDs are returned ONLY when
// the user presses Enter (explicit confirm). If the program ends for any other
// reason — EOF, an unexpected quit, or any path other than Enter — ErrAborted
// is returned and no IDs are returned. This fixes the silent "install all" bug
// where a non-error early exit fell through to returning all checked items.
//
// Error table:
//   - ErrNoTTY    — /dev/tty could not be opened (no controlling terminal).
//     The ONLY sentinel that triggers the non-interactive "select all" fallback.
//   - ErrCancelled — user pressed q or Ctrl-C. Install nothing.
//   - ErrAborted   — any abnormal failure after the tty was opened: raw-mode or
//     program setup failure, tea.Program.Run() returned an error, or the program
//     ended without an explicit confirm/cancel decision.
func RunPicker(items []Item) (selectedIDs []string, err error) {
	// Open /dev/tty for OUTPUT. If it cannot be opened, there is no controlling
	// terminal (e.g. CI/cron) → ErrNoTTY → the orchestrator falls back to
	// install-all (documented non-interactive behavior). This /dev/tty
	// availability check — NOT a stdin check — is what distinguishes "a human at
	// a terminal" (curl | sh included) from "truly headless".
	tty, err := openTTY()
	if err != nil {
		return nil, ErrNoTTY
	}
	defer tty.Close()

	// Bind the UI styler to the tty so Lip Gloss auto-detects the color profile
	// (NO_COLOR, TERM=dumb, etc.) from the actual terminal file descriptor.
	u := ui.New(tty)

	m := pickerModel{
		state: newPickerState(items),
		ui:    u,
	}

	// Input via tea.WithInputTTY(): Bubble Tea opens /dev/tty itself for input.
	// This is the canonical idiom for staying interactive under `curl | sh`,
	// where os.Stdin is the pipe carrying the script (so WithInput(os.Stdin)
	// would see EOF and WithInput(tty) alone did not render). Output goes to the
	// /dev/tty handle opened above.
	p := tea.NewProgram(m,
		tea.WithInputTTY(),
		tea.WithOutput(tty),
	)

	finalModel, runErr := p.Run()
	if runErr != nil {
		// tea.Program.Run() returned an error (raw-mode setup failure, etc.)
		// → ErrAborted, never ErrNoTTY.
		return nil, fmt.Errorf("%w: %v", ErrAborted, runErr)
	}

	result, ok := finalModel.(pickerModel)
	if !ok {
		// Should never happen; defensive guard.
		return nil, ErrAborted
	}

	// CONFIRM-ONLY CONTRACT: only return IDs on explicit Enter confirm.
	// If neither confirmed nor cancelled, the program ended without a decision
	// (unexpected EOF, etc.) → ErrAborted.
	switch {
	case result.confirmed:
		var ids []string
		for _, item := range result.state.items {
			if item.Checked {
				ids = append(ids, item.ID)
			}
		}
		return ids, nil

	case result.cancelled:
		return nil, ErrCancelled

	default:
		// Program ended without explicit confirm or cancel → ErrAborted.
		// NEVER fall through to returning checked items.
		return nil, ErrAborted
	}
}
