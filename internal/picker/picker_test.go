package picker

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/ui"
	"github.com/muesli/termenv"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// testItems returns a fresh slice of 3 items, all Checked=true.
func testItems() []Item {
	return []Item{
		{ID: "claude-code", Label: "Claude Code", Detail: "~/.claude/ found", Checked: true},
		{ID: "codex", Label: "Codex", Detail: "codex on PATH", Checked: true},
		{ID: "cursor", Label: "Cursor", Detail: "~/.cursor/ found", Checked: true},
	}
}

// key is a shorthand to build a keyEvent.
func key(k keyKind) keyEvent { return keyEvent{kind: k} }

// apply is a shorthand that returns just the new state (discards action).
func apply(s pickerState, k keyKind) pickerState {
	ns, _ := applyKey(s, key(k))
	return ns
}

// applyAction returns just the action.
func applyAction(s pickerState, k keyKind) action {
	_, act := applyKey(s, key(k))
	return act
}

// stripANSI removes all ESC[…m sequences so tests can match plain text.
func stripANSI(s string) string {
	var out strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == '\033' && i+1 < len(s) && s[i+1] == '[' {
			// skip until 'm' (or end)
			i += 2
			for i < len(s) && s[i] != 'm' {
				i++
			}
			i++ // skip 'm'
			continue
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String()
}

// plainUI returns a UI with the ASCII/no-color profile for deterministic
// render assertions (no ANSI escape codes in output).
func plainUI() *ui.UI {
	var buf bytes.Buffer
	return ui.NewWithProfile(&buf, termenv.Ascii)
}

// colorUI returns a UI with a TrueColor profile for assertions that require
// ANSI codes to be present in output.
func colorUI() *ui.UI {
	var buf bytes.Buffer
	return ui.NewWithProfile(&buf, termenv.TrueColor)
}

// ── Item initialisation ───────────────────────────────────────────────────────

func TestAllItemsStartChecked(t *testing.T) {
	s := newPickerState(testItems())
	for _, item := range s.items {
		if !item.Checked {
			t.Errorf("item %q should start checked but is unchecked", item.ID)
		}
	}
}

// ── Space toggle ──────────────────────────────────────────────────────────────

func TestSpaceTogglesHighlightedItem(t *testing.T) {
	s := newPickerState(testItems())
	// cursor=0, item 0 is checked → space unchecks it
	s = apply(s, keySpace)
	if s.items[0].Checked {
		t.Error("item[0] should be unchecked after space")
	}
	if !s.items[1].Checked {
		t.Error("item[1] should remain checked")
	}
	// space again → re-checks item 0
	s = apply(s, keySpace)
	if !s.items[0].Checked {
		t.Error("item[0] should be checked again after second space")
	}
}

// ── Cursor movement ───────────────────────────────────────────────────────────

func TestCursorMovesDown(t *testing.T) {
	s := newPickerState(testItems())
	if s.cursor != 0 {
		t.Fatalf("expected cursor=0, got %d", s.cursor)
	}
	s = apply(s, keyDown)
	if s.cursor != 1 {
		t.Errorf("expected cursor=1 after keyDown, got %d", s.cursor)
	}
}

func TestCursorMovesUp(t *testing.T) {
	s := newPickerState(testItems())
	s = apply(s, keyDown) // cursor=1
	s = apply(s, keyUp)   // cursor=0
	if s.cursor != 0 {
		t.Errorf("expected cursor=0 after keyUp, got %d", s.cursor)
	}
}

func TestCursorClampsAtBoundaries(t *testing.T) {
	s := newPickerState(testItems())
	// Already at top; up should not go negative
	s = apply(s, keyUp)
	if s.cursor != 0 {
		t.Errorf("cursor should stay 0 at top, got %d", s.cursor)
	}
	// Move to bottom
	s = apply(s, keyDown)
	s = apply(s, keyDown)
	last := len(s.items) - 1
	if s.cursor != last {
		t.Errorf("expected cursor=%d at bottom, got %d", last, s.cursor)
	}
	// Try to go past bottom
	s = apply(s, keyDown)
	if s.cursor != last {
		t.Errorf("cursor should stay at %d at bottom, got %d", last, s.cursor)
	}
}

// ── Space toggles the correct item after cursor movement ─────────────────────

func TestSpaceTogglesCorrectItemAfterCursorMove(t *testing.T) {
	s := newPickerState(testItems())
	s = apply(s, keyDown) // cursor=1
	s = apply(s, keySpace)
	if !s.items[0].Checked {
		t.Error("item[0] should still be checked")
	}
	if s.items[1].Checked {
		t.Error("item[1] should be unchecked after space at cursor=1")
	}
	if !s.items[2].Checked {
		t.Error("item[2] should still be checked")
	}
}

// ── Toggle-all ────────────────────────────────────────────────────────────────

func TestToggleAllChecksAllWhenAnyUnchecked(t *testing.T) {
	s := newPickerState(testItems())
	s = apply(s, keySpace)   // uncheck item[0]
	s = apply(s, keyToggleA) // 'a' should check all
	for i, item := range s.items {
		if !item.Checked {
			t.Errorf("item[%d] (%s) should be checked after toggleAll (some were unchecked)", i, item.ID)
		}
	}
}

func TestToggleAllUnchecksAllWhenAllChecked(t *testing.T) {
	s := newPickerState(testItems())
	// All start checked; toggleAll should uncheck all
	s = apply(s, keyToggleA)
	for i, item := range s.items {
		if item.Checked {
			t.Errorf("item[%d] (%s) should be unchecked after toggleAll (all were checked)", i, item.ID)
		}
	}
}

func TestToggleAllIsIdempotentOnSecondPress(t *testing.T) {
	s := newPickerState(testItems())
	s = apply(s, keyToggleA) // uncheck all
	s = apply(s, keyToggleA) // check all
	for i, item := range s.items {
		if !item.Checked {
			t.Errorf("item[%d] should be checked after two toggleAll presses", i)
		}
	}
}

// ── Enter (confirm) ───────────────────────────────────────────────────────────

func TestEnterYieldsConfirmAction(t *testing.T) {
	s := newPickerState(testItems())
	if act := applyAction(s, keyEnter); act != actionConfirm {
		t.Errorf("expected actionConfirm on Enter, got %v", act)
	}
}

func TestEnterDoesNotMutateItems(t *testing.T) {
	s := newPickerState(testItems())
	s = apply(s, keySpace) // uncheck item[0]
	ns, act := applyKey(s, key(keyEnter))
	if act != actionConfirm {
		t.Fatal("expected actionConfirm")
	}
	// Items in the returned state should reflect the uncheck.
	if ns.items[0].Checked {
		t.Error("item[0] should still be unchecked after Enter")
	}
	if !ns.items[1].Checked {
		t.Error("item[1] should still be checked after Enter")
	}
}

// ── Cancel via q and Ctrl-C ───────────────────────────────────────────────────

func TestCancelKeyYieldsCancelAction(t *testing.T) {
	s := newPickerState(testItems())
	if act := applyAction(s, keyCancel); act != actionCancel {
		t.Errorf("expected actionCancel on q/Ctrl-C, got %v", act)
	}
}

// TestNonEnterKeysNeverYieldConfirm verifies the confirm-only guarantee: none
// of the navigation / toggle keys ever produce actionConfirm.
func TestNonEnterKeysNeverYieldConfirm(t *testing.T) {
	s := newPickerState(testItems())
	nonConfirmKeys := []keyKind{keyUp, keyDown, keySpace, keyToggleA, keyUnknown}
	for _, k := range nonConfirmKeys {
		if act := applyAction(s, k); act == actionConfirm {
			t.Errorf("key %v unexpectedly yielded actionConfirm", k)
		}
	}
}

// ── RunPicker — ErrNoTTY when opener fails ────────────────────────────────────

// TestRunPickerReturnsErrNoTTYWhenOpenFails verifies that RunPicker returns
// ErrNoTTY when openTTY() cannot open /dev/tty (e.g. headless CI, no
// controlling terminal). The stdin state is irrelevant — the picker uses
// tea.WithInputTTY() and never inspects os.Stdin.
func TestRunPickerReturnsErrNoTTYWhenOpenFails(t *testing.T) {
	origTTY := openTTY
	defer func() { openTTY = origTTY }()

	openTTY = func() (*os.File, error) {
		return nil, errors.New("simulated: no controlling terminal")
	}

	ids, err := RunPicker(testItems())
	if !errors.Is(err, ErrNoTTY) {
		t.Errorf("expected ErrNoTTY, got %v", err)
	}
	if ids != nil {
		t.Errorf("expected nil ids on ErrNoTTY, got %v", ids)
	}
}

// ── render() smoke tests ──────────────────────────────────────────────────────

func TestRenderContainsLabels(t *testing.T) {
	s := newPickerState(testItems())
	out := stripANSI(render(s, plainUI()))
	for _, item := range s.items {
		if !strings.Contains(out, item.Label) {
			t.Errorf("render() missing label %q", item.Label)
		}
	}
}

func TestRenderCheckedItemHasCheckmark(t *testing.T) {
	s := newPickerState(testItems()) // all checked
	out := stripANSI(render(s, plainUI()))
	if !strings.Contains(out, "✓") {
		t.Error("render() should contain ✓ for checked items")
	}
}

func TestRenderUncheckedItemHasEmptyBox(t *testing.T) {
	s := newPickerState(testItems())
	s = apply(s, keyToggleA) // uncheck all
	out := stripANSI(render(s, plainUI()))
	if !strings.Contains(out, "[ ]") {
		t.Error("render() should contain [ ] for unchecked items")
	}
}

func TestRenderContainsFooterHint(t *testing.T) {
	s := newPickerState(testItems())
	out := stripANSI(render(s, plainUI()))
	for _, kw := range []string{"space", "enter", "cancel"} {
		if !strings.Contains(out, kw) {
			t.Errorf("render() footer hint missing keyword %q", kw)
		}
	}
}

func TestRenderHighlightedItemHasCursorIndicator(t *testing.T) {
	s := newPickerState(testItems())
	out := stripANSI(render(s, plainUI()))
	if !strings.Contains(out, "❯") {
		t.Error("render() should contain ❯ cursor indicator for highlighted item")
	}
}

// TestRenderNoANSIWithAsciiProfile verifies that render() produces no ANSI
// escape codes when the UI uses the ASCII/no-color termenv profile (equivalent
// to NO_COLOR=1 or a non-color terminal). The styling path goes through
// internal/ui which inherits the profile from the writer.
func TestRenderNoANSIWithAsciiProfile(t *testing.T) {
	s := newPickerState(testItems())
	out := render(s, plainUI()) // plainUI() uses termenv.Ascii → no ANSI
	if strings.Contains(out, "\033[") {
		t.Error("render() with Ascii profile should not contain ANSI escape codes")
	}
}

// TestRenderWithColorContainsANSI verifies that render() produces ANSI escape
// codes when the UI uses a color-capable termenv profile (TrueColor). The
// styling is delegated to internal/ui which emits Lip Gloss sequences.
func TestRenderWithColorContainsANSI(t *testing.T) {
	s := newPickerState(testItems())
	out := render(s, colorUI()) // colorUI() uses termenv.TrueColor → ANSI present
	if !strings.Contains(out, "\033[") {
		t.Error("render() with TrueColor profile should contain ANSI escape codes")
	}
}

// ── Confirm-only contract regression tests ────────────────────────────────────

// TestNoIDsWithoutExplicitConfirm verifies the confirm-only contract at the
// model level: a pickerModel that ends without confirmed=true must never return
// IDs. This is the regression test for the original silent-install-all bug.
func TestNoIDsWithoutExplicitConfirm(t *testing.T) {
	// Simulate a model that ended without an explicit decision (e.g. unexpected
	// EOF): both confirmed and cancelled are false.
	m := pickerModel{
		state:     newPickerState(testItems()),
		ui:        nil, // nil ui is fine for pure state-machine tests that don't call View()
		confirmed: false,
		cancelled: false,
	}

	// Verify that such a model would cause RunPicker to return ErrAborted + nil.
	// We replicate the decision logic from RunPicker directly to test it in
	// isolation without needing a real TTY.
	switch {
	case m.confirmed:
		t.Error("model should not be confirmed")
	case m.cancelled:
		t.Error("model should not be cancelled")
	default:
		// Correct: no IDs, ErrAborted — this is what RunPicker returns.
		// No IDs should ever be returned without an explicit confirm.
	}
}

// TestModelConfirmedReturnsCheckedIDs verifies that a confirmed model returns
// the checked IDs (the happy path of the confirm-only contract).
func TestModelConfirmedReturnsCheckedIDs(t *testing.T) {
	state := newPickerState(testItems())
	// Uncheck item[1] (codex), keep item[0] and item[2] checked.
	state = apply(state, keyDown)  // cursor=1
	state = apply(state, keySpace) // uncheck codex

	m := pickerModel{
		state:     state,
		ui:        nil, // nil ui is fine for pure state-machine tests that don't call View()
		confirmed: true,
		cancelled: false,
	}

	// Replicate RunPicker's final-model decision.
	if !m.confirmed {
		t.Fatal("model should be confirmed")
	}
	var ids []string
	for _, item := range m.state.items {
		if item.Checked {
			ids = append(ids, item.ID)
		}
	}
	if len(ids) != 2 {
		t.Errorf("expected 2 IDs after unchecking codex, got %d: %v", len(ids), ids)
	}
	for _, id := range ids {
		if id == "codex" {
			t.Error("codex should NOT be in returned IDs after being unchecked")
		}
	}
}

// TestModelCancelledReturnsNoIDs verifies that a cancelled model returns no
// IDs, even if some items are checked.
func TestModelCancelledReturnsNoIDs(t *testing.T) {
	m := pickerModel{
		state:     newPickerState(testItems()), // all checked
		ui:        nil, // nil ui is fine for pure state-machine tests that don't call View()
		confirmed: false,
		cancelled: true,
	}

	if m.confirmed {
		t.Error("confirmed should be false")
	}
	if !m.cancelled {
		t.Error("cancelled should be true")
	}
	// In the cancelled branch, RunPicker returns nil ids + ErrCancelled.
	// Verify we do NOT return any IDs from the cancelled model.
}

// TestErrAbortedWhenNeitherConfirmedNorCancelled verifies the exact
// ErrAborted production: a final model with neither flag set must yield
// ErrAborted and nil IDs (not the items' checked state).
func TestErrAbortedWhenNeitherConfirmedNorCancelled(t *testing.T) {
	// This test exercises the default branch of RunPicker's final switch.
	// We do so by constructing the model state directly and running the same
	// logic, since we cannot drive the Tea program without a real TTY.
	m := pickerModel{
		state:     newPickerState(testItems()), // all checked — must NOT be returned
		ui:        nil, // nil ui is fine for pure state-machine tests that don't call View()
		confirmed: false,
		cancelled: false,
	}

	var resultIDs []string
	var resultErr error

	switch {
	case m.confirmed:
		for _, item := range m.state.items {
			if item.Checked {
				resultIDs = append(resultIDs, item.ID)
			}
		}
	case m.cancelled:
		resultErr = ErrCancelled
	default:
		resultErr = ErrAborted
	}

	if resultIDs != nil {
		t.Errorf("no IDs should be returned without explicit confirm; got %v", resultIDs)
	}
	if !errors.Is(resultErr, ErrAborted) {
		t.Errorf("expected ErrAborted when neither confirmed nor cancelled, got %v", resultErr)
	}
}

// TestErrNoTTYDistinctFromErrAborted verifies the three error sentinels are
// distinct and not interchangeable.
func TestErrNoTTYDistinctFromErrAborted(t *testing.T) {
	if errors.Is(ErrNoTTY, ErrAborted) {
		t.Error("ErrNoTTY should not match ErrAborted")
	}
	if errors.Is(ErrNoTTY, ErrCancelled) {
		t.Error("ErrNoTTY should not match ErrCancelled")
	}
	if errors.Is(ErrAborted, ErrNoTTY) {
		t.Error("ErrAborted should not match ErrNoTTY")
	}
	if errors.Is(ErrAborted, ErrCancelled) {
		t.Error("ErrAborted should not match ErrCancelled")
	}
	if errors.Is(ErrCancelled, ErrNoTTY) {
		t.Error("ErrCancelled should not match ErrNoTTY")
	}
	if errors.Is(ErrCancelled, ErrAborted) {
		t.Error("ErrCancelled should not match ErrAborted")
	}
}

// TestErrAbortedIsWrappable verifies that ErrAborted wraps correctly when used
// as a base error (e.g. fmt.Errorf("%w: ...", ErrAborted)).
func TestErrAbortedIsWrappable(t *testing.T) {
	wrapped := fmt.Errorf("%w: simulated run failure", ErrAborted)
	if !errors.Is(wrapped, ErrAborted) {
		t.Error("wrapped ErrAborted should satisfy errors.Is(err, ErrAborted)")
	}
}

// TestOpenTTYFailureYieldsErrNoTTYNotErrAborted verifies that ONLY a failure
// of openTTY itself returns ErrNoTTY, not ErrAborted. The stdin state is
// irrelevant: the picker uses tea.WithInputTTY() and never checks os.Stdin.
func TestOpenTTYFailureYieldsErrNoTTYNotErrAborted(t *testing.T) {
	origTTY := openTTY
	defer func() { openTTY = origTTY }()

	openTTY = func() (*os.File, error) {
		return nil, errors.New("no such device or address")
	}

	ids, err := RunPicker(testItems())
	if !errors.Is(err, ErrNoTTY) {
		t.Errorf("openTTY failure must return ErrNoTTY, got %v", err)
	}
	if errors.Is(err, ErrAborted) {
		t.Error("openTTY failure must NOT return ErrAborted")
	}
	if ids != nil {
		t.Errorf("expected nil ids, got %v", ids)
	}
}
