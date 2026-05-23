package agents

import "testing"

// TestRegistryIDs asserts that Registry returns exactly three agents with
// the correct IDs in the canonical order: claude-code, cursor, codex.
func TestRegistryIDs(t *testing.T) {
	want := []string{"claude-code", "cursor", "codex"}
	got := Registry()

	if len(got) != len(want) {
		t.Fatalf("Registry() returned %d agent(s), want %d", len(got), len(want))
	}

	for i, ag := range got {
		if ag.ID() != want[i] {
			t.Errorf("Registry()[%d].ID() = %q, want %q", i, ag.ID(), want[i])
		}
	}
}
