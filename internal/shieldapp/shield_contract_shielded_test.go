package shieldapp

import (
	"slices"
	"testing"
)

// Guards the premise the badge rests on: the variable means "sandboxed", not
// "the shield ran". See ADR 0087-shielded-means-sandboxed.
func TestAppendShieldedEnv(t *testing.T) {
	tests := []struct {
		name  string
		state SandboxState
		want  bool
	}{
		{"sandbox applied", Sandboxed, true},
		{"fail-open launch, no sandbox", NotSandboxed, false},
		{"zero value is not sandboxed", SandboxState(0), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AppendShieldedEnv([]string{"PATH=/usr/bin"}, tt.state)
			if slices.Contains(got, "AGENTJAIL_SHIELDED=1") != tt.want {
				t.Errorf("AppendShieldedEnv(%v) → %v, want SHIELDED present = %v",
					tt.state, got, tt.want)
			}
			if !slices.Contains(got, "PATH=/usr/bin") {
				t.Error("dropped the caller's env")
			}
		})
	}
}

// The zero value must be the unsafe-to-claim one, so a state nobody resolved
// cannot render a padlock.
func TestNotSandboxedIsZeroValue(t *testing.T) {
	var s SandboxState
	if s != NotSandboxed {
		t.Fatalf("zero SandboxState = %v, want NotSandboxed — an unset state must never claim a sandbox", s)
	}
}
