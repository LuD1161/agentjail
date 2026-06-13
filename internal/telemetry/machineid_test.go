package telemetry

import (
	"testing"
)

func TestStableMachineID_Deterministic(t *testing.T) {
	id1 := stableMachineID()
	id2 := stableMachineID()
	if id1 != id2 {
		t.Fatalf("not deterministic: %q vs %q", id1, id2)
	}
	if id1 == "" {
		t.Skip("no hardware ID available on this platform")
	}
	if len(id1) != 64 {
		t.Fatalf("expected 64 hex chars, got %d: %q", len(id1), id1)
	}
}

func TestStableMachineID_NotRawHardwareID(t *testing.T) {
	raw := rawMachineID()
	if raw == "" {
		t.Skip("no hardware ID available")
	}
	stable := stableMachineID()
	if stable == raw {
		t.Fatal("stable ID should be hashed, not raw")
	}
}
