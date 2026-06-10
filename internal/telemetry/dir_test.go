package telemetry

import (
	"path/filepath"
	"testing"
)

func TestPaths_UnderBaseDir(t *testing.T) {
	base := t.TempDir()
	p := Paths{Base: base}
	if got, want := p.Consent(), filepath.Join(base, "telemetry.json"); got != want {
		t.Errorf("Consent()=%q want %q", got, want)
	}
	if got, want := p.Spool(), filepath.Join(base, "telemetry-spool.jsonl"); got != want {
		t.Errorf("Spool()=%q want %q", got, want)
	}
	if got, want := p.Dropped(), filepath.Join(base, "telemetry-spool.dropped"); got != want {
		t.Errorf("Dropped()=%q want %q", got, want)
	}
	if got, want := p.Checkpoint(), filepath.Join(base, "telemetry-rollup.partial.json"); got != want {
		t.Errorf("Checkpoint()=%q want %q", got, want)
	}
}

func TestDefaultPaths_UsesHomeAgentjail(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	p, err := DefaultPaths()
	if err != nil {
		t.Fatalf("DefaultPaths: %v", err)
	}
	home, _ := homeDir()
	if want := filepath.Join(home, ".agentjail"); p.Base != want {
		t.Errorf("Base=%q want %q", p.Base, want)
	}
}
