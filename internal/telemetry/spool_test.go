package telemetry

import "testing"

func TestSpool_AppendReadTruncate(t *testing.T) {
	p := Paths{Base: t.TempDir()}
	s := NewSpool(p, 100, 1<<20)
	if err := s.Append(NewFeatureEvent("a", "v", "logs", nil)); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(NewFeatureEvent("a", "v", "try", nil)); err != nil {
		t.Fatal(err)
	}
	evs, err := s.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 {
		t.Fatalf("got %d events want 2", len(evs))
	}
	if err := s.Truncate(); err != nil {
		t.Fatal(err)
	}
	evs, _ = s.ReadAll()
	if len(evs) != 0 {
		t.Fatalf("after truncate got %d want 0", len(evs))
	}
}

func TestSpool_CapDropsOldestAndCountsDropped(t *testing.T) {
	p := Paths{Base: t.TempDir()}
	s := NewSpool(p, 3, 1<<20) // cap at 3 events
	for i := 0; i < 5; i++ {
		if err := s.Append(NewFeatureEvent("a", "v", "logs", nil)); err != nil {
			t.Fatal(err)
		}
	}
	evs, _ := s.ReadAll()
	if len(evs) != 3 {
		t.Fatalf("got %d events want 3 (capped)", len(evs))
	}
	dropped, err := s.DrainDropped()
	if err != nil {
		t.Fatal(err)
	}
	if dropped != 2 {
		t.Fatalf("dropped=%d want 2", dropped)
	}
	// Drain resets.
	d2, _ := s.DrainDropped()
	if d2 != 0 {
		t.Fatalf("dropped after drain=%d want 0", d2)
	}
}
