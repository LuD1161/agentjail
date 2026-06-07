package telemetry

import "testing"

func TestRecordFeature_AppendsWhenEnabled(t *testing.T) {
	p := Paths{Base: t.TempDir()}
	RecordFeature(p, func(string) string { return "" }, "0.1.0", "logs", []string{"claude"})
	s := NewSpool(p, spoolMaxEvents, spoolMaxBytes)
	evs, _ := s.ReadAll()
	if len(evs) != 1 || evs[0].Event != "feature_used" {
		t.Fatalf("got %+v", evs)
	}
	if evs[0].Properties["command"] != "logs" {
		t.Fatalf("command=%v", evs[0].Properties["command"])
	}
}

func TestRecordFeature_NoopWhenDisabled(t *testing.T) {
	p := Paths{Base: t.TempDir()}
	RecordFeature(p, func(k string) string {
		if k == EnvVar {
			return "false"
		}
		return ""
	}, "0.1.0", "logs", nil)
	s := NewSpool(p, spoolMaxEvents, spoolMaxBytes)
	evs, _ := s.ReadAll()
	if len(evs) != 0 {
		t.Fatalf("disabled wrote %d events", len(evs))
	}
}
