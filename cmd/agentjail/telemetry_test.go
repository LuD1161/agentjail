package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/telemetry"
)

func TestRunTelemetry_StatusEnableDisable(t *testing.T) {
	p := telemetry.Paths{Base: t.TempDir()}
	getenv := func(string) string { return "" }

	var out bytes.Buffer
	if code := runTelemetryWith(p, getenv, []string{"status"}, &out); code != 0 {
		t.Fatalf("status exit=%d", code)
	}
	if !strings.Contains(strings.ToLower(out.String()), "enabled") {
		t.Fatalf("status missing state: %q", out.String())
	}

	out.Reset()
	if code := runTelemetryWith(p, getenv, []string{"disable"}, &out); code != 0 {
		t.Fatalf("disable exit=%d", code)
	}
	c, _ := telemetry.LoadConsent(p)
	if c.Enabled {
		t.Fatal("disable did not persist")
	}

	out.Reset()
	if code := runTelemetryWith(p, getenv, []string{"enable"}, &out); code != 0 {
		t.Fatalf("enable exit=%d", code)
	}
	c, _ = telemetry.LoadConsent(p)
	if !c.Enabled {
		t.Fatal("enable did not persist")
	}
}

func TestFeatureName_MapsKnownCommands(t *testing.T) {
	if featureName("install") != "install" {
		t.Fatal("install")
	}
	if featureName("--help") != "help" {
		t.Fatal("help alias")
	}
	if featureName("bogus") != "other" {
		t.Fatalf("unknown should map to 'other', got %q", featureName("bogus"))
	}
}

func TestRunTelemetry_ViewPrintsJSON(t *testing.T) {
	p := telemetry.Paths{Base: t.TempDir()}
	telemetry.RecordFeature(p, func(string) string { return "" }, "0.1.0", "logs", nil)
	var out bytes.Buffer
	if code := runTelemetryWith(p, func(string) string { return "" }, []string{"view"}, &out); code != 0 {
		t.Fatalf("view exit=%d", code)
	}
	if !strings.Contains(out.String(), "feature_used") {
		t.Fatalf("view did not print spooled event: %q", out.String())
	}
}
