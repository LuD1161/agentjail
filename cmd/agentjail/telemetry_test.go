package main

import (
	"bytes"
	"encoding/json"
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

func TestRunTelemetry_StatusJSONOmitsAnonymousID(t *testing.T) {
	p := telemetry.Paths{Base: t.TempDir()}
	var out bytes.Buffer
	if code := runTelemetryWith(p, func(string) string { return "" }, []string{"status", "json"}, &out); code != 0 {
		t.Fatalf("status json exit=%d", code)
	}
	var status struct {
		Enabled bool   `json:"enabled"`
		Source  string `json:"source"`
	}
	if err := json.Unmarshal(out.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if !status.Enabled || status.Source != "config" {
		t.Fatalf("status=%+v", status)
	}
	if strings.Contains(out.String(), "anonymous") {
		t.Fatalf("machine status exposed anonymous ID: %q", out.String())
	}
	if code := runTelemetryWith(p, func(string) string { return "" }, []string{"status", "unexpected"}, &out); code != 2 {
		t.Fatalf("unexpected status mode exit=%d", code)
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

func TestRunTelemetry_MacOSSetupRecordsOnlyValidEnums(t *testing.T) {
	p := telemetry.Paths{Base: t.TempDir()}
	getenv := func(string) string { return "" }
	var out bytes.Buffer
	if code := runTelemetryWith(p, getenv, []string{"macos-setup", "extension", "succeeded"}, &out); code != 0 {
		t.Fatalf("record valid setup event: code=%d output=%q", code, out.String())
	}
	events, err := telemetry.NewSpool(p, 100, 1<<20).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Event != "macos_setup" {
		t.Fatalf("events=%#v", events)
	}
	if code := runTelemetryWith(p, getenv, []string{"macos-setup", "arbitrary", "failed"}, &out); code != 0 {
		t.Fatalf("invalid enum must fail soft, got code %d", code)
	}
	events, err = telemetry.NewSpool(p, 100, 1<<20).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("invalid event was recorded: %#v", events)
	}
}
