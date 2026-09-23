package telemetry

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestResolve_EnvWinsFalse(t *testing.T) {
	on, src := Resolve(Consent{Enabled: true}, env(map[string]string{"AGENTJAIL_SEND_ANONYMOUS_USAGE_STATS": "false"}))
	if on || src != "env" {
		t.Fatalf("got on=%v src=%q want false/env", on, src)
	}
}

func TestResolve_EnvWinsTrue(t *testing.T) {
	on, src := Resolve(Consent{Enabled: false}, env(map[string]string{"AGENTJAIL_SEND_ANONYMOUS_USAGE_STATS": "true"}))
	if !on || src != "env" {
		t.Fatalf("got on=%v src=%q want true/env", on, src)
	}
}

func TestResolve_CIDisables(t *testing.T) {
	on, src := Resolve(Consent{Enabled: true}, env(map[string]string{"CI": "true"}))
	if on || src != "ci" {
		t.Fatalf("got on=%v src=%q want false/ci", on, src)
	}
}

func TestResolve_ConfigThenDefault(t *testing.T) {
	on, src := Resolve(Consent{Enabled: false}, env(nil))
	if on || src != "config" {
		t.Fatalf("config-disabled: got on=%v src=%q", on, src)
	}
	on, src = Resolve(Consent{Enabled: true}, env(nil))
	if !on || src != "config" {
		t.Fatalf("config-enabled: got on=%v src=%q", on, src)
	}
}

func TestLoadConsent_CreatesDefaultsWhenMissing(t *testing.T) {
	p := Paths{Base: t.TempDir()}
	c, err := LoadConsent(p)
	if err != nil {
		t.Fatalf("LoadConsent: %v", err)
	}
	if !c.Enabled || c.AnonymousID == "" || c.Schema != 2 {
		t.Fatalf("bad defaults: %+v", c)
	}
	// Persisted at 0600.
	info, err := os.Stat(p.Consent())
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v want 0600", info.Mode().Perm())
	}
	// Stable across reloads.
	c2, _ := LoadConsent(p)
	if c2.AnonymousID != c.AnonymousID {
		t.Fatalf("anon id changed: %q -> %q", c.AnonymousID, c2.AnonymousID)
	}
}

func TestLoadConsent_InvalidPreserved(t *testing.T) {
	for _, data := range []string{
		`{"enabled":false`, `null`, `{}`, `{"enabled":false,"schema":0,"anonymous_id":"old"}`,
		`{"enabled":true,"schema":2,"anonymous_id":""}`, `{"enabled":true,"schema":99,"anonymous_id":"future"}`,
	} {
		t.Run(data, func(t *testing.T) {
			p := Paths{Base: t.TempDir()}
			if err := os.WriteFile(p.Consent(), []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			c, err := LoadConsent(p)
			if !errors.Is(err, ErrInvalidConsent) || c.Enabled || c.Schema != 2 || c.AnonymousID == "" {
				t.Fatalf("got %+v, %v", c, err)
			}
			stored, err := os.ReadFile(p.Consent())
			if err != nil || !bytes.Equal(stored, []byte(data)) {
				t.Fatalf("invalid consent overwritten: %q, %v", stored, err)
			}
			if r, err := New(p, env(map[string]string{EnvVar: "true"}), "test", "test", "test", nil); err == nil || r != nil {
				t.Fatal("invalid consent started a recorder")
			}
		})
	}
}

func TestLoadConsent_DisabledMigration(t *testing.T) {
	p := Paths{Base: t.TempDir()}
	c := Consent{Enabled: false, AnonymousID: "legacy", FirstSeen: "2025-01-01", NoticeShown: true, Schema: 1}
	if err := SaveConsent(p, c); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConsent(p)
	if err != nil || got.Enabled || got.FirstSeen != c.FirstSeen || !got.NoticeShown {
		t.Fatalf("got %+v, %v", got, err)
	}
	var persisted Consent
	b, err := os.ReadFile(p.Consent())
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Enabled {
		t.Fatal("migration enabled telemetry")
	}
}

func TestLoadConsent_ReadFailurePreserved(t *testing.T) {
	p := Paths{Base: t.TempDir()}
	if err := os.WriteFile(p.Consent(), []byte(`{"enabled":false}`), 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p.Consent(), 0600) })
	if _, err := os.ReadFile(p.Consent()); err == nil {
		t.Skip("user can read mode 0000 files")
	}
	c, err := LoadConsent(p)
	if !errors.Is(err, os.ErrPermission) || c.Enabled {
		t.Fatalf("got %+v, %v", c, err)
	}
	info, err := os.Stat(p.Consent())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0 {
		t.Fatal("unreadable consent replaced")
	}
}
