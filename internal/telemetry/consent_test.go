package telemetry

import (
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
