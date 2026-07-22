package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Merge copies field-by-field into a fresh struct, so a field nobody adds to it
// is silently dropped. tunnel_mitm was: the standing opt-out from TLS
// interception (ADR 0077 D3) parsed correctly, then Merge discarded it and
// every install that wrote `tunnel_mitm: false` was decrypted anyway.
func TestMergePreservesTunnelMITM(t *testing.T) {
	no := false
	yes := true

	for _, tc := range []struct {
		name    string
		overlay *bool
		base    *bool
		want    *bool
	}{
		{"overlay false wins over absent base", &no, nil, &no},
		{"overlay true wins over absent base", &yes, nil, &yes},
		{"absent overlay keeps base", nil, &no, &no},
		{"both absent stays absent", nil, nil, nil},
		{"overlay true overrides base false", &yes, &no, &yes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := Default()
			base.Network.TunnelMITM = tc.base
			overlay := &PolicyConfig{}
			overlay.Network.TunnelMITM = tc.overlay

			got := Merge(base, overlay).Network.TunnelMITM

			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("TunnelMITM = %v, want nil (absent)", *got)
			case tc.want != nil && got == nil:
				t.Fatalf("TunnelMITM = nil, want %v — Merge dropped the field", *tc.want)
			case tc.want != nil && *got != *tc.want:
				t.Fatalf("TunnelMITM = %v, want %v", *got, *tc.want)
			}
		})
	}
}

// Mirrors TestMergePreservesTunnelMITM for tunnel_ipv6 (ADR 0110, AGE-262):
// same tri-state contract, so the same drop bug is possible here too.
func TestMergePreservesTunnelIPv6(t *testing.T) {
	no := false
	yes := true

	for _, tc := range []struct {
		name    string
		overlay *bool
		base    *bool
		want    *bool
	}{
		{"overlay false wins over absent base", &no, nil, &no},
		{"overlay true wins over absent base", &yes, nil, &yes},
		{"absent overlay keeps base", nil, &no, &no},
		{"both absent stays absent", nil, nil, nil},
		{"overlay true overrides base false", &yes, &no, &yes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := Default()
			base.Network.TunnelIPv6 = tc.base
			overlay := &PolicyConfig{}
			overlay.Network.TunnelIPv6 = tc.overlay

			got := Merge(base, overlay).Network.TunnelIPv6

			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("TunnelIPv6 = %v, want nil (absent)", *got)
			case tc.want != nil && got == nil:
				t.Fatalf("TunnelIPv6 = nil, want %v — Merge dropped the field", *tc.want)
			case tc.want != nil && *got != *tc.want:
				t.Fatalf("TunnelIPv6 = %v, want %v", *got, *tc.want)
			}
		})
	}
}

// The path a real launch takes: policy.yaml -> LoadPolicyForEnforcement -> the
// value resolveMITM reads. The unit test above can pass while this one fails,
// because enforcement loads through Merge(Default(), cfg).
func TestLoadPolicyForEnforcementKeepsTunnelMITM(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(p, []byte("network:\n  tunnel_mitm: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadPolicyForEnforcement(p)
	if err != nil {
		t.Fatalf("LoadPolicyForEnforcement: %v", err)
	}
	if cfg.Network.TunnelMITM == nil {
		t.Fatal("tunnel_mitm: false was dropped on the enforcement path — " +
			"the install's standing opt-out from decryption silently does nothing (ADR 0077 D3)")
	}
	if *cfg.Network.TunnelMITM {
		t.Fatalf("tunnel_mitm = true, want false")
	}
}

// Catches the next dropped field rather than only this one: set every
// NetworkConfig field to a non-zero value, merge onto an empty base, and
// require Merge to carry each one through.
func TestMergeCarriesEveryNetworkField(t *testing.T) {
	overlay := &PolicyConfig{}
	fillNonZero(t, reflect.ValueOf(&overlay.Network).Elem())

	got := Merge(&PolicyConfig{}, overlay).Network

	gv := reflect.ValueOf(got)
	ov := reflect.ValueOf(overlay.Network)
	for i := 0; i < gv.NumField(); i++ {
		name := gv.Type().Field(i).Name
		if gv.Type().Field(i).Tag.Get("yaml") == "-" {
			continue // runtime-derived, not user config
		}
		if gv.Field(i).IsZero() && !ov.Field(i).IsZero() {
			t.Errorf("Merge dropped NetworkConfig.%s — it is set in the overlay but zero in the result; "+
				"add it to Merge", name)
		}
	}
}

// fillNonZero sets every settable field of a struct to a distinctive non-zero
// value so a dropped field shows up as a zero in the merged result.
func fillNonZero(t *testing.T, v reflect.Value) {
	t.Helper()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if !f.CanSet() {
			continue
		}
		switch f.Kind() {
		case reflect.Slice:
			f.Set(reflect.MakeSlice(f.Type(), 1, 1))
			if f.Index(0).Kind() == reflect.String {
				f.Index(0).SetString("probe.example.com")
			}
		case reflect.Ptr:
			f.Set(reflect.New(f.Type().Elem()))
			if f.Elem().Kind() == reflect.Bool {
				f.Elem().SetBool(true)
			}
		case reflect.String:
			f.SetString("probe")
		case reflect.Bool:
			f.SetBool(true)
		case reflect.Int, reflect.Int64:
			f.SetInt(1)
		}
	}
}
