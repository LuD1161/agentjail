//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Guards the OFF/ON status-line selection: consent recorded wins (ON), else a
// restricted host shows the OFF hint, else the line stays silent so unrestricted
// hosts are never nagged. See ADR 0104-shield-apparmor-userns.
func TestNetworkVisibilityLine(t *testing.T) {
	cases := []struct {
		name       string
		restricted bool
		consented  bool
		wantShow   bool
		wantSubstr string
	}{
		{"consent+restricted", true, true, true, "ON"},
		{"consent+unrestricted", false, true, true, "ON"},
		{"restricted-no-consent", true, false, true, "OFF"},
		{"unrestricted-no-consent", false, false, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line, show := networkVisibilityLine(tc.restricted, tc.consented)
			if show != tc.wantShow {
				t.Fatalf("show = %v, want %v", show, tc.wantShow)
			}
			if show && !strings.Contains(line, tc.wantSubstr) {
				t.Fatalf("line %q missing %q", line, tc.wantSubstr)
			}
			if !show && line != "" {
				t.Fatalf("hidden line must be empty, got %q", line)
			}
		})
	}
}

// Guards that writeApparmorConsent produces the exact marker doctor reads, 0600,
// so a successful `install --with-apparmor` unblocks `doctor --fix`.
func TestWriteApparmorConsent(t *testing.T) {
	home := t.TempDir()

	if apparmorConsentRecorded(home) {
		t.Fatal("consent unexpectedly recorded before write")
	}
	if err := writeApparmorConsent(home); err != nil {
		t.Fatalf("writeApparmorConsent: %v", err)
	}
	if !apparmorConsentRecorded(home) {
		t.Fatal("consent not recorded after write")
	}

	marker := apparmorConsentMarker(home)
	if want := filepath.Join(home, ".agentjail", "apparmor-consent"); marker != want {
		t.Fatalf("marker path = %q, want %q", marker, want)
	}
	info, err := os.Stat(marker)
	if err != nil {
		t.Fatalf("stat marker: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("marker perm = %o, want 600", perm)
	}
}
