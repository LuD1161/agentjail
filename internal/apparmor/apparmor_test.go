package apparmor

import "testing"

// TestRender guards the exact profile text: the abi/4.0 line, the {,-shield}
// glob covering both re-exec paths, flags=(unconfined), and the userns rule.
func TestRender(t *testing.T) {
	got := renderer{}.Render("/home/agent/.agentjail/bin")
	want := `abi <abi/4.0>,
include <tunables/global>
profile agentjail-shield /home/agent/.agentjail/bin/agentjail{,-shield} flags=(unconfined) {
  userns,
  include if exists <local/agentjail-shield>
}
`
	if got != want {
		t.Fatalf("Render mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestRenderTrimsTrailingSlash: a trailing slash on installDir must not double up.
func TestRenderTrimsTrailingSlash(t *testing.T) {
	got := renderer{}.Render("/home/agent/.agentjail/bin/")
	want := renderer{}.Render("/home/agent/.agentjail/bin")
	if got != want {
		t.Fatalf("trailing slash changed output:\n%s", got)
	}
}

func TestParseParserVersion(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		wantVer Version
		wantOK  bool
		wantSup bool // >= minParserVersion
	}{
		{"4.0.1 ok", "AppArmor parser version 4.0.1\nCopyright ...", Version{4, 0, 1}, true, true},
		{"4.0.0 no patch", "AppArmor parser version 4.0", Version{4, 0, 0}, true, true},
		{"3.0.4 too old", "AppArmor parser version 3.0.4\nCopyright ...", Version{3, 0, 4}, true, false},
		{"5.2.0 newer ok", "AppArmor parser version 5.2.0", Version{5, 2, 0}, true, true},
		{"garbage", "not a version string", Version{}, false, false},
		{"empty", "", Version{}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, ok := parseParserVersion(tt.output)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if v != tt.wantVer {
				t.Fatalf("version = %v, want %v", v, tt.wantVer)
			}
			if got := v.AtLeast(minParserVersion); got != tt.wantSup {
				t.Fatalf("AtLeast(min) = %v, want %v", got, tt.wantSup)
			}
		})
	}
}

func TestVersionAtLeast(t *testing.T) {
	tests := []struct {
		v, o Version
		want bool
	}{
		{Version{4, 0, 0}, Version{4, 0, 0}, true},
		{Version{4, 0, 1}, Version{4, 0, 0}, true},
		{Version{3, 9, 9}, Version{4, 0, 0}, false},
		{Version{4, 1, 0}, Version{4, 0, 9}, true},
		{Version{4, 0, 0}, Version{4, 1, 0}, false},
		{Version{5, 0, 0}, Version{4, 9, 9}, true},
	}
	for _, tt := range tests {
		if got := tt.v.AtLeast(tt.o); got != tt.want {
			t.Errorf("%v.AtLeast(%v) = %v, want %v", tt.v, tt.o, got, tt.want)
		}
	}
}
