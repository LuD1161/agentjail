package sandbox

import (
	"testing"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
)

// TestBuildCleanEnv_OnlyAllowlisted verifies that only allowlisted vars survive.
func TestBuildCleanEnv_OnlyAllowlisted(t *testing.T) {
	hostEnv := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/home/user",
		"TERM=xterm-256color",
		"TYPEFULLY_API_KEY=secret",
		"ANTHROPIC_API_KEY=sk-...",
		"MY_RANDOM_VAR=hello",
		"GOPATH=/home/user/go",
	}

	cfg := config.Default()
	result := BuildCleanEnv(hostEnv, cfg)

	resultMap := make(map[string]bool)
	for _, kv := range result {
		resultMap[EnvVarName(kv)] = true
	}

	// Allowlisted vars should be present.
	for _, want := range []string{"PATH", "HOME", "TERM", "GOPATH"} {
		if !resultMap[want] {
			t.Errorf("allowlisted var %q missing from clean env", want)
		}
	}

	// Non-allowlisted vars should be absent.
	for _, unwanted := range []string{"TYPEFULLY_API_KEY", "ANTHROPIC_API_KEY", "MY_RANDOM_VAR"} {
		if resultMap[unwanted] {
			t.Errorf("non-allowlisted var %q leaked into clean env", unwanted)
		}
	}
}

// TestBuildCleanEnv_Passthrough verifies that env_passthrough adds to the allowlist.
func TestBuildCleanEnv_Passthrough(t *testing.T) {
	hostEnv := []string{
		"PATH=/usr/bin",
		"MY_SAFE_CONFIG=value",
		"CUSTOM_VAR=custom",
		"SECRET_KEY=shouldnotpass",
	}

	strip := true
	cfg := &config.PolicyConfig{
		Secrets: config.SecretsConfig{
			StripOnLaunch:  &strip,
			EnvPassthrough: []string{"MY_SAFE_CONFIG", "CUSTOM_VAR"},
		},
	}

	result := BuildCleanEnv(hostEnv, cfg)

	resultMap := make(map[string]bool)
	for _, kv := range result {
		resultMap[EnvVarName(kv)] = true
	}

	if !resultMap["PATH"] {
		t.Error("baseline var PATH missing")
	}
	if !resultMap["MY_SAFE_CONFIG"] {
		t.Error("passthrough var MY_SAFE_CONFIG missing")
	}
	if !resultMap["CUSTOM_VAR"] {
		t.Error("passthrough var CUSTOM_VAR missing")
	}
	if resultMap["SECRET_KEY"] {
		t.Error("non-allowlisted var SECRET_KEY leaked")
	}
}

// TestBuildCleanEnv_NilConfig verifies that nil config uses only baseline.
func TestBuildCleanEnv_NilConfig(t *testing.T) {
	hostEnv := []string{
		"PATH=/usr/bin",
		"HOME=/home/user",
		"RANDOM_THING=value",
	}

	result := BuildCleanEnv(hostEnv, nil)

	resultMap := make(map[string]bool)
	for _, kv := range result {
		resultMap[EnvVarName(kv)] = true
	}

	if !resultMap["PATH"] {
		t.Error("PATH missing with nil config")
	}
	if !resultMap["HOME"] {
		t.Error("HOME missing with nil config")
	}
	if resultMap["RANDOM_THING"] {
		t.Error("RANDOM_THING should not be in clean env")
	}
}

// TestIsDenied verifies deny patterns.
func TestIsDenied(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"LD_PRELOAD", true},
		{"LD_LIBRARY_PATH", true},
		{"LD_CUSTOM_THING", true}, // matches LD_ prefix
		{"DYLD_INSERT_LIBRARIES", true},
		{"DYLD_ANYTHING", true}, // matches DYLD_ prefix
		{"BASH_ENV", true},
		{"NODE_OPTIONS", true},
		{"BASH_FUNC_something", true}, // matches BASH_FUNC_ prefix
		{"OP_SESSION_xyz", true},      // matches OP_SESSION_ prefix
		{"PATH", false},
		{"HOME", false},
		{"MY_CUSTOM_VAR", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsDenied(tc.name)
			if got != tc.want {
				t.Errorf("IsDenied(%q) = %v; want %v", tc.name, got, tc.want)
			}
		})
	}
}

// TestMatchesBlocklist verifies the blocklist matching logic.
func TestMatchesBlocklist(t *testing.T) {
	tests := []struct {
		key      string
		patterns []string
		want     bool
	}{
		{"AWS_ACCESS_KEY_ID", []string{"AWS_ACCESS_KEY_ID"}, true},
		{"AWS_ACCESS_KEY_ID", []string{"AWS_*"}, true},
		{"AWS_SECRET_ACCESS_KEY", []string{"*_SECRET_ACCESS_KEY"}, true},
		{"MY_API_KEY", []string{"*_API_KEY"}, true},
		{"PATH", []string{"AWS_*"}, false},
		{"HOME", []string{"AWS_*"}, false},
	}

	for _, tc := range tests {
		got := MatchesBlocklist(tc.key, tc.patterns)
		if got != tc.want {
			t.Errorf("MatchesBlocklist(%q, %v) = %v; want %v", tc.key, tc.patterns, got, tc.want)
		}
	}
}

// TestStripEnv_RemovesBlocklistedVars verifies that blocklisted env vars are stripped.
func TestStripEnv_RemovesBlocklistedVars(t *testing.T) {
	cfg := config.Default()
	env := []string{
		"AWS_ACCESS_KEY_ID=AKIA...",
		"AWS_SECRET_ACCESS_KEY=secret123",
		"PGPASSWORD=mypassword",
		"PATH=/usr/bin:/bin",
		"HOME=/home/user",
	}

	result := StripEnv(env, cfg)

	for _, kv := range result {
		name := EnvVarName(kv)
		for _, blocked := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "PGPASSWORD"} {
			if name == blocked {
				t.Errorf("blocklisted var %q was not stripped", blocked)
			}
		}
	}
}

// TestStripEnv_NilConfig verifies that nil config returns env unchanged.
func TestStripEnv_NilConfig(t *testing.T) {
	env := []string{"AWS_ACCESS_KEY_ID=AKIA...", "PATH=/usr/bin"}
	result := StripEnv(env, nil)
	if len(result) != len(env) {
		t.Errorf("expected %d vars (nil config), got %d", len(env), len(result))
	}
}

// TestEnvVarName verifies env var name extraction.
func TestEnvVarName(t *testing.T) {
	tests := []struct {
		kv   string
		want string
	}{
		{"KEY=VALUE", "KEY"},
		{"AWS_ACCESS_KEY_ID=AKIA123", "AWS_ACCESS_KEY_ID"},
		{"NO_EQUALS", "NO_EQUALS"},
		{"", ""},
	}
	for _, tc := range tests {
		got := EnvVarName(tc.kv)
		if got != tc.want {
			t.Errorf("EnvVarName(%q) = %q; want %q", tc.kv, got, tc.want)
		}
	}
}
