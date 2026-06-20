package main

import (
	"os"
	"testing"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
)

// TestStripEnv_RemovesBlocklistedVars verifies that blocklisted env vars are stripped.
func TestStripEnv_RemovesBlocklistedVars(t *testing.T) {
	cfg := config.Default()
	env := []string{
		"AWS_ACCESS_KEY_ID=AKIA...",
		"AWS_SECRET_ACCESS_KEY=secret123",
		"AWS_SESSION_TOKEN=token123",
		"PGPASSWORD=mypassword",
		"REDIS_PASSWORD=redispass",
		"GITHUB_TOKEN=ghp_...",
		"ANTHROPIC_API_KEY=sk-...",
		"OPENAI_API_KEY=sk-...",
		"PATH=/usr/bin:/bin",
		"HOME=/home/user",
		"MY_CUSTOM_VAR=hello",
	}

	result := stripEnv(env, cfg)

	for _, kv := range result {
		name := envVarName(kv)
		for _, blocked := range []string{
			"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
			"PGPASSWORD", "REDIS_PASSWORD", "GITHUB_TOKEN",
			"ANTHROPIC_API_KEY", "OPENAI_API_KEY",
		} {
			if name == blocked {
				t.Errorf("blocklisted var %q was not stripped", blocked)
			}
		}
	}

	if len(result) >= len(env) {
		t.Errorf("expected fewer env vars after stripping, got %d (was %d)", len(result), len(env))
	}
}

// TestStripEnv_KeepsNonBlocklistedVars verifies that non-blocklisted vars are kept.
func TestStripEnv_KeepsNonBlocklistedVars(t *testing.T) {
	cfg := config.Default()
	env := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/home/user",
		"MY_CUSTOM_VAR=hello",
		"TERM=xterm-256color",
	}

	result := stripEnv(env, cfg)

	if len(result) < len(env) {
		t.Errorf("expected all env vars to be kept, got %d (was %d)", len(result), len(env))
	}
	for i, kv := range env {
		if i >= len(result) {
			break
		}
		found := false
		for _, r := range result {
			if r == kv {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("non-blocklisted var %q was stripped", kv)
		}
	}
}

// TestStripEnv_CustomBlocklist verifies that a custom blocklist is used.
func TestStripEnv_CustomBlocklist(t *testing.T) {
	custom := []string{"MY_SECRET", "*_TOKEN"}
	strip := true
	cfg := &config.PolicyConfig{
		Secrets: config.SecretsConfig{
			EnvBlocklist:  custom,
			StripOnLaunch: &strip,
		},
	}

	env := []string{
		"MY_SECRET=secret",
		"MY_TOKEN=token",
		"AWS_ACCESS_KEY_ID=should-still-be-here",
		"PATH=/usr/bin",
	}

	result := stripEnv(env, cfg)

	resultMap := make(map[string]bool)
	for _, kv := range result {
		resultMap[envVarName(kv)] = true
	}

	if resultMap["MY_SECRET"] {
		t.Error("MY_SECRET was not stripped")
	}
	if resultMap["MY_TOKEN"] {
		t.Error("MY_TOKEN was not stripped (should match *_TOKEN)")
	}
	if !resultMap["AWS_ACCESS_KEY_ID"] {
		t.Error("AWS_ACCESS_KEY_ID should NOT be stripped with custom blocklist")
	}
	if !resultMap["PATH"] {
		t.Error("PATH should NOT be stripped")
	}
}

// TestStripEnv_GlobPatterns verifies that glob patterns work.
func TestStripEnv_GlobPatterns(t *testing.T) {
	custom := []string{"*_API_KEY", "*_SECRET_KEY", "*_API_TOKEN"}
	strip := true
	cfg := &config.PolicyConfig{
		Secrets: config.SecretsConfig{
			EnvBlocklist:  custom,
			StripOnLaunch: &strip,
		},
	}

	env := []string{
		"MY_SERVICE_API_KEY=key123",
		"DB_SECRET_KEY=secret",
		"LLM_API_TOKEN=token",
		"MY_SERVICE_API_URL=url",
		"NORMAL_VAR=value",
	}

	result := stripEnv(env, cfg)

	resultMap := make(map[string]bool)
	for _, kv := range result {
		resultMap[envVarName(kv)] = true
	}

	if resultMap["MY_SERVICE_API_KEY"] {
		t.Error("MY_SERVICE_API_KEY should be stripped by *_API_KEY")
	}
	if resultMap["DB_SECRET_KEY"] {
		t.Error("DB_SECRET_KEY should be stripped by *_SECRET_KEY")
	}
	if resultMap["LLM_API_TOKEN"] {
		t.Error("LLM_API_TOKEN should be stripped by *_API_TOKEN")
	}
	if !resultMap["MY_SERVICE_API_URL"] {
		t.Error("MY_SERVICE_API_URL should NOT be stripped (doesn't match any pattern)")
	}
	if !resultMap["NORMAL_VAR"] {
		t.Error("NORMAL_VAR should NOT be stripped")
	}
}

// TestStripEnv_Disabled verifies that stripping can be disabled.
func TestStripEnv_Disabled(t *testing.T) {
	strip := false
	cfg := &config.PolicyConfig{
		Secrets: config.SecretsConfig{
			EnvBlocklist:  []string{"AWS_ACCESS_KEY_ID"},
			StripOnLaunch: &strip,
		},
	}

	env := []string{
		"AWS_ACCESS_KEY_ID=AKIA...",
		"PATH=/usr/bin",
	}

	result := stripEnv(env, cfg)

	if len(result) != len(env) {
		t.Errorf("expected %d vars (stripping disabled), got %d", len(env), len(result))
	}
}

// TestStripEnv_NilConfig verifies that nil config returns env unchanged.
func TestStripEnv_NilConfig(t *testing.T) {
	env := []string{"AWS_ACCESS_KEY_ID=AKIA...", "PATH=/usr/bin"}
	result := stripEnv(env, nil)
	if len(result) != len(env) {
		t.Errorf("expected %d vars (nil config), got %d", len(env), len(result))
	}
}

// TestStripEnv_DefaultBlocklist verifies the default blocklist covers expected vars.
func TestStripEnv_DefaultBlocklist(t *testing.T) {
	cfg := config.Default()
	expected := []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"AWS_SECURITY_TOKEN",
		"AWS_DELEGATION_TOKEN",
		"PGPASSWORD",
		"REDIS_PASSWORD",
		"GITHUB_TOKEN",
		"ANTHROPIC_API_KEY",
		"OPENAI_API_KEY",
	}

	for _, name := range expected {
		if !matchesBlocklist(name, cfg.Secrets.EnvBlocklist) {
			t.Errorf("default blocklist does not cover %q", name)
		}
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
		{"AWS_ACCESS_KEY_ID", []string{"PGPASSWORD"}, false},
	}

	for _, tc := range tests {
		got := matchesBlocklist(tc.key, tc.patterns)
		if got != tc.want {
			t.Errorf("matchesBlocklist(%q, %v) = %v; want %v", tc.key, tc.patterns, got, tc.want)
		}
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
		got := envVarName(tc.kv)
		if got != tc.want {
			t.Errorf("envVarName(%q) = %q; want %q", tc.kv, got, tc.want)
		}
	}
}

// TestSecretsConfig_Default verifies the default secrets config.
func TestSecretsConfig_Default(t *testing.T) {
	cfg := config.Default()
	if cfg.Secrets.EnvBlocklist == nil || len(cfg.Secrets.EnvBlocklist) == 0 {
		t.Error("default Secrets.EnvBlocklist is empty")
	}
	if cfg.Secrets.StripOnLaunch == nil || !*cfg.Secrets.StripOnLaunch {
		t.Error("default Secrets.StripOnLaunch should be true")
	}
}

// TestSecretsConfig_Merge verifies that Merge handles the Secrets section.
func TestSecretsConfig_Merge(t *testing.T) {
	base := config.Default()
	strip := false
	overlay := &config.PolicyConfig{
		Secrets: config.SecretsConfig{
			EnvBlocklist:  []string{"CUSTOM_VAR"},
			StripOnLaunch: &strip,
		},
	}

	result := config.Merge(base, overlay)

	if len(result.Secrets.EnvBlocklist) != 1 || result.Secrets.EnvBlocklist[0] != "CUSTOM_VAR" {
		t.Errorf("Merge: expected [CUSTOM_VAR], got %v", result.Secrets.EnvBlocklist)
	}
	if result.Secrets.StripOnLaunch == nil || *result.Secrets.StripOnLaunch {
		t.Error("Merge: expected StripOnLaunch=false")
	}
}

// TestSecretsConfig_MergeKeepBase verifies that Merge keeps base when overlay is empty.
func TestSecretsConfig_MergeKeepBase(t *testing.T) {
	base := config.Default()
	overlay := &config.PolicyConfig{}

	result := config.Merge(base, overlay)

	if len(result.Secrets.EnvBlocklist) != len(base.Secrets.EnvBlocklist) {
		t.Errorf("Merge: expected %d blocklist entries, got %d", len(base.Secrets.EnvBlocklist), len(result.Secrets.EnvBlocklist))
	}
	if result.Secrets.StripOnLaunch == nil || !*result.Secrets.StripOnLaunch {
		t.Error("Merge: expected StripOnLaunch=true (from base)")
	}
}

// TestSecretsConfig_ToOPAData verifies the OPA data output includes secrets config.
func TestSecretsConfig_ToOPAData(t *testing.T) {
	cfg := config.Default()
	data := cfg.ToOPAData()

	secrets, ok := data["secrets"]
	if !ok {
		t.Fatal("ToOPAData: missing 'secrets' key")
	}
	secretsMap, ok := secrets.(map[string]interface{})
	if !ok {
		t.Fatal("ToOPAData: 'secrets' is not a map")
	}
	if _, ok := secretsMap["env_blocklist"]; !ok {
		t.Error("ToOPAData: missing secrets.env_blocklist")
	}
	if _, ok := secretsMap["strip_on_launch"]; !ok {
		t.Error("ToOPAData: missing secrets.strip_on_launch")
	}
}

// TestSecretsConfig_YAMLLoad verifies that a YAML config with the secrets section loads.
func TestSecretsConfig_YAMLLoad(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/policy.yaml"
	yamlContent := `secrets:
  env_blocklist:
    - MY_CUSTOM_SECRET
    - "*_TOKEN"
  strip_on_launch: true
`
	if err := os.WriteFile(path, []byte(yamlContent), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Secrets.EnvBlocklist) != 2 {
		t.Errorf("expected 2 blocklist entries, got %d: %v", len(cfg.Secrets.EnvBlocklist), cfg.Secrets.EnvBlocklist)
	}
	if cfg.Secrets.StripOnLaunch == nil || !*cfg.Secrets.StripOnLaunch {
		t.Error("expected StripOnLaunch=true")
	}
}

// TestSecretsConfig_YAMLLoadStripFalse verifies that strip_on_launch: false is respected.
func TestSecretsConfig_YAMLLoadStripFalse(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/policy.yaml"
	yamlContent := `secrets:
  strip_on_launch: false
`
	if err := os.WriteFile(path, []byte(yamlContent), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Secrets.StripOnLaunch == nil {
		t.Fatal("StripOnLaunch is nil")
	}
	if *cfg.Secrets.StripOnLaunch {
		t.Error("expected StripOnLaunch=false")
	}
}
