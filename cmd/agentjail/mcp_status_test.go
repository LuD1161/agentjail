package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/ui"
)

func TestMCPServerStatus(t *testing.T) {
	allowed := []string{"chrome-devtools", "plugin_posthog_posthog"}
	blocked := []string{"*stripe*", "*payment*"}

	cases := map[string]string{
		"chrome-devtools":        "allowed",
		"plugin_posthog_posthog": "allowed",
		"my-stripe-mcp":          "blocked",
		"netlify":                "none",
	}
	for name, want := range cases {
		if got := mcpServerStatus(name, allowed, blocked); got != want {
			t.Errorf("mcpServerStatus(%q) = %q, want %q", name, got, want)
		}
	}

	// Blocked must win even when the name is also explicitly allowed.
	if got := mcpServerStatus("stripe-thing", []string{"stripe-thing"}, []string{"*stripe*"}); got != "blocked" {
		t.Errorf("blocked should take precedence, got %q", got)
	}
}

func TestMCPDisplayServers_UnionsAllowedExactExcludesGlobs(t *testing.T) {
	discovered := []string{"chrome-devtools", "memory"}
	allowed := []string{"chrome-devtools", "plugin_posthog_posthog", "*glob*"}
	got := mcpDisplayServers(discovered, allowed)
	want := []string{"chrome-devtools", "memory", "plugin_posthog_posthog"} // sorted, deduped, no glob
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("mcpDisplayServers = %v, want %v", got, want)
	}
}

func TestRenderMCPInstalled_ShowsEachStatus(t *testing.T) {
	var buf bytes.Buffer
	u := ui.New(&buf)
	installed := []string{"chrome-devtools", "netlify", "my-stripe"}
	renderMCPInstalled(&buf, u, installed, []string{"chrome-devtools"}, []string{"*stripe*"})

	s := buf.String()
	for _, want := range []string{
		"Installed MCP servers",
		"chrome-devtools", "allowed",
		"netlify", "not configured",
		"my-stripe", "blocked",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("rendered output missing %q:\n%s", want, s)
		}
	}
}

func TestRenderMCPInstalled_NoneDetected(t *testing.T) {
	var buf bytes.Buffer
	u := ui.New(&buf)
	renderMCPInstalled(&buf, u, nil, nil, nil)
	if !strings.Contains(buf.String(), "none detected") {
		t.Errorf("expected 'none detected' message, got:\n%s", buf.String())
	}
}
