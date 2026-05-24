package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

// TestUsageContainsAllCommands verifies that usage() outputs all expected
// command names and key flag hints regardless of the io.Writer target.
func TestUsageContainsAllCommands(t *testing.T) {
	var buf bytes.Buffer
	usage(&buf)
	out := buf.String()

	// Strip ANSI escape codes for plain-text matching.
	stripped := stripANSI(out)

	required := []string{
		"install",
		"uninstall",
		"status",
		"version",
		"logs",
		"policy",
		"ui",
		"help",
	}
	for _, cmd := range required {
		if !strings.Contains(stripped, cmd) {
			t.Errorf("usage() output missing command %q", cmd)
		}
	}
}

func TestUsagePremiumStructure(t *testing.T) {
	var buf bytes.Buffer
	usage(&buf)
	out := stripANSI(buf.String())

	required := []string{
		"Usage",
		"  agentjail <command> [flags]",
		"Commands",
		"Maintenance",
		"Examples",
		"  agentjail install --for codex",
		"  agentjail policy enable no_shell_init_write",
	}
	for _, want := range required {
		if !strings.Contains(out, want) {
			t.Errorf("usage() output missing %q\nfull output:\n%s", want, out)
		}
	}
	forbidden := []string{
		"logs flags:",
		"full teardown",
		"exit 0",
		"manage named policy",
	}
	for _, bad := range forbidden {
		if strings.Contains(out, bad) {
			t.Errorf("usage() output contains stale copy %q\nfull output:\n%s", bad, out)
		}
	}
	if !strings.HasSuffix(buf.String(), "\n\n") {
		t.Errorf("usage() output should end with a blank line before the shell prompt\ngot:\n%q", buf.String())
	}
}

// stripANSI removes ESC[…m escape sequences for plain-text comparison.
func stripANSI(s string) string {
	var out strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == '\033' && i+1 < len(s) && s[i+1] == '[' {
			i += 2
			for i < len(s) && s[i] != 'm' {
				i++
			}
			if i < len(s) {
				i++ // skip 'm'
			}
			continue
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String()
}

func TestParseTopLevelFlags(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		rest []string
		slug string
	}{
		{
			name: "no flag",
			in:   []string{"claude", "-p", "hi"},
			rest: []string{"claude", "-p", "hi"},
			slug: "",
		},
		{
			name: "long form",
			in:   []string{"--agent", "comp-intel", "claude", "-p", "hi"},
			rest: []string{"claude", "-p", "hi"},
			slug: "comp-intel",
		},
		{
			name: "inline form",
			in:   []string{"--agent=comp-intel", "claude", "-p", "hi"},
			rest: []string{"claude", "-p", "hi"},
			slug: "comp-intel",
		},
		{
			name: "flag stops at first positional, child flags pass through",
			in:   []string{"--agent", "comp-intel", "claude", "--help"},
			rest: []string{"claude", "--help"},
			slug: "comp-intel",
		},
		{
			name: "subcommand also receives unchanged args",
			in:   []string{"--agent", "x", "tail", "--json"},
			rest: []string{"tail", "--json"},
			slug: "x",
		},
		{
			name: "empty input",
			in:   []string{},
			rest: []string{},
			slug: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rest, slug := parseTopLevelFlags(c.in)
			if !reflect.DeepEqual(rest, c.rest) {
				t.Errorf("rest = %v, want %v", rest, c.rest)
			}
			if slug != c.slug {
				t.Errorf("slug = %q, want %q", slug, c.slug)
			}
		})
	}
}
