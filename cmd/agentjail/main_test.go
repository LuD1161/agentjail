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

// TestUsageIncludesGeneratedCommands guards against U5: usage() used to be a
// hand-curated list that silently omitted commands as new ones were added to
// root.go. Since usage() now derives its command list from rootCmd.Commands()
// (see commandLists), this asserts that commands historically missing from
// the old hardcoded list are present in the generated output.
func TestUsageIncludesGeneratedCommands(t *testing.T) {
	var buf bytes.Buffer
	usage(&buf)
	out := stripANSI(buf.String())

	previouslyOmitted := []string{
		"sessions",
		"skill",
		"trust",
		"untrust",
		"allow",
		"grants",
		"grant",
	}
	for _, cmd := range previouslyOmitted {
		if !strings.Contains(out, cmd) {
			t.Errorf("usage() output missing command %q (previously omitted from hand-curated list)", cmd)
		}
	}
}

// TestCommandListsMatchesRootCommands asserts commandLists() never drops a
// registered, non-hidden top-level command -- the actual guarantee behind
// U5's fix.
func TestCommandListsMatchesRootCommands(t *testing.T) {
	cmds, maintenance := commandLists(rootCmd)
	got := map[string]bool{}
	for _, c := range cmds {
		got[c.name] = true
	}
	for _, c := range maintenance {
		got[c.name] = true
	}
	for _, c := range rootCmd.Commands() {
		// "completion" is cobra's own auto-generated command; commandLists()
		// deliberately excludes it as boilerplate (see its comment). It may
		// or may not be present in rootCmd.Commands() depending on whether
		// an earlier test in this process already called Execute(), which
		// lazily registers it -- so it must be excluded here too rather than
		// asserted on.
		if c.Hidden || c.Name() == "completion" {
			continue
		}
		if !got[c.Name()] {
			t.Errorf("commandLists() missing registered command %q", c.Name())
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
		"  agentjail claude",
		"  agentjail install --all",
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
