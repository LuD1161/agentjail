package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestMCPCobraSubcommands(t *testing.T) {
	want := []string{"allow", "block", "list", "scan", "where", "tools", "tool"}
	got := make(map[string]bool)
	for _, cmd := range rootCmd.Commands() {
		if cmd.Use != "mcp" {
			continue
		}
		for _, sub := range cmd.Commands() {
			// Use is like "allow <server>" -- take the first word
			name := strings.SplitN(sub.Use, " ", 2)[0]
			got[name] = true
		}
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("mcp command tree missing subcommand %q; found: %v", w, got)
		}
	}
}

func TestMCPToolCobraSubcommands(t *testing.T) {
	want := []string{"allow", "block", "ask", "clear"}
	got := make(map[string]bool)
	for _, cmd := range rootCmd.Commands() {
		if cmd.Use != "mcp" {
			continue
		}
		for _, sub := range cmd.Commands() {
			if strings.SplitN(sub.Use, " ", 2)[0] != "tool" {
				continue
			}
			for _, tsub := range sub.Commands() {
				name := strings.SplitN(tsub.Use, " ", 2)[0]
				got[name] = true
			}
		}
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("mcp tool command tree missing subcommand %q; found: %v", w, got)
		}
	}
}

func TestSkillCobraSubcommands(t *testing.T) {
	want := []string{"list", "allow", "block", "ask", "clear"}
	got := make(map[string]bool)
	for _, cmd := range rootCmd.Commands() {
		if cmd.Use != "skill" {
			continue
		}
		for _, sub := range cmd.Commands() {
			name := strings.SplitN(sub.Use, " ", 2)[0]
			got[name] = true
		}
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("skill command tree missing subcommand %q; found: %v", w, got)
		}
	}
}

// TestMCPCobraHelp verifies that cobra generates help text listing all mcp
// subcommands when rootCmd dispatches to the mcp cobra command tree.
func TestMCPCobraHelp(t *testing.T) {
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"mcp", "--help"})
	_ = rootCmd.Execute()
	out := buf.String()
	for _, want := range []string{"allow", "block", "list", "scan", "where", "tools", "tool"} {
		if !strings.Contains(out, want) {
			t.Errorf("mcp --help (cobra) missing %q in output:\n%s", want, out)
		}
	}
}

// TestSkillCobraHelp verifies that cobra generates help text listing all skill
// subcommands.
func TestSkillCobraHelp(t *testing.T) {
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"skill", "--help"})
	_ = rootCmd.Execute()
	out := buf.String()
	for _, want := range []string{"list", "allow", "block", "ask", "clear"} {
		if !strings.Contains(out, want) {
			t.Errorf("skill --help (cobra) missing %q in output:\n%s", want, out)
		}
	}
}

// TestMCPToolCobraHelp verifies the mcp tool subcommand help.
func TestMCPToolCobraHelp(t *testing.T) {
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"mcp", "tool", "--help"})
	_ = rootCmd.Execute()
	out := buf.String()
	for _, want := range []string{"allow", "block", "ask", "clear"} {
		if !strings.Contains(out, want) {
			t.Errorf("mcp tool --help (cobra) missing %q in output:\n%s", want, out)
		}
	}
}
