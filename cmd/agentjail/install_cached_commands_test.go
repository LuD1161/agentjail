package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/agents"
)

func TestFullUninstallPreservesActualCachedAgentCommands(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("ZDOTDIR", filepath.Join(home, ".zsh"))
	t.Setenv("AGENTJAIL_SEND_ANONYMOUS_USAGE_STATS", "false")
	isolateLegacyDaemonLog(t)
	env := buildAgentsEnv(home)
	env.LookPath = func(name string) (string, error) { return filepath.Join(env.BinDir, name), nil }
	if err := os.MkdirAll(env.BinDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, binary := range []string{env.HookBin, env.CLIBin} {
		if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 49\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, agent := range agents.Registry() {
		if err := agent.Install(env); err != nil {
			t.Fatalf("install %s: %v", agent.ID(), err)
		}
		if !agent.Status(env).Installed {
			t.Fatalf("%s was not registered before uninstall", agent.ID())
		}
	}

	var cached []cachedAgentCommand
	for _, config := range []struct{ agent, path string }{
		{"claude-code", filepath.Join(home, ".claude", "settings.json")},
		{"codex", filepath.Join(home, ".codex", "hooks.json")},
		{"cursor", filepath.Join(home, ".cursor", "hooks.json")},
	} {
		cached = append(cached, snapshotCachedHooks(t, config.agent, config.path)...)
	}
	for _, config := range []struct{ agent, path string }{
		{"claude-code", filepath.Join(home, ".claude", "settings.json")},
		{"cursor", filepath.Join(home, ".cursor", "cli-config.json")},
	} {
		var document struct {
			StatusLine struct{ Command string } `json:"statusLine"`
		}
		readCachedCommandConfig(t, config.path, &document)
		if document.StatusLine.Command == "" {
			t.Fatalf("%s statusline was not installed", config.agent)
		}
		cached = append(cached, cachedAgentCommand{agent: config.agent, event: "statusline", command: document.StatusLine.Command})
	}

	result := performFullUninstall(home, "unsupported", false, false)
	if result.HardFailed || result.Aborted || !result.Retired || !result.DaemonSkipped {
		t.Fatalf("uninstall failed: %+v", result)
	}
	for _, agent := range agents.Registry() {
		if agent.Status(env).Installed {
			t.Errorf("%s remains registered after uninstall", agent.ID())
		}
	}
	for _, cached := range cached {
		t.Run(cached.agent+"/"+cached.event, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "/bin/sh", "-c", cached.command)
			command.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
			command.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{}}`)
			var stdout, stderr bytes.Buffer
			command.Stdout, command.Stderr = &stdout, &stderr
			if err := command.Run(); err != nil {
				t.Fatalf("cached command failed: %v; stderr=%s", err, stderr.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("cached command emitted an error: %s", stderr.String())
			}
			if cached.event == "statusline" {
				if stdout.Len() != 0 {
					t.Fatalf("retired statusline was not quiet: %s", stdout.String())
				}
				return
			}
			var response map[string]string
			if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
				t.Fatalf("invalid hook response %q: %v", stdout.String(), err)
			}
			if cached.agent == "cursor" {
				if len(response) != 1 || response["permission"] != "allow" {
					t.Fatalf("Cursor response = %s", stdout.String())
				}
			} else if response == nil || len(response) != 0 {
				t.Fatalf("hook overrode native permissions: %s", stdout.String())
			}
		})
	}
}

type cachedAgentCommand struct{ agent, event, command string }

func snapshotCachedHooks(t *testing.T, agent, path string) []cachedAgentCommand {
	t.Helper()
	var document struct {
		Hooks map[string][]struct {
			Command string
			Hooks   []struct{ Command string }
		}
	}
	readCachedCommandConfig(t, path, &document)
	var commands []cachedAgentCommand
	for event, groups := range document.Hooks {
		for _, group := range groups {
			if agent == "cursor" {
				if group.Command == "" {
					t.Fatalf("%s %s has an empty command", agent, event)
				}
				commands = append(commands, cachedAgentCommand{agent, event, group.Command})
			} else {
				for index, hook := range group.Hooks {
					if hook.Command == "" {
						t.Fatalf("%s %s has an empty command", agent, event)
					}
					commands = append(commands, cachedAgentCommand{agent, fmt.Sprintf("%s/%d", event, index), hook.Command})
				}
			}
		}
	}
	if len(commands) == 0 {
		t.Fatalf("%s has no registered hooks to exercise", agent)
	}
	return commands
}

func readCachedCommandConfig(t *testing.T, path string, destination any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, destination); err != nil {
		t.Fatal(err)
	}
}
