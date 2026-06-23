package shellparse

import (
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want []string
	}{
		{"simple", "git status", []string{"git"}},
		{"pipeline", "cat file | grep foo | wc -l", []string{"cat", "grep", "wc"}},
		{"chain_and", "go build && go test", []string{"go", "go"}},
		{"chain_or", "make || echo fail", []string{"make", "echo"}},
		{"semicolon", "echo a; echo b", []string{"echo", "echo"}},
		{"mixed", "git status && git push | tee log.txt", []string{"git", "git", "tee"}},
		{"absolute_path", "/usr/local/bin/agentjail policy list", []string{"agentjail"}},
		{"quoted_path", `"$HOME/.agentjail/bin/agentjail" mcp allow`, []string{"agentjail"}},
		{"env_prefix", "KEY=value FOO=bar mycommand arg1", []string{"mycommand"}},
		{"git_add_agentjail_path", "git add cmd/agentjail/update.go", []string{"git"}},
		{"go_build_agentjail", "go build ./cmd/agentjail/...", []string{"go"}},
		{"grep_in_agentjail", "grep -rn update /Users/dev/project/cmd/agentjail/", []string{"grep"}},
		{"agentjail_update", "agentjail update --force", []string{"agentjail"}},
		{"codex_exec_with_agentjail_in_prompt", `codex exec -s read-only "review agentjail policy"`, []string{"codex"}},
		{"empty", "", []string{}},
		{"whitespace_only", "   ", []string{}},
		{"redirect", "echo hello > /tmp/out.txt", []string{"echo"}},
		{"which_substitution", "$(which agentjail) mcp allow", []string{"agentjail"}},
		{"command_v_substitution", "$(command -v agentjail) policy disable foo", []string{"agentjail"}},
		{"single_quoted_path", "'/usr/bin/agentjail' update", []string{"agentjail"}},
		// Additional edge cases
		{"sudo_cmd", "sudo rm -rf /tmp/foo", []string{"sudo", "rm"}},
		{"sudo_with_flag", "sudo -u root ls /etc", []string{"sudo", "ls"}},
		{"env_cmd", "env FOO=bar myapp --flag", []string{"env", "myapp"}},
		{"subshell", "(cd /tmp && ls -la)", []string{"cd", "ls"}},
		{"pipe_with_quoted", `cat file | grep "foo bar" | wc -l`, []string{"cat", "grep", "wc"}},
		{"no_split_inside_quotes", `echo "hello && world"`, []string{"echo"}},
		{"no_split_pipe_in_quotes", `awk '{print $1 | "sort"}'`, []string{"awk"}},
		{"which_standalone", "which agentjail", []string{"which"}},
		{"command_v_standalone", "command -v agentjail", []string{"command"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Parse(tt.cmd)
			if len(got.Binaries) != len(tt.want) {
				t.Fatalf("Parse(%q).Binaries = %v, want %v", tt.cmd, got.Binaries, tt.want)
			}
			for i, b := range got.Binaries {
				if b != tt.want[i] {
					t.Errorf("Parse(%q).Binaries[%d] = %q, want %q", tt.cmd, i, b, tt.want[i])
				}
			}
		})
	}
}

func TestParseResult_EmptyNotNil(t *testing.T) {
	r := Parse("")
	if r.Binaries == nil {
		t.Error("expected non-nil Binaries slice for empty input")
	}
}
