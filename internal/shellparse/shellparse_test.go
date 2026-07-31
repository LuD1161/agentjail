package shellparse

import (
	"reflect"
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
		// P6 hardening: interpreter wrappers, process wrappers, newline
		// splitting, and command substitution.
		{"sh_dash_c", "sh -c 'agentjail policy disable no-sudo'", []string{"sh", "agentjail"}},
		{"bash_dash_c", "bash -c 'agentjail policy disable no-sudo'", []string{"bash", "agentjail"}},
		{"sh_dash_c_double_quoted", `sh -c "agentjail policy disable no-sudo"`, []string{"sh", "agentjail"}},
		{"sh_dash_c_chained_script", "sh -c 'echo hi && agentjail policy disable x'", []string{"sh", "echo", "agentjail"}},
		{"nohup_agentjail", "nohup agentjail policy disable x", []string{"nohup", "agentjail"}},
		{"timeout_agentjail", "timeout 5 agentjail policy disable x", []string{"timeout", "agentjail"}},
		{"timeout_with_duration_unit", "timeout 5s agentjail policy disable x", []string{"timeout", "agentjail"}},
		{"newline_separated", "echo hi\nagentjail policy disable x", []string{"echo", "agentjail"}},
		{"dollar_paren_substitution_whole_cmd", "$(agentjail policy disable x)", []string{"agentjail"}},
		{"backtick_substitution_whole_cmd", "`agentjail policy disable x`", []string{"agentjail"}},
		{"dollar_paren_substitution_embedded", "echo $(agentjail policy disable x)", []string{"echo", "agentjail"}},
		{"backtick_substitution_embedded", "echo `agentjail policy disable x`", []string{"echo", "agentjail"}},
		{"sudo_agentjail_disable", "sudo agentjail policy disable no-sudo", []string{"sudo", "agentjail"}},
		{"xargs_agentjail", "echo x | xargs agentjail policy disable", []string{"echo", "xargs", "agentjail"}},
		{"nice_agentjail", "nice -n 10 agentjail policy disable x", []string{"nice", "agentjail"}},
		{"stdbuf_agentjail", "stdbuf -oL agentjail policy disable x", []string{"stdbuf", "agentjail"}},
		{"setsid_agentjail", "setsid agentjail policy disable x", []string{"setsid", "agentjail"}},
		{"command_exec_agentjail", "command agentjail policy disable x", []string{"command", "agentjail"}},
		{"nested_wrapper_interpreter", "sudo sh -c 'agentjail policy disable x'", []string{"sudo", "sh", "agentjail"}},
		{"semicolon_agentjail_second", "echo hi; agentjail policy disable x", []string{"echo", "agentjail"}},
		// Non-shell scripting interpreters: the inline code is not shell
		// syntax, so it is not recursively parsed as a command — instead
		// quoted string literals inside it are extracted and each is
		// recursively parsed, catching the common "shell out via a string
		// argument" evasion (os.system/execSync/system/shell_exec).
		{"python_dash_c_os_system", `python -c 'import os; os.system("agentjail policy disable no-sudo")'`, []string{"python", "agentjail"}},
		{"python3_dash_c_single_quoted_inner", `python3 -c "os.system('agentjail policy disable x')"`, []string{"python3", "agentjail"}},
		{"node_dash_e_execSync", `node -e 'require("child_process").execSync("agentjail policy disable x")'`, []string{"node", "child_process", "agentjail"}},
		{"node_dash_dash_eval", `node --eval 'require("child_process").execSync("agentjail policy disable x")'`, []string{"node", "child_process", "agentjail"}},
		{"nodejs_dash_e", `nodejs -e 'require("child_process").execSync("agentjail policy disable x")'`, []string{"nodejs", "child_process", "agentjail"}},
		{"perl_dash_e_system", `perl -e 'system("agentjail policy disable x")'`, []string{"perl", "agentjail"}},
		{"ruby_dash_e_system", `ruby -e 'system("agentjail policy disable x")'`, []string{"ruby", "agentjail"}},
		{"php_dash_r_system", `php -r 'system("agentjail policy disable x");'`, []string{"php", "agentjail"}},
		{"python_leading_flag_before_dash_c", `python -u -c 'os.system("agentjail policy disable x")'`, []string{"python", "agentjail"}},
		// Regression: no inline-code flag present — the interpreter name is
		// still reported but no recursion into the (unread) script file.
		{"python_script_file_no_recursion", "python script.py --arg", []string{"python"}},
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
	if r.Invocations == nil {
		t.Error("expected non-nil Invocations slice for empty input")
	}
}

func TestParseInvocations(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want []Invocation
	}{
		{
			name: "git global options",
			cmd:  `git -C "/tmp/work repo" -c color.ui=false push origin HEAD:refs/heads/topic`,
			want: []Invocation{{Binary: "git", Arguments: []string{"-C", "/tmp/work repo", "-c", "color.ui=false", "push", "origin", "HEAD:refs/heads/topic"}}},
		},
		{
			name: "text argument is not an invocation",
			cmd:  `rg -n "git push" README.md`,
			want: []Invocation{{Binary: "rg", Arguments: []string{"-n", "git push", "README.md"}}},
		},
		{
			name: "environment wrapper",
			cmd:  `env TRACE=1 git -C /tmp/work push origin topic`,
			want: []Invocation{
				{Binary: "env", Arguments: []string{"TRACE=1", "git", "-C", "/tmp/work", "push", "origin", "topic"}},
				{Binary: "git", Arguments: []string{"-C", "/tmp/work", "push", "origin", "topic"}},
			},
		},
		{
			name: "shell script",
			cmd:  `sh -c 'git -C /tmp/work push origin topic'`,
			want: []Invocation{
				{Binary: "sh", Arguments: []string{"-c", "git -C /tmp/work push origin topic"}},
				{Binary: "git", Arguments: []string{"-C", "/tmp/work", "push", "origin", "topic"}},
			},
		},
		{
			name: "chained commands",
			cmd:  `echo ready && /usr/bin/git status`,
			want: []Invocation{
				{Binary: "echo", Arguments: []string{"ready"}},
				{Binary: "git", Arguments: []string{"status"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Parse(tt.cmd).Invocations
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Parse(%q).Invocations = %#v, want %#v", tt.cmd, got, tt.want)
			}
		})
	}
}

// TestParse_ScriptInterpreterEvasion is the acceptance test for surfacing
// "agentjail" (and the interpreter itself) when a flagged binary is buried
// inside a non-shell scripting interpreter's inline code argument. It checks
// inclusion rather than an exact binary list, since the best-effort quoted-
// string scan may also surface incidental non-binary tokens (e.g.
// "child_process" from a JS require() call) alongside the real evasion.
func TestParse_ScriptInterpreterEvasion(t *testing.T) {
	tests := []struct {
		name        string
		cmd         string
		wantInclude []string
	}{
		{
			"python_os_system",
			`python -c 'import os; os.system("agentjail policy disable no-sudo")'`,
			[]string{"python", "agentjail"},
		},
		{
			"python3_os_system_single_quoted",
			`python3 -c "os.system('agentjail policy disable x')"`,
			[]string{"python3", "agentjail"},
		},
		{
			"node_execSync",
			`node -e 'require("child_process").execSync("agentjail policy disable x")'`,
			[]string{"node", "agentjail"},
		},
		{
			"perl_system",
			`perl -e 'system("agentjail policy disable x")'`,
			[]string{"perl", "agentjail"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Parse(tt.cmd)
			for _, want := range tt.wantInclude {
				found := false
				for _, b := range got.Binaries {
					if b == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Parse(%q).Binaries = %v, missing required binary %q", tt.cmd, got.Binaries, want)
				}
			}
		})
	}
}
