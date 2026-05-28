package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// TestParseEvalLine verifies that JSON log lines are parsed into evalLine structs.
func TestParseEvalLine(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantMsg string
		wantAct string
		wantTool string
		wantRule string
		wantElap int64
		wantLevel string
	}{
		{
			name:    "eval_ask",
			input:   `{"time":"2026-05-23T16:56:55.424479-07:00","level":"INFO","msg":"eval","req_id":"hook-manual-test-Bash","tool":"Bash","action":"ask","rule_id":"file_policy/default","elapsed_us":867}`,
			wantMsg: "eval", wantAct: "ask", wantTool: "Bash", wantRule: "file_policy/default", wantElap: 867, wantLevel: "INFO",
		},
		{
			name:    "eval_deny",
			input:   `{"time":"2026-05-23T17:49:30.000-07:00","level":"INFO","msg":"eval","req_id":"hook-xxx-Bash","tool":"Bash","action":"deny","rule_id":"command_policy/no-bash-touch-sensitive-path","elapsed_us":4362}`,
			wantMsg: "eval", wantAct: "deny", wantTool: "Bash", wantRule: "command_policy/no-bash-touch-sensitive-path", wantElap: 4362, wantLevel: "INFO",
		},
		{
			name:    "eval_allow",
			input:   `{"time":"2026-05-23T17:45:09.997423-07:00","level":"INFO","msg":"eval","req_id":"hook-yyy-Write","tool":"Write","action":"allow","rule_id":"file_policy/project_allow","elapsed_us":623}`,
			wantMsg: "eval", wantAct: "allow", wantTool: "Write", wantRule: "file_policy/project_allow", wantElap: 623, wantLevel: "INFO",
		},
		{
			name:    "warn_line",
			input:   `{"time":"2026-05-23T16:56:55.111-07:00","level":"WARN","msg":"malformed request","err":"unexpected EOF"}`,
			wantMsg: "malformed request", wantLevel: "WARN",
		},
		{
			name:    "info_startup",
			input:   `{"time":"2026-05-23T16:56:45.811-07:00","level":"INFO","msg":"loaded rego modules","count":4}`,
			wantMsg: "loaded rego modules", wantLevel: "INFO",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got evalLine
			if err := json.Unmarshal([]byte(tc.input), &got); err != nil {
				t.Fatalf("unmarshal error: %v", err)
			}
			if got.Msg != tc.wantMsg {
				t.Errorf("Msg: got %q, want %q", got.Msg, tc.wantMsg)
			}
			if got.Level != tc.wantLevel {
				t.Errorf("Level: got %q, want %q", got.Level, tc.wantLevel)
			}
			if tc.wantAct != "" && got.Action != tc.wantAct {
				t.Errorf("Action: got %q, want %q", got.Action, tc.wantAct)
			}
			if tc.wantTool != "" && got.Tool != tc.wantTool {
				t.Errorf("Tool: got %q, want %q", got.Tool, tc.wantTool)
			}
			if tc.wantRule != "" && got.RuleID != tc.wantRule {
				t.Errorf("RuleID: got %q, want %q", got.RuleID, tc.wantRule)
			}
			if tc.wantElap != 0 && got.ElapsedUs != tc.wantElap {
				t.Errorf("ElapsedUs: got %d, want %d", got.ElapsedUs, tc.wantElap)
			}
		})
	}
}

// TestFormatEvalLine verifies that renderEvalLine produces the expected output
// with and without color.
func TestFormatEvalLine(t *testing.T) {
	ts, _ := time.Parse(time.RFC3339Nano, "2026-05-23T16:56:55.424479-07:00")

	cases := []struct {
		name     string
		line     evalLine
		color    bool
		contains []string // substrings that must appear
		absent   []string // substrings that must NOT appear
	}{
		{
			name: "ask_no_color",
			line: evalLine{
				Time: ts, Level: "INFO", Msg: "eval",
				Agent: "claude", SessionID: "abc123xyz", CWD: "/home/user/project",
				Tool: "Bash", Action: "ask", RuleID: "file_policy/default", ElapsedUs: 867,
			},
			color:    false,
			contains: []string{"16:56:55", "ASK", "Bash", "file_policy/default", "867µs", "Claude", "abc123"},
			absent:   []string{"\033["},
		},
		{
			name: "deny_color",
			line: evalLine{
				Time: ts, Level: "INFO", Msg: "eval",
				Agent: "claude", SessionID: "def456uvw", CWD: "/home/user/repo",
				Tool: "Bash", Action: "deny", RuleID: "command_policy/no-bash-touch-sensitive-path", ElapsedUs: 4362,
			},
			color:    true,
			contains: []string{"16:56:55", "DENY", "Bash", "command_policy/no-bash-touch-sensitive-path", "4362µs", "\033[31;1m", "Claude", "def456"},
		},
		{
			name: "allow_color",
			line: evalLine{
				Time: ts, Level: "INFO", Msg: "eval",
				Agent: "cursor", SessionID: "ghi789rst", CWD: "/home/user/app",
				Tool: "Write", Action: "allow", RuleID: "file_policy/project_allow", ElapsedUs: 623,
			},
			color:    true,
			contains: []string{"16:56:55", "ALLOW", "Write", "file_policy/project_allow", "623µs", "\033[32m", "Cursor", "ghi789"},
		},
		{
			name: "ask_color",
			line: evalLine{
				Time: ts, Level: "INFO", Msg: "eval",
				Agent: "codex", SessionID: "jkl012mno",
				Tool: "AskUserQuestion", Action: "ask", RuleID: "file_policy/default", ElapsedUs: 8992,
			},
			color:    true,
			contains: []string{"AskUserQuestion", "ASK", "\033[33m", "Codex", "jkl012"},
		},
		// SOURCE column: try row shows "try (manual)" dimmed, no raw session.
		{
			name: "try_row_no_color",
			line: evalLine{
				Time: ts, Level: "INFO", Msg: "eval",
				Agent: "try", SessionID: "agentjail-try", CWD: "",
				Tool: "Bash", Action: "ask", RuleID: "r", ElapsedUs: 100,
			},
			color:    false,
			contains: []string{"try (manual)"},
			absent:   []string{"agentjail-try", "\033["},
		},
		{
			name: "try_row_color",
			line: evalLine{
				Time: ts, Level: "INFO", Msg: "eval",
				Agent: "try", SessionID: "agentjail-try", CWD: "",
				Tool: "Bash", Action: "ask", RuleID: "r", ElapsedUs: 100,
			},
			color:    true,
			contains: []string{"try (manual)", "\033[2m"}, // dim ANSI for try
			absent:   []string{"agentjail-try"},
		},
		// SOURCE column: legacy row (no agent/cwd) renders "unknown", no misalignment.
		{
			name: "legacy_row_no_agent",
			line: evalLine{
				Time: ts, Level: "INFO", Msg: "eval",
				// Agent and CWD deliberately empty — pre-upgrade log line.
				Tool: "Bash", Action: "allow", RuleID: "r", ElapsedUs: 50,
			},
			color:    false,
			contains: []string{"unknown", "ALLOW", "Bash"},
			absent:   []string{"\033["},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Capture stdout by redirecting via pipe-like trick: we call
			// renderEvalLine and check what was printed. Since it writes to
			// os.Stdout directly, we build opts with useColor.
			opts := logsOpts{useColor: tc.color}

			// Use a bytes.Buffer to capture output by overriding os.Stdout
			// temporarily via a pipe.
			old := captureStdout(t, func() {
				_ = renderEvalLine(tc.line, opts, nil)
			})

			for _, want := range tc.contains {
				if !strings.Contains(old, want) {
					t.Errorf("output missing %q\nfull output: %q", want, old)
				}
			}
			for _, bad := range tc.absent {
				if strings.Contains(old, bad) {
					t.Errorf("output should not contain %q\nfull output: %q", bad, old)
				}
			}
		})
	}
}

// TestSourceCell verifies the SOURCE cell builder for all three row types.
func TestSourceCell(t *testing.T) {
	cases := []struct {
		name      string
		agent     string
		sessionID string
		cwd       string
		wantIn    []string // substrings that must appear
		wantNot   []string // substrings that must NOT appear
	}{
		{
			name:      "normal_claude",
			agent:     "claude",
			sessionID: "a1b2c3d4e5f6",
			cwd:       "/home/user/myrepo",
			wantIn:    []string{"Claude", "a1b2c3", "myrepo"},
			wantNot:   []string{"try (manual)", "agentjail-try"},
		},
		{
			name:      "try_row_agent_field",
			agent:     "try",
			sessionID: "agentjail-try",
			cwd:       "",
			wantIn:    []string{"try (manual)"},
			wantNot:   []string{"agentjail-try", "Claude", "·"},
		},
		{
			name:      "try_row_session_only",
			agent:     "",
			sessionID: "agentjail-try",
			cwd:       "",
			wantIn:    []string{"try (manual)"},
			wantNot:   []string{"agentjail-try", "·"},
		},
		{
			name:      "legacy_no_agent",
			agent:     "",
			sessionID: "sess-abcdef",
			cwd:       "",
			wantIn:    []string{"unknown", "sess-a"},
			wantNot:   []string{"try (manual)"},
		},
		{
			name:      "codex_with_cwd",
			agent:     "codex",
			sessionID: "xyz789abc",
			cwd:       "/home/user/projects/myapp",
			wantIn:    []string{"Codex", "xyz789", "myapp"},
		},
		{
			name:      "cursor_no_cwd",
			agent:     "cursor",
			sessionID: "cur123",
			cwd:       "",
			wantIn:    []string{"Cursor", "cur123"},
			wantNot:   []string{"·\n"}, // no trailing separator
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sourceCell(tc.agent, tc.sessionID, tc.cwd)
			for _, want := range tc.wantIn {
				if !strings.Contains(got, want) {
					t.Errorf("sourceCell(%q, %q, %q) = %q, want substring %q",
						tc.agent, tc.sessionID, tc.cwd, got, want)
				}
			}
			for _, bad := range tc.wantNot {
				if strings.Contains(got, bad) {
					t.Errorf("sourceCell(%q, %q, %q) = %q, should NOT contain %q",
						tc.agent, tc.sessionID, tc.cwd, got, bad)
				}
			}
		})
	}
}

// TestAgentDisplay verifies the normalization registry covers all expected keys.
func TestAgentDisplay(t *testing.T) {
	cases := []struct {
		agent string
		want  string
	}{
		{"claude", "Claude"},
		{"claude-code", "Claude"},
		{"cursor", "Cursor"},
		{"codex", "Codex"},
		{"try", "try"},
		{"", "unknown"},
		{"some-unknown-agent", "unknown"},
	}
	for _, tc := range cases {
		got := agentDisplay(tc.agent)
		if got != tc.want {
			t.Errorf("agentDisplay(%q) = %q, want %q", tc.agent, got, tc.want)
		}
	}
}

// TestCwdShort verifies home-relativization and last-2-segment truncation.
func TestCwdShort(t *testing.T) {
	home, _ := os.UserHomeDir()

	cases := []struct {
		name   string
		input  string
		wantIn string
	}{
		{"empty", "", ""},
		// Home-relative short path (2 segments after ~): "~" counts as 1 segment,
		// so ~/a has 2 segments and is not truncated. ~/a/b has 3 and is truncated.
		{"home_short", home + "/myrepo", ""},
		{"long_path_truncated", "/a/b/c/d/e/f", "…/e/f"},
		{"two_segments_ok", "/a/b", "/a/b"},
		{"single_segment", "/tmp", "/tmp"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cwdShort(tc.input)
			if tc.input == "" {
				if got != "" {
					t.Errorf("cwdShort(%q) = %q, want empty", tc.input, got)
				}
				return
			}
			if tc.name == "home_short" {
				// Check: home-relative path uses ~ prefix and ends with the basename.
				if !strings.HasPrefix(got, "~") {
					t.Errorf("cwdShort(%q) = %q, want ~ prefix", tc.input, got)
				}
				if !strings.HasSuffix(got, "myrepo") {
					t.Errorf("cwdShort(%q) = %q, want suffix 'myrepo'", tc.input, got)
				}
				return
			}
			if got != tc.wantIn {
				t.Errorf("cwdShort(%q) = %q, want %q", tc.input, got, tc.wantIn)
			}
		})
	}
}

// TestActionFilter verifies that action filtering works correctly.
func TestActionFilter(t *testing.T) {
	ts := time.Now()
	denyLine := evalLine{
		Time: ts, Level: "INFO", Msg: "eval",
		Tool: "Bash", Action: "deny", RuleID: "r", ElapsedUs: 1,
	}
	askLine := evalLine{
		Time: ts, Level: "INFO", Msg: "eval",
		Tool: "Bash", Action: "ask", RuleID: "r", ElapsedUs: 1,
	}

	cases := []struct {
		name    string
		actions []string
		line    evalLine
		wantOut bool
	}{
		{"deny_filter_matches_deny", []string{"deny"}, denyLine, true},
		{"deny_filter_blocks_ask", []string{"deny"}, askLine, false},
		{"ask_filter_matches_ask", []string{"ask"}, askLine, true},
		{"ask_deny_filter_matches_deny", []string{"ask", "deny"}, denyLine, true},
		{"ask_deny_filter_matches_ask", []string{"ask", "deny"}, askLine, true},
		{"no_filter_passes_all", nil, denyLine, true},
		{"no_filter_passes_ask", nil, askLine, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := logsOpts{useColor: false, actions: tc.actions}
			out := captureStdout(t, func() {
				_ = renderEvalLine(tc.line, opts, nil)
			})
			hasOutput := strings.TrimSpace(out) != ""
			if hasOutput != tc.wantOut {
				t.Errorf("got output=%v, want output=%v (output: %q)", hasOutput, tc.wantOut, out)
			}
		})
	}
}

// TestToolFilter verifies that --tool filtering works.
func TestToolFilter(t *testing.T) {
	ts := time.Now()
	bashLine := evalLine{Time: ts, Level: "INFO", Msg: "eval", Tool: "Bash", Action: "ask", RuleID: "r", ElapsedUs: 1}
	readLine := evalLine{Time: ts, Level: "INFO", Msg: "eval", Tool: "Read", Action: "ask", RuleID: "r", ElapsedUs: 1}

	cases := []struct {
		name    string
		tool    string
		line    evalLine
		wantOut bool
	}{
		{"bash_filter_matches_bash", "Bash", bashLine, true},
		{"bash_filter_blocks_read", "Bash", readLine, false},
		{"no_filter_passes_bash", "", bashLine, true},
		{"no_filter_passes_read", "", readLine, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := logsOpts{useColor: false, tool: tc.tool}
			out := captureStdout(t, func() {
				_ = renderEvalLine(tc.line, opts, nil)
			})
			hasOutput := strings.TrimSpace(out) != ""
			if hasOutput != tc.wantOut {
				t.Errorf("got output=%v, want output=%v (output: %q)", hasOutput, tc.wantOut, out)
			}
		})
	}
}

// TestSinceFilter verifies that --since filtering drops old lines.
func TestSinceFilter(t *testing.T) {
	oldTime := time.Now().Add(-2 * time.Hour)
	recentTime := time.Now().Add(-1 * time.Minute)
	dur := 30 * time.Minute // filter: only last 30 minutes

	cases := []struct {
		name    string
		lineTime time.Time
		since   time.Duration
		wantOut bool
	}{
		{"recent_line_passes", recentTime, dur, true},
		{"old_line_filtered", oldTime, dur, false},
		{"no_since_passes_old", oldTime, 0, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line := evalLine{
				Time: tc.lineTime, Level: "INFO", Msg: "eval",
				Tool: "Bash", Action: "ask", RuleID: "r", ElapsedUs: 1,
			}
			opts := logsOpts{useColor: false, since: tc.since}
			out := captureStdout(t, func() {
				_ = renderEvalLine(line, opts, nil)
			})
			hasOutput := strings.TrimSpace(out) != ""
			if hasOutput != tc.wantOut {
				t.Errorf("since=%v, line age=%v: got output=%v, want=%v (output: %q)",
					tc.since, time.Since(tc.lineTime).Round(time.Second), hasOutput, tc.wantOut, out)
			}
		})
	}
}

// TestColorDisabledStripsANSI verifies that --no-color / useColor=false produces
// no escape sequences in the output.
func TestColorDisabledStripsANSI(t *testing.T) {
	ts := time.Now()
	cases := []struct {
		name string
		line evalLine
	}{
		{"deny", evalLine{Time: ts, Level: "INFO", Msg: "eval", Tool: "Bash", Action: "deny", RuleID: "r", ElapsedUs: 100}},
		{"allow", evalLine{Time: ts, Level: "INFO", Msg: "eval", Tool: "Write", Action: "allow", RuleID: "r", ElapsedUs: 200}},
		{"ask", evalLine{Time: ts, Level: "INFO", Msg: "eval", Tool: "AskUserQuestion", Action: "ask", RuleID: "r", ElapsedUs: 300}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := logsOpts{useColor: false}
			out := captureStdout(t, func() {
				_ = renderEvalLine(tc.line, opts, nil)
			})
			if strings.Contains(out, "\033[") {
				t.Errorf("output contains ANSI escape when color disabled: %q", out)
			}
		})
	}

	// Also test WARN/ERROR lines.
	t.Run("warn_no_color", func(t *testing.T) {
		line := evalLine{Time: ts, Level: "WARN", Msg: "malformed request", Err: "unexpected EOF"}
		opts := logsOpts{useColor: false}
		out := captureStdout(t, func() {
			_ = renderWarnErrorLine(line, opts, false)
		})
		if strings.Contains(out, "\033[") {
			t.Errorf("WARN output contains ANSI escape when color disabled: %q", out)
		}
	})
}

// ─── impact field tests ───────────────────────────────────────────────────────

// TestImpactFor_PolicyDeclared verifies that a non-empty line.Impact takes
// priority over the builtin heuristic and the reason fallback.
func TestImpactFor_PolicyDeclared(t *testing.T) {
	// Policy-declared impact must win even when a builtin heuristic would match.
	line := evalLine{
		RuleID: "command_policy/no-sudo",        // matches builtinImpact
		Impact: "would call sudo on prod cluster", // policy-declared
		Reason: "sudo escalates privileges",
	}
	got := impactFor(line)
	const want = "would call sudo on prod cluster"
	if got != want {
		t.Errorf("impactFor with Impact set: got %q, want %q", got, want)
	}
}

// TestImpactFor_BuiltinFallback verifies that when Impact is empty, the
// builtin heuristic fires.
func TestImpactFor_BuiltinFallback(t *testing.T) {
	line := evalLine{
		RuleID: "command_policy/no-sudo",
		Impact: "", // not set
	}
	got := impactFor(line)
	if !strings.Contains(got, "root") {
		t.Errorf("builtinImpact for no-sudo should contain 'root', got %q", got)
	}
}

// TestImpactFor_ReasonFallback verifies that when Impact is empty and no
// builtin matches, the reason field is used.
func TestImpactFor_ReasonFallback(t *testing.T) {
	line := evalLine{
		RuleID: "custom/user-authored-rule",
		Impact: "",
		Reason: "this operation is blocked by custom policy",
	}
	got := impactFor(line)
	if !strings.Contains(got, "custom policy") {
		t.Errorf("reason fallback: got %q, want substring 'custom policy'", got)
	}
}

// ─── impact-for tests ─────────────────────────────────────────────────────────

// TestImpactFor covers every rule_id pattern + the fallback.
func TestImpactFor(t *testing.T) {
	cases := []struct {
		name   string
		line   evalLine
		wantIn string // substring that must appear in the result
	}{
		{
			name:   "ssh_read",
			line:   evalLine{RuleID: "command_policy/no-bash-touch-sensitive-path", Summary: "cat ~/.ssh/id_rsa"},
			wantIn: "SSH key",
		},
		{
			name:   "ssh_write",
			line:   evalLine{RuleID: "command_policy/no-bash-touch-sensitive-path", Summary: "echo foo > ~/.ssh/id_rsa"},
			wantIn: "overwrite SSH key",
		},
		{
			name:   "aws_read",
			line:   evalLine{RuleID: "command_policy/no-bash-touch-sensitive-path", Summary: "cat ~/.aws/credentials"},
			wantIn: "AWS",
		},
		{
			name:   "aws_write",
			line:   evalLine{RuleID: "command_policy/no-bash-touch-sensitive-path", Summary: "tee ~/.aws/credentials"},
			wantIn: "overwrite AWS",
		},
		{
			name:   "gnupg",
			line:   evalLine{RuleID: "command_policy/no-bash-touch-sensitive-path", Summary: "cat ~/.gnupg/secring.gpg"},
			wantIn: "GPG",
		},
		{
			name:   "env_file",
			line:   evalLine{RuleID: "command_policy/no-bash-touch-sensitive-path", Summary: "cat .env"},
			wantIn: "env file",
		},
		{
			name:   "etc",
			line:   evalLine{RuleID: "command_policy/no-bash-touch-sensitive-path", Summary: "cat /etc/passwd"},
			wantIn: "system config",
		},
		{
			name:   "file_policy_ssh_read",
			line:   evalLine{RuleID: "file_policy/sensitive_credential", Tool: "Read", Summary: "~/.ssh/id_rsa"},
			wantIn: "SSH",
		},
		{
			name:   "file_policy_aws_write",
			line:   evalLine{RuleID: "file_policy/sensitive_credential", Tool: "Write", Summary: "~/.aws/credentials"},
			wantIn: "AWS",
		},
		{
			name:   "no_rm_rf",
			line:   evalLine{RuleID: "command_policy/no-rm-rf-absolute"},
			wantIn: "recursive",
		},
		{
			name:   "no_pipe_to_shell",
			line:   evalLine{RuleID: "command_policy/no-pipe-to-shell"},
			wantIn: "remote script",
		},
		{
			name:   "no_sudo",
			line:   evalLine{RuleID: "command_policy/no-sudo"},
			wantIn: "root",
		},
		{
			name:   "no_git_push_force",
			line:   evalLine{RuleID: "command_policy/no-git-push-force"},
			wantIn: "remote history",
		},
		{
			name:   "no_env_exfil",
			line:   evalLine{RuleID: "command_policy/no-env-exfil"},
			wantIn: "env",
		},
		{
			name:   "no_gpg_secret_export",
			line:   evalLine{RuleID: "command_policy/no-gpg-secret-export"},
			wantIn: "GPG",
		},
		{
			name:   "no_chmod_777",
			line:   evalLine{RuleID: "command_policy/no-chmod-777"},
			wantIn: "access controls",
		},
		{
			name:   "no_dd_device_read",
			line:   evalLine{RuleID: "command_policy/no-dd-device-read"},
			wantIn: "disk",
		},
		{
			name:   "no_device_overwrite",
			line:   evalLine{RuleID: "command_policy/no-device-overwrite"},
			wantIn: "block device",
		},
		{
			name:   "no_launchctl_remove",
			line:   evalLine{RuleID: "command_policy/no-launchctl-remove"},
			wantIn: "launchd",
		},
		{
			name:   "no_systemctl_disrupt",
			line:   evalLine{RuleID: "command_policy/no-systemctl-disrupt"},
			wantIn: "systemd",
		},
		{
			name:   "mcp_blocked",
			line:   evalLine{RuleID: "mcp_policy/blocked"},
			wantIn: "MCP",
		},
		{
			name:   "mcp_unknown",
			line:   evalLine{RuleID: "mcp_policy/unknown"},
			wantIn: "MCP",
		},
		{
			name:   "fallback_reason",
			line:   evalLine{RuleID: "some-unknown-rule", Reason: "custom denial reason"},
			wantIn: "custom denial reason",
		},
		{
			name:   "fallback_rule_id",
			line:   evalLine{RuleID: "some-unknown-rule"},
			wantIn: "some-unknown-rule",
		},
		{
			name: "fallback_truncated",
			line: evalLine{
				RuleID: "x",
				Reason: strings.Repeat("a", 60),
			},
			wantIn: "...",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := impactFor(tc.line)
			if !strings.Contains(got, tc.wantIn) {
				t.Errorf("impactFor(%+v) = %q, want substring %q", tc.line, got, tc.wantIn)
			}
		})
	}
}

// TestLatencyFormat verifies ms rounding and the sub-1ms lightning bolt.
func TestLatencyFormat(t *testing.T) {
	cases := []struct {
		name     string
		us       int64
		color    bool
		wantIn   string
		wantNot  string
	}{
		{"21ms_no_color", 21000, false, "21ms", "µs"},
		{"5ms_no_color", 4500, false, "5ms", "µs"},   // round to nearest
		{"sub1ms_no_color", 800, false, "<1ms", "µs"},
		{"sub1ms_has_bolt", 800, false, "⚡", ""},
		{"21ms_color", 21000, true, "21ms", "µs"},
		{"sub1ms_color_yellow", 999, true, "\033[33m", ""},
		{"1ms_boundary", 1000, false, "1ms", "<1ms"},
		{"1499_rounds_to_1ms", 1499, false, "1ms", "2ms"},
		{"1500_rounds_to_2ms", 1500, false, "2ms", "1ms"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := latencyStr(tc.us, tc.color)
			if tc.wantIn != "" && !strings.Contains(got, tc.wantIn) {
				t.Errorf("latencyStr(%d, %v) = %q, want substring %q", tc.us, tc.color, got, tc.wantIn)
			}
			if tc.wantNot != "" && strings.Contains(got, tc.wantNot) {
				t.Errorf("latencyStr(%d, %v) = %q, should not contain %q", tc.us, tc.color, got, tc.wantNot)
			}
		})
	}
}

// TestSavedSummary verifies impact bucketing and deduplication.
func TestSavedSummary(t *testing.T) {
	cases := []struct {
		name    string
		impacts []string
		wantIn  string
		wantNot string
	}{
		{
			name:    "empty",
			impacts: nil,
			wantIn:  "",
		},
		{
			name:    "single_ssh",
			impacts: []string{"would read SSH key"},
			wantIn:  "SSH",
		},
		{
			name: "three_ssh_deduped",
			// Three identical SSH-read impacts → "3 SSH reads"
			impacts: []string{
				"would read SSH key",
				"would read SSH key",
				"would read SSH key",
			},
			wantIn:  "3 SSH reads",
			wantNot: "1 SSH reads, 1 SSH reads",
		},
		{
			name: "mixed_buckets",
			impacts: []string{
				"would read SSH key",
				"would escalate to root",
				"would call blocked MCP server",
			},
			wantIn:  "SSH",
		},
		{
			name: "max_three_displayed",
			impacts: []string{
				"would read SSH key",
				"would escalate to root",
				"would call blocked MCP server",
				"would recursively delete absolute path",
				"would overwrite AWS credentials",
			},
			// Only the first 3 unique buckets appear (insertion order).
			wantIn:  "SSH reads",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := savedSummary(tc.impacts)
			if tc.wantIn == "" {
				if got != "" {
					t.Errorf("savedSummary(%v) = %q, want empty", tc.impacts, got)
				}
				return
			}
			if !strings.Contains(got, tc.wantIn) {
				t.Errorf("savedSummary(%v) = %q, want substring %q", tc.impacts, got, tc.wantIn)
			}
			if tc.wantNot != "" && strings.Contains(got, tc.wantNot) {
				t.Errorf("savedSummary(%v) = %q, should NOT contain %q", tc.impacts, got, tc.wantNot)
			}
		})
	}
}

// TestImpactBucketing verifies that repeated denies of the same category are
// aggregated rather than listed individually.
func TestImpactBucketing(t *testing.T) {
	// Three SSH write impacts → bucket "SSH writes" with count 3.
	impacts := []string{
		"would overwrite SSH key",
		"would overwrite SSH key",
		"would overwrite SSH key",
	}
	got := savedSummary(impacts)
	if !strings.Contains(got, "3 SSH writes") {
		t.Errorf("expected '3 SSH writes' in %q", got)
	}
	if strings.Contains(got, "1 SSH writes") {
		t.Errorf("should not list individually; got %q", got)
	}
}

// TestMedianLatency verifies median computation across typical ring-buffer slices.
func TestMedianLatency(t *testing.T) {
	cases := []struct {
		name   string
		lats   []int64
		wantIn string
	}{
		{"empty", nil, "—"},
		{"single_5ms", []int64{5000}, "5ms"},
		{"three_values", []int64{1000, 5000, 10000}, "5ms"},
		{"sub1ms_median", []int64{500, 800, 900}, "<1ms"},
		{"even_count_takes_upper", []int64{1000, 5000, 10000, 20000}, "10ms"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := medianLatencyStr(tc.lats)
			if !strings.Contains(got, tc.wantIn) {
				t.Errorf("medianLatencyStr(%v) = %q, want substring %q", tc.lats, got, tc.wantIn)
			}
		})
	}
}

// TestRichDisabledNoANSI verifies that --basic or useColor=false produces no
// ANSI escapes from renderEvalLine.
func TestRichDisabledNoANSI(t *testing.T) {
	ts := time.Now()
	cases := []struct {
		name string
		line evalLine
	}{
		{"deny_basic", evalLine{Time: ts, Level: "INFO", Msg: "eval", Tool: "Bash", Action: "deny", RuleID: "command_policy/no-bash-touch-sensitive-path", ElapsedUs: 4000}},
		{"allow_basic", evalLine{Time: ts, Level: "INFO", Msg: "eval", Tool: "Write", Action: "allow", RuleID: "r", ElapsedUs: 1000}},
		{"ask_basic", evalLine{Time: ts, Level: "INFO", Msg: "eval", Tool: "AskUserQuestion", Action: "ask", RuleID: "r", ElapsedUs: 800}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// useColor=false + nil rich → no ANSI.
			opts := logsOpts{useColor: false, basic: true}
			out := captureStdout(t, func() {
				_ = renderEvalLine(tc.line, opts, nil)
			})
			if strings.Contains(out, "\033[") {
				t.Errorf("basic mode output contains ANSI escape: %q", out)
			}
		})
	}
}

// TestRichModeImpactColumnForDeny verifies that in rich mode, DENY rows show
// an impact string rather than the raw rule_id.
func TestRichModeImpactColumnForDeny(t *testing.T) {
	ts := time.Now()
	line := evalLine{
		Time:      ts,
		Level:     "INFO",
		Msg:       "eval",
		Tool:      "Bash",
		Action:    "deny",
		RuleID:    "command_policy/no-sudo",
		ElapsedUs: 3000,
	}

	// We cannot exercise the actual ANSI scrolling region in a unit test
	// (no real TTY), but we CAN verify that with a non-nil richState whose
	// active=false the render path takes the basic branch. The richState
	// with active=true would call redrawBar which writes ANSI — that's the
	// manual smoke path for the rich scrolling-region mode.
	//
	// What we test: with active=false rich, output falls through to basic.
	rich := &richState{active: false}
	opts := logsOpts{useColor: false}
	out := captureStdout(t, func() {
		_ = renderEvalLine(line, opts, rich)
	})
	// Basic path: rule_id appears.
	if !strings.Contains(out, "command_policy/no-sudo") {
		t.Errorf("basic-fallback output missing rule_id: %q", out)
	}
}

// TestImpactFor_AllRuleIDs is a comprehensive table of all supported rule_ids.
func TestImpactFor_AllRuleIDs(t *testing.T) {
	rules := []struct {
		ruleID string
		wantIn string
	}{
		{"command_policy/no-bash-touch-sensitive-path", "sensitive"},
		{"file_policy/sensitive_credential", "credential"},
		{"command_policy/no-rm-rf-absolute", "delete"},
		{"command_policy/no-pipe-to-shell", "shell"},
		{"command_policy/no-sudo", "root"},
		{"command_policy/no-git-push-force", "history"},
		{"command_policy/no-env-exfil", "env"},
		{"command_policy/no-gpg-secret-export", "GPG"},
		{"command_policy/no-chmod-777", "access"},
		{"command_policy/no-dd-device-read", "disk"},
		{"command_policy/no-device-overwrite", "device"},
		{"command_policy/no-launchctl-remove", "launchd"},
		{"command_policy/no-systemctl-disrupt", "systemd"},
		{"mcp_policy/blocked", "MCP"},
		{"mcp_policy/unknown", "MCP"},
	}

	for _, r := range rules {
		t.Run(r.ruleID, func(t *testing.T) {
			line := evalLine{RuleID: r.ruleID, Tool: "Bash"}
			got := impactFor(line)
			if !strings.Contains(strings.ToLower(got), strings.ToLower(r.wantIn)) {
				t.Errorf("impactFor(ruleID=%q) = %q, want substring %q", r.ruleID, got, r.wantIn)
			}
		})
	}
}

// ─── Task 2: colored agent glyph tests ───────────────────────────────────────

// withTestEnv sets logsEnvLookup to return the provided key→value map for the
// duration of the test, then restores it.
func withTestEnv(t *testing.T, env map[string]string) {
	t.Helper()
	orig := logsEnvLookup
	logsEnvLookup = func(key string) string { return env[key] }
	t.Cleanup(func() { logsEnvLookup = orig })
}

// TestDetectLogsUTF8 verifies the locale/TERM detection logic.
func TestDetectLogsUTF8(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		wantUTF bool
	}{
		{"utf8_via_lang", map[string]string{"LANG": "en_US.UTF-8"}, true},
		{"utf8_via_lc_all", map[string]string{"LC_ALL": "C.UTF-8"}, true},
		{"utf8_via_lc_ctype", map[string]string{"LC_CTYPE": "en_US.utf8"}, true},
		{"ascii_no_locale", map[string]string{}, false},
		{"ascii_c_locale", map[string]string{"LANG": "C"}, false},
		{"ascii_dumb_term", map[string]string{"LANG": "en_US.UTF-8", "TERM": "dumb"}, false},
		{"utf8_non_dumb_term", map[string]string{"LANG": "en_US.UTF-8", "TERM": "xterm-256color"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withTestEnv(t, tc.env)
			got := detectLogsUTF8()
			if got != tc.wantUTF {
				t.Errorf("detectLogsUTF8() = %v, want %v (env=%v)", got, tc.wantUTF, tc.env)
			}
		})
	}
}

// TestAgentGlyphFor verifies glyph selection for each agent in UTF-8 and ASCII modes.
func TestAgentGlyphFor(t *testing.T) {
	cases := []struct {
		agent      string
		wantUTF8   string
		wantASCII  string
		wantColor  bool // agent has a distinct non-empty color
	}{
		{"claude",      "✳", "*", true},
		{"claude-code", "✳", "*", true},
		{"cursor",      "▸", ">", true},
		{"codex",       "◆", "#", true},
		{"try",         "*", "*", true},
		{"unknown",     "·", ".", false},
		{"",            "·", ".", false}, // empty → unknown fallback
	}
	for _, tc := range cases {
		t.Run(tc.agent, func(t *testing.T) {
			gotUTF8 := agentGlyphFor(tc.agent, true)
			if gotUTF8 != tc.wantUTF8 {
				t.Errorf("agentGlyphFor(%q, true) = %q, want %q", tc.agent, gotUTF8, tc.wantUTF8)
			}
			gotASCII := agentGlyphFor(tc.agent, false)
			if gotASCII != tc.wantASCII {
				t.Errorf("agentGlyphFor(%q, false) = %q, want %q", tc.agent, gotASCII, tc.wantASCII)
			}
			gotColor := agentColorFor(tc.agent)
			if tc.wantColor && gotColor == "" {
				t.Errorf("agentColorFor(%q) = empty, want a non-empty color", tc.agent)
			}
			if !tc.wantColor && gotColor != "" {
				t.Errorf("agentColorFor(%q) = %q, want empty for unknown", tc.agent, gotColor)
			}
		})
	}
}

// TestSourceCellGlyphAlignment verifies that the rendered SOURCE cell in a
// data row has exactly sourceWidth visible columns across all agent types.
// It also checks that no-color mode emits the bare glyph without ANSI escapes.
func TestSourceCellGlyphAlignment(t *testing.T) {
	ts, _ := time.Parse(time.RFC3339Nano, "2026-06-02T10:00:00.000000-07:00")

	agents := []struct {
		agent     string
		sessionID string
		cwd       string
	}{
		{"claude",  "abc123xyz456", "/home/user/project"},
		{"codex",   "xyz789abc012", "/home/user/projects/bigapp"},
		{"cursor",  "cur123def456", ""},
		{"try",     "agentjail-try", ""},
		{"",        "sess-legacy01", ""}, // legacy / unknown
	}

	for _, ag := range agents {
		for _, useColor := range []bool{true, false} {
			name := ag.agent
			if name == "" {
				name = "legacy"
			}
			if useColor {
				name += "_color"
			} else {
				name += "_nocolor"
			}

			t.Run(name, func(t *testing.T) {
				// Force UTF-8 mode for reliable glyph selection.
				withTestEnv(t, map[string]string{"LANG": "en_US.UTF-8"})

				line := evalLine{
					Time:      ts,
					Level:     "INFO",
					Msg:       "eval",
					Agent:     ag.agent,
					SessionID: ag.sessionID,
					CWD:       ag.cwd,
					Tool:      "Bash",
					Action:    "allow",
					RuleID:    "r",
					ElapsedUs: 100,
				}
				opts := logsOpts{useColor: useColor}
				out := captureStdout(t, func() {
					_ = renderEvalLine(line, opts, nil)
				})

				// Extract the SOURCE cell: it's the second whitespace-separated
				// field in the output line. But since the cell contains spaces
				// we can't just split on whitespace. Instead we use the known
				// position: TIME(8) + "  " + SOURCE(sourceWidth).
				//
				// After stripping ANSI from out, the first 8 chars are TIME,
				// then 2 spaces, then sourceWidth chars of SOURCE.
				plain := stripANSI(out)
				const timeLen = 8
				const sep = 2
				if len([]rune(plain)) < timeLen+sep+sourceWidth {
					t.Fatalf("output too short to extract SOURCE: %q", plain)
				}
				runes := []rune(plain)
				sourceCell := string(runes[timeLen+sep : timeLen+sep+sourceWidth])
				got := len([]rune(sourceCell))
				if got != sourceWidth {
					t.Errorf("SOURCE visible width = %d, want %d\ncell: %q\nfull: %q",
						got, sourceWidth, sourceCell, plain)
				}

				// No-color: must not contain ANSI escapes.
				if !useColor && strings.Contains(out, "\033[") {
					t.Errorf("no-color output contains ANSI escape: %q", out)
				}
			})
		}
	}
}

// TestGlyphAppearsInColorOutput verifies that in color+UTF-8 mode each agent's
// expected glyph and brand color escape appear in the rendered SOURCE.
func TestGlyphAppearsInColorOutput(t *testing.T) {
	ts, _ := time.Parse(time.RFC3339Nano, "2026-06-02T10:00:00.000000-07:00")

	cases := []struct {
		agent        string
		sessionID    string
		wantGlyph    string
		wantColor    string // ANSI color constant that must appear in output
	}{
		{"claude",  "abc123xyz", "✳", ansiColorClaude},
		{"codex",   "xyz789abc", "◆", ansiColorCodex},
		{"cursor",  "cur123xyz", "▸", ansiColorCursor},
		{"try",     "agentjail-try", "*", ansiColorTry},
	}

	for _, tc := range cases {
		t.Run(tc.agent, func(t *testing.T) {
			withTestEnv(t, map[string]string{"LANG": "en_US.UTF-8"})
			line := evalLine{
				Time:      ts,
				Level:     "INFO",
				Msg:       "eval",
				Agent:     tc.agent,
				SessionID: tc.sessionID,
				Tool:      "Bash",
				Action:    "allow",
				RuleID:    "r",
				ElapsedUs: 100,
			}
			opts := logsOpts{useColor: true}
			out := captureStdout(t, func() {
				_ = renderEvalLine(line, opts, nil)
			})
			if !strings.Contains(out, tc.wantGlyph) {
				t.Errorf("glyph %q not found in output: %q", tc.wantGlyph, out)
			}
			if !strings.Contains(out, tc.wantColor) {
				t.Errorf("color escape %q not found in output: %q", tc.wantColor, out)
			}
		})
	}
}

// TestGlyphASCIIFallback verifies that when UTF-8 is not available, the ASCII
// fallback glyph is used and no multi-byte UTF-8 glyph characters appear.
func TestGlyphASCIIFallback(t *testing.T) {
	ts, _ := time.Parse(time.RFC3339Nano, "2026-06-02T10:00:00.000000-07:00")

	// Force ASCII mode: no UTF-8 locale.
	withTestEnv(t, map[string]string{"LANG": "C"})

	cases := []struct {
		agent     string
		sessionID string
		wantGlyph string // ASCII fallback glyph
		wantNot   string // UTF-8 glyph that must NOT appear
	}{
		{"claude", "abc123", "*", "✳"},
		{"codex",  "xyz789", "#", "◆"},
		{"cursor", "cur123", ">", "▸"},
	}
	for _, tc := range cases {
		t.Run(tc.agent, func(t *testing.T) {
			line := evalLine{
				Time:      ts,
				Level:     "INFO",
				Msg:       "eval",
				Agent:     tc.agent,
				SessionID: tc.sessionID,
				Tool:      "Bash",
				Action:    "allow",
				RuleID:    "r",
				ElapsedUs: 100,
			}
			opts := logsOpts{useColor: true}
			out := captureStdout(t, func() {
				_ = renderEvalLine(line, opts, nil)
			})
			if !strings.Contains(out, tc.wantGlyph) {
				t.Errorf("ASCII glyph %q not in output: %q", tc.wantGlyph, out)
			}
			if strings.Contains(out, tc.wantNot) {
				t.Errorf("UTF-8 glyph %q should not appear in ASCII mode: %q", tc.wantNot, out)
			}
		})
	}
}

// TestUnknownAgentGlyph verifies that a legacy/unknown agent renders the "·"
// (or "." in ASCII) glyph dimly, not a brand color.
func TestUnknownAgentGlyph(t *testing.T) {
	ts, _ := time.Parse(time.RFC3339Nano, "2026-06-02T10:00:00.000000-07:00")
	withTestEnv(t, map[string]string{"LANG": "en_US.UTF-8"})

	line := evalLine{
		Time: ts, Level: "INFO", Msg: "eval",
		// Agent intentionally empty → unknown.
		SessionID: "sess-abc", Tool: "Bash", Action: "allow", RuleID: "r", ElapsedUs: 50,
	}
	opts := logsOpts{useColor: true}
	out := captureStdout(t, func() {
		_ = renderEvalLine(line, opts, nil)
	})
	if !strings.Contains(out, "·") {
		t.Errorf("unknown glyph '·' not in output: %q", out)
	}
	// Should not contain any of the brand-color escapes.
	for _, c := range []string{ansiColorClaude, ansiColorCodex, ansiColorCursor, ansiColorTry} {
		if strings.Contains(out, c) {
			t.Errorf("brand color %q should not appear for unknown agent: %q", c, out)
		}
	}
}

// TestPadRight verifies the padRight helper.
func TestPadRight(t *testing.T) {
	cases := []struct {
		s     string
		width int
		want  string
	}{
		{"hello", 10, "hello     "},
		{"hello", 5, "hello"},
		{"hi", 3, "hi "},
		{"toolong!", 5, "tool…"},
	}
	for _, tc := range cases {
		got := padRight(tc.s, tc.width)
		if got != tc.want {
			t.Errorf("padRight(%q, %d) = %q, want %q", tc.s, tc.width, got, tc.want)
		}
	}
}

// captureStdout redirects os.Stdout to a pipe, runs f, then returns the
// collected output as a string.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("captureStdout: pipe: %v", err)
	}
	old := os.Stdout
	os.Stdout = w

	f()

	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatalf("captureStdout: read: %v", err)
	}
	return buf.String()
}
