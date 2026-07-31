package policyeval

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/agentpolicy/policy"
)

type capturingEngine struct {
	input policy.HookInput
}

func (e *capturingEngine) Eval(_ context.Context, input policy.HookInput) (policy.Decision, error) {
	e.input = input
	return policy.Decision{Action: "allow", RuleID: "test/capture"}, nil
}

func TestEvalInjectsParsedCommandIntents(t *testing.T) {
	engine := &capturingEngine{}
	evaluator := New(engine, policy.NewLRUCache(8), nil, nil)
	_, err := evaluator.Eval(context.Background(), Request{
		HookEvent: "PreToolUse",
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{
			"command": "git -C /tmp/work -c color.ui=false push origin topic",
		},
		SessionID: "test",
		CWD:       t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	want := []policy.CommandIntent{"git-push"}
	if !reflect.DeepEqual(engine.input.CommandIntents, want) {
		t.Fatalf("CommandIntents = %v, want %v", engine.input.CommandIntents, want)
	}
}

func TestEvalDoesNotClassifyTextOnlyCommandArguments(t *testing.T) {
	engine := &capturingEngine{}
	evaluator := New(engine, policy.NewLRUCache(8), nil, nil)
	_, err := evaluator.Eval(context.Background(), Request{
		HookEvent: "PreToolUse",
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{
			"command": `rg -n "git push" README.md`,
		},
		SessionID: "test",
		CWD:       t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if len(engine.input.CommandIntents) != 0 {
		t.Fatalf("CommandIntents = %v, want none", engine.input.CommandIntents)
	}
}

// ---------------------------------------------------------------------------
// NormalizeToolInput
// ---------------------------------------------------------------------------

func TestNormalizeToolInput_NilInput(t *testing.T) {
	if got := NormalizeToolInput(nil, "/tmp"); got != nil {
		t.Errorf("NormalizeToolInput(nil, ...) = %v, want nil", got)
	}
}

func TestNormalizeToolInput_CanonicalizesFilePath(t *testing.T) {
	cwd := "/home/user/project"
	input := map[string]interface{}{
		"file_path": "src/main.go",
	}
	out := NormalizeToolInput(input, cwd)
	fp, ok := out["file_path"].(string)
	if !ok {
		t.Fatal("file_path missing from output")
	}
	// Should be absolute and under cwd.
	if !strings.HasPrefix(fp, "/") {
		t.Errorf("expected absolute path, got %q", fp)
	}
	if !strings.Contains(fp, "src/main.go") {
		t.Errorf("expected path to contain src/main.go, got %q", fp)
	}
}

func TestNormalizeToolInput_ExpandsCommand(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("no home directory available")
	}

	input := map[string]interface{}{
		"command": "cat ~/.aws/credentials",
	}
	out := NormalizeToolInput(input, "/tmp")
	cmd, ok := out["command"].(string)
	if !ok {
		t.Fatal("command field missing from normalized output")
	}
	if strings.Contains(cmd, "~") {
		t.Errorf("NormalizeToolInput should expand ~ in command, got %q", cmd)
	}
	want := "cat " + home + "/.aws/credentials"
	if cmd != want {
		t.Errorf("got %q, want %q", cmd, want)
	}
}

func TestNormalizeToolInput_PreservesOtherFields(t *testing.T) {
	input := map[string]interface{}{
		"command": "git status",
		"extra":   42,
	}
	out := NormalizeToolInput(input, "/tmp")
	if out["extra"] != 42 {
		t.Errorf("extra field not preserved: got %v", out["extra"])
	}
}

func TestNormalizeToolCall_ApplyPatchUsesEditPolicyContract(t *testing.T) {
	cwd := CanonicalizeCWD(t.TempDir())
	toolName, input := NormalizeToolCall("apply_patch", map[string]interface{}{
		"command": "*** Begin Patch\n*** Update File: internal/main.go\n*** Add File: testdata/new.txt\n*** End Patch",
	}, cwd)
	if toolName != "Edit" {
		t.Errorf("tool name = %q, want Edit", toolName)
	}
	paths, ok := input["file_paths"].([]string)
	if !ok {
		t.Fatalf("file_paths = %#v, want []string", input["file_paths"])
	}
	if len(paths) != 2 {
		t.Fatalf("file_paths = %v, want two paths", paths)
	}
	for _, path := range paths {
		if !strings.HasPrefix(path, cwd+string(os.PathSeparator)) {
			t.Errorf("path %q is not canonicalized beneath %q", path, cwd)
		}
	}
}

func TestExtractPatchPaths(t *testing.T) {
	patch := "*** Begin Patch\n*** Add File: added.txt\n*** Update File: changed.txt\n*** Move to: moved.txt\n*** Delete File: removed.txt\n*** Update File: changed.txt\n*** End Patch"
	got := ExtractPatchPaths(patch)
	want := []string{"added.txt", "changed.txt", "moved.txt", "removed.txt"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ExtractPatchPaths() = %v, want %v", got, want)
	}
}

func TestNormalizeToolCall_PreservesNonPatchTool(t *testing.T) {
	toolName, input := NormalizeToolCall("Bash", map[string]interface{}{"command": "git status"}, "/tmp")
	if toolName != "Bash" {
		t.Errorf("tool name = %q, want Bash", toolName)
	}
	if input["command"] != "git status" {
		t.Errorf("command = %#v, want git status", input["command"])
	}
}

// ---------------------------------------------------------------------------
// SummarizeToolInput
// ---------------------------------------------------------------------------

func TestSummarizeToolInput_Bash(t *testing.T) {
	in := map[string]interface{}{"command": "ls -la /tmp"}
	got := SummarizeToolInput("Bash", in)
	if got != "ls -la /tmp" {
		t.Errorf("SummarizeToolInput(Bash) = %q, want %q", got, "ls -la /tmp")
	}
}

func TestSummarizeToolInput_FileTools(t *testing.T) {
	in := map[string]interface{}{"file_path": "/home/user/foo.go"}
	got := SummarizeToolInput("Read", in)
	if got != "/home/user/foo.go" {
		t.Errorf("SummarizeToolInput(Read) = %q, want %q", got, "/home/user/foo.go")
	}
}

func TestSummarizeToolInput_Nil(t *testing.T) {
	got := SummarizeToolInput("Bash", nil)
	if got != "" {
		t.Errorf("SummarizeToolInput(nil) = %q, want empty", got)
	}
}

func TestSummarizeToolInput_Truncation(t *testing.T) {
	long := strings.Repeat("x", 300)
	in := map[string]interface{}{"command": long}
	got := SummarizeToolInput("Bash", in)
	// The truncation cuts at maxLen-1 bytes (199) then appends "..." (3-byte UTF-8),
	// so the result is 202 bytes but 200 runes. Verify it's reasonably bounded.
	if len(got) > 210 {
		t.Errorf("expected truncation near 200, got len=%d", len(got))
	}
	if len(got) >= 300 {
		t.Errorf("output was not truncated at all, got len=%d", len(got))
	}
}

func TestSummarizeToolInput_NewlineCollapse(t *testing.T) {
	in := map[string]interface{}{"command": "echo\nhello\rworld"}
	got := SummarizeToolInput("Bash", in)
	if strings.ContainsAny(got, "\n\r") {
		t.Errorf("newlines should be collapsed, got %q", got)
	}
}

func TestSummarizeToolInput_MCP(t *testing.T) {
	in := map[string]interface{}{"url": "https://example.com/api"}
	got := SummarizeToolInput("mcp__server__tool", in)
	if got != "https://example.com/api" {
		t.Errorf("SummarizeToolInput(MCP) = %q, want URL", got)
	}
}

// ---------------------------------------------------------------------------
// HookCacheKey
// ---------------------------------------------------------------------------

func TestHookCacheKey_SessionIDExcluded(t *testing.T) {
	a := policy.HookInput{
		HookEvent: "PreToolUse",
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "ls -la"},
		SessionID: "session-1",
		CWD:       "/home/user/project",
	}
	b := a
	b.SessionID = "session-999"

	if HookCacheKey(a) != HookCacheKey(b) {
		t.Error("cache keys should be equal when only SessionID differs")
	}
}

func TestHookCacheKey_CWDIncluded(t *testing.T) {
	a := policy.HookInput{
		HookEvent: "PreToolUse",
		ToolName:  "Write",
		ToolInput: map[string]interface{}{"file_path": "/Users/u/proj/secrets.yaml"},
		SessionID: "s1",
		CWD:       "/Users/u/proj",
	}
	b := a
	b.CWD = "/Users/u/other"

	if HookCacheKey(a) == HookCacheKey(b) {
		t.Error("cache keys should differ when CWD differs")
	}
}

func TestHookCacheKey_DifferentInput(t *testing.T) {
	a := policy.HookInput{
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "ls -la"},
		CWD:       "/proj",
	}
	b := a
	b.ToolInput = map[string]interface{}{"command": "ls -la /etc"}

	if HookCacheKey(a) == HookCacheKey(b) {
		t.Error("different ToolInput should produce different cache keys")
	}
}

func TestHookCacheKey_SameCWDSameKey(t *testing.T) {
	a := policy.HookInput{
		ToolName:  "Write",
		ToolInput: map[string]interface{}{"file_path": "/tmp/foo.txt"},
		SessionID: "session-1",
		CWD:       "/proj",
	}
	b := a
	b.SessionID = "session-999"

	if HookCacheKey(a) != HookCacheKey(b) {
		t.Error("cache keys should be equal for same static fields + same cwd but different session IDs")
	}
}

// ---------------------------------------------------------------------------
// ParseAWSConfig
// ---------------------------------------------------------------------------

func TestParseAWSConfig(t *testing.T) {
	content := `
[default]
region = us-east-1
role_arn = arn:aws:iam::000000000000:role/default-role

[profile prod]
role_arn = arn:aws:iam::123456789012:role/MyRole
source_profile = default

[profile dev]
sso_account_id = 111122223333

[profile chained]
source_profile = prod

[profile cyclical]
source_profile = cyclical

# a comment
[profile empty]
region = us-west-2

[sso-session my-sso]
sso_start_url = https://example.com/start
`
	profiles := ParseAWSConfig(content)
	if len(profiles) != 6 {
		t.Fatalf("parsed %d profiles, want 6: %+v", len(profiles), profiles)
	}
	if profiles["default"].roleARN != "arn:aws:iam::000000000000:role/default-role" {
		t.Errorf("default role_arn = %q", profiles["default"].roleARN)
	}
	if profiles["prod"].roleARN != "arn:aws:iam::123456789012:role/MyRole" {
		t.Errorf("prod role_arn = %q", profiles["prod"].roleARN)
	}
	if profiles["prod"].sourceProfile != "default" {
		t.Errorf("prod source_profile = %q", profiles["prod"].sourceProfile)
	}
	if profiles["dev"].ssoAccountID != "111122223333" {
		t.Errorf("dev sso_account_id = %q", profiles["dev"].ssoAccountID)
	}
	if _, ok := profiles["my-sso"]; ok {
		t.Error("sso-session section must not be parsed as a profile")
	}
}

func TestParseAWSConfig_Empty(t *testing.T) {
	profiles := ParseAWSConfig("")
	if len(profiles) != 0 {
		t.Errorf("expected 0 profiles from empty config, got %d", len(profiles))
	}
}

// ---------------------------------------------------------------------------
// AWS helpers
// ---------------------------------------------------------------------------

func TestIsAWSCLICommand(t *testing.T) {
	cases := []struct {
		cmd  string
		want bool
	}{
		{"aws s3 ls", true},
		{"aws s3 rb --force my-bucket --profile prod", true},
		{"AWS_ACCESS_KEY_ID=x aws s3 ls", true},
		{"echo aws s3 ls", true},
		{"git status", false},
		{"ls -la", false},
		{"", false},
		{"awsome tool", false},
	}
	for _, c := range cases {
		if got := IsAWSCLICommand(c.cmd); got != c.want {
			t.Errorf("IsAWSCLICommand(%q) = %v, want %v", c.cmd, got, c.want)
		}
	}
}

func TestExtractAWSProfile(t *testing.T) {
	cases := []struct {
		cmd  string
		want string
	}{
		{"aws s3 ls --profile prod", "prod"},
		{"aws s3 ls --profile=prod", "prod"},
		{"aws s3 ls", "default"},
		{"aws s3 ls --profile dev --region us-east-1", "dev"},
	}
	for _, c := range cases {
		if got := ExtractAWSProfile(c.cmd); got != c.want {
			t.Errorf("ExtractAWSProfile(%q) = %q, want %q", c.cmd, got, c.want)
		}
	}
}

func TestAccountFromRoleARN(t *testing.T) {
	cases := []struct {
		arn  string
		want string
	}{
		{"arn:aws:iam::123456789012:role/MyRole", "123456789012"},
		{"arn:aws-cn:iam::123456789012:role/MyRole", "123456789012"},
		{"arn:aws:s3:::my-bucket", ""},
		{"not-an-arn", ""},
	}
	for _, c := range cases {
		if got := AccountFromRoleARN(c.arn); got != c.want {
			t.Errorf("AccountFromRoleARN(%q) = %q, want %q", c.arn, got, c.want)
		}
	}
}

func TestAccountForProfile(t *testing.T) {
	profiles := ParseAWSConfig(`
[default]
role_arn = arn:aws:iam::000000000000:role/default-role

[profile prod]
role_arn = arn:aws:iam::123456789012:role/MyRole
source_profile = default

[profile dev]
sso_account_id = 111122223333

[profile chained]
source_profile = prod

[profile cyclical]
source_profile = cyclical
`)
	cases := []struct {
		profile string
		want    string
	}{
		{"prod", "123456789012"},
		{"dev", "111122223333"},
		{"default", "000000000000"},
		{"chained", "123456789012"},
		{"cyclical", ""},
		{"nonexistent", ""},
	}
	for _, c := range cases {
		if got := AccountForProfile(profiles, c.profile, map[string]bool{}); got != c.want {
			t.Errorf("AccountForProfile(%q) = %q, want %q", c.profile, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// ExpandCommandPaths
// ---------------------------------------------------------------------------

func TestExpandCommandPaths(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("no home directory available")
	}

	tests := []struct {
		name string
		cmd  string
		want string
	}{
		{"tilde_slash_aws", "cat ~/.aws/credentials", "cat " + home + "/.aws/credentials"},
		{"tilde_slash_ssh", "cat ~/.ssh/id_rsa", "cat " + home + "/.ssh/id_rsa"},
		{"dollar_home_aws", "cat $HOME/.aws/credentials", "cat " + home + "/.aws/credentials"},
		{"multiple_tildes", "cat ~/.ssh/id_rsa ~/.aws/credentials", "cat " + home + "/.ssh/id_rsa " + home + "/.aws/credentials"},
		{"no_expansion_needed", "git status", "git status"},
		{"tilde_not_at_word_boundary", "echo ~other/foo", "echo ~other/foo"},
		{"bare_tilde_eol", "echo ~", "echo " + home},
		{"bare_tilde_space", "cd ~ && ls", "cd " + home + " && ls"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExpandCommandPaths(tt.cmd)
			if got != tt.want {
				t.Errorf("ExpandCommandPaths(%q)\n  got  %q\n  want %q", tt.cmd, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CanonicalizePath
// ---------------------------------------------------------------------------

func TestCanonicalizePath_Empty(t *testing.T) {
	canonical, failClose := CanonicalizePath("", "/tmp")
	if failClose {
		t.Error("expected no fail-close for empty path")
	}
	if canonical != "" {
		t.Errorf("expected empty canonical, got %q", canonical)
	}
}

func TestCanonicalizePath_RelativeSafe(t *testing.T) {
	cwd := "/home/user/proj"
	canonical, failClose := CanonicalizePath("src/foo.go", cwd)
	if failClose {
		t.Fatal("expected no fail-close for a simple relative path")
	}
	want := "/home/user/proj/src/foo.go"
	if !strings.HasSuffix(canonical, "src/foo.go") {
		t.Errorf("expected path ending with src/foo.go, got %q", canonical)
	}
	_ = want
}

func TestCanonicalizePath_AbsoluteUnchanged(t *testing.T) {
	// An absolute path to a known existing directory should resolve.
	canonical, failClose := CanonicalizePath("/tmp", "")
	if failClose {
		t.Fatal("expected no fail-close for /tmp")
	}
	if canonical == "" {
		t.Error("expected non-empty canonical for /tmp")
	}
}
