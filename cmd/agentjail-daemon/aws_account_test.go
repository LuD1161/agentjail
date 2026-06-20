package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestIsAWSCLICommand verifies the AWS CLI detection regex.
func TestIsAWSCLICommand(t *testing.T) {
	cases := []struct {
		cmd string
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
		if got := isAWSCLICommand(c.cmd); got != c.want {
			t.Errorf("isAWSCLICommand(%q) = %v, want %v", c.cmd, got, c.want)
		}
	}
}

// TestExtractAWSProfile verifies --profile extraction and "default" fallback.
func TestExtractAWSProfile(t *testing.T) {
	cases := []struct {
		cmd  string
		want string
	}{
		{"aws s3 ls --profile prod", "prod"},
		{"aws s3 ls --profile=prod", "prod"},
		{"aws s3 ls --profile \"my profile\"", "my"}, // \S+ stops at whitespace
		{"aws s3 ls", "default"},
		{"aws s3 ls --profile dev --region us-east-1", "dev"},
	}
	for _, c := range cases {
		if got := extractAWSProfile(c.cmd); got != c.want {
			t.Errorf("extractAWSProfile(%q) = %q, want %q", c.cmd, got, c.want)
		}
	}
}

// TestAccountFromRoleARN verifies IAM role ARN account extraction.
func TestAccountFromRoleARN(t *testing.T) {
	cases := []struct {
		arn  string
		want string
	}{
		{"arn:aws:iam::123456789012:role/MyRole", "123456789012"},
		{"arn:aws-cn:iam::123456789012:role/MyRole", "123456789012"},
		{"arn:aws:iam::111122223333:role/foo/bar", "111122223333"},
		{"arn:aws:s3:::my-bucket", ""},
		{"not-an-arn", ""},
	}
	for _, c := range cases {
		if got := accountFromRoleARN(c.arn); got != c.want {
			t.Errorf("accountFromRoleARN(%q) = %q, want %q", c.arn, got, c.want)
		}
	}
}

// TestParseAWSConfig verifies the ~/.aws/config parser.
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
	profiles := parseAWSConfig(content)
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

// TestAccountForProfile verifies resolution including source_profile chains
// and cycle protection.
func TestAccountForProfile(t *testing.T) {
	profiles := parseAWSConfig(`
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

[profile unknown-flags]
region = us-east-1
`)
	cases := []struct {
		profile string
		want    string
	}{
		{"prod", "123456789012"},
		{"dev", "111122223333"},
		{"default", "000000000000"},
		{"chained", "123456789012"}, // chained -> prod -> role_arn
		{"cyclical", ""},            // cycle -> ""
		{"unknown-flags", ""},       // no role_arn/sso/source -> ""
		{"nonexistent", ""},         // not in config -> ""
	}
	for _, c := range cases {
		if got := accountForProfile(profiles, c.profile, map[string]bool{}); got != c.want {
			t.Errorf("accountForProfile(%q) = %q, want %q", c.profile, got, c.want)
		}
	}
}

// TestResolveAWSAccountEndToEnd verifies the daemon resolves --profile to an
// account id via a temp AWS_CONFIG_FILE, and returns "" for unresolvable.
func TestResolveAWSAccountEndToEnd(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config")
	content := `
[profile prod]
role_arn = arn:aws:iam::123456789012:role/MyRole

[profile dev]
sso_account_id = 111122223333
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	t.Setenv("AWS_CONFIG_FILE", cfgPath)

	s := &server{}
	cases := []struct {
		cmd  string
		want string
	}{
		{"aws s3 rb --force my-bucket --profile prod", "123456789012"},
		{"aws s3 ls --profile=dev", "111122223333"},
		{"aws s3 ls --profile unknown", ""},
		{"aws s3 ls", ""}, // "default" profile not in config -> ""
		{"git status", ""}, // not an AWS command
	}
	for _, c := range cases {
		got := s.resolveAWSAccount(c.cmd)
		if got != c.want {
			t.Errorf("resolveAWSAccount(%q) = %q, want %q", c.cmd, got, c.want)
		}
	}
}

// TestResolveAWSAccountNoConfigFile verifies graceful "" when ~/.aws/config is
// absent (fail-safe: aws_policy/posture falls back to default_posture).
func TestResolveAWSAccountNoConfigFile(t *testing.T) {
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "nonexistent"))
	s := &server{}
	if got := s.resolveAWSAccount("aws s3 rb --force x --profile prod"); got != "" {
		t.Errorf("resolveAWSAccount with no config = %q, want \"\"", got)
	}
}
