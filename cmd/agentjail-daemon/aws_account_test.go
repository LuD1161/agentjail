package main

import (
	"testing"

	"github.com/LuD1161/agentjail/internal/policyeval"
)

// TestIsAWSCLICommand verifies the AWS CLI detection regex.
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
		if got := policyeval.IsAWSCLICommand(c.cmd); got != c.want {
			t.Errorf("IsAWSCLICommand(%q) = %v, want %v", c.cmd, got, c.want)
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
		if got := policyeval.ExtractAWSProfile(c.cmd); got != c.want {
			t.Errorf("ExtractAWSProfile(%q) = %q, want %q", c.cmd, got, c.want)
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
		if got := policyeval.AccountFromRoleARN(c.arn); got != c.want {
			t.Errorf("AccountFromRoleARN(%q) = %q, want %q", c.arn, got, c.want)
		}
	}
}

// TestAccountForProfile verifies resolution including source_profile chains
// and cycle protection via the exported helpers.
func TestAccountForProfile(t *testing.T) {
	profiles := policyeval.ParseAWSConfig(`
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
		if got := policyeval.AccountForProfile(profiles, c.profile, map[string]bool{}); got != c.want {
			t.Errorf("AccountForProfile(%q) = %q, want %q", c.profile, got, c.want)
		}
	}
}

// TestResolveAWSAccountEndToEnd verifies the profile+config compose correctly
// to resolve --profile to an account id.
func TestResolveAWSAccountEndToEnd(t *testing.T) {
	content := `
[profile prod]
role_arn = arn:aws:iam::123456789012:role/MyRole

[profile dev]
sso_account_id = 111122223333
`
	profiles := policyeval.ParseAWSConfig(content)
	cases := []struct {
		cmd  string
		want string
	}{
		{"aws s3 rb --force my-bucket --profile prod", "123456789012"},
		{"aws s3 ls --profile=dev", "111122223333"},
		{"aws s3 ls --profile unknown", ""},
		{"aws s3 ls", ""}, // "default" profile not in config -> ""
	}
	for _, c := range cases {
		profile := policyeval.ExtractAWSProfile(c.cmd)
		got := policyeval.AccountForProfile(profiles, profile, map[string]bool{})
		if got != c.want {
			t.Errorf("resolveAWSAccount(%q) = %q, want %q", c.cmd, got, c.want)
		}
	}
}

// TestResolveAWSAccountNoConfigFile verifies graceful "" when no config is
// available.
func TestResolveAWSAccountNoConfigFile(t *testing.T) {
	profiles := policyeval.ParseAWSConfig("")
	profile := policyeval.ExtractAWSProfile("aws s3 rb --force x --profile prod")
	if got := policyeval.AccountForProfile(profiles, profile, map[string]bool{}); got != "" {
		t.Errorf("resolveAWSAccount with no config = %q, want \"\"", got)
	}
}
