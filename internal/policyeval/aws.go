package policyeval

import (
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// awsProfileInfo is the per-profile account-resolution data parsed from
// ~/.aws/config. The account id is derived from role_arn (the 12-digit IAM
// account in arn:aws:iam::<acct>:role/...) or sso_account_id. source_profile
// chains to another profile when the profile itself has no role_arn/sso_account_id.
type awsProfileInfo struct {
	roleARN       string
	ssoAccountID  string
	sourceProfile string
}

// reAWSCLI matches a Bash command that invokes the AWS CLI as the first
// significant token (allowing leading env-var assignments and whitespace).
var reAWSCLI = regexp.MustCompile(`(^|[\s;&|(])aws\s+\S+`)

// reAWSProfile captures the --profile argument value (--profile prod or
// --profile=prod). AWS accepts both space- and equals-separated forms.
var reAWSProfile = regexp.MustCompile(`--profile[ =](\S+)`)

// reAWSRoleARNAccount captures the 12-digit account id from an IAM role ARN.
var reAWSRoleARNAccount = regexp.MustCompile(`arn:aws[a-z-]*:iam::(\d+):`)

// IsAWSCLICommand reports whether cmd invokes the AWS CLI.
func IsAWSCLICommand(cmd string) bool {
	return reAWSCLI.MatchString(cmd)
}

// ExtractAWSProfile returns the --profile name from an AWS CLI command, or
// "default" when no --profile is given (the AWS CLI default profile).
func ExtractAWSProfile(cmd string) string {
	if m := reAWSProfile.FindStringSubmatch(cmd); len(m) == 2 {
		return strings.Trim(m[1], `"'`)
	}
	return "default"
}

// AccountFromRoleARN extracts the account id from an IAM role ARN, or "".
func AccountFromRoleARN(arn string) string {
	if m := reAWSRoleARNAccount.FindStringSubmatch(arn); len(m) == 2 {
		return m[1]
	}
	return ""
}

// AWSConfigPath returns the AWS config file path, honoring AWS_CONFIG_FILE
// and falling back to ~/.aws/config.
func AWSConfigPath() string {
	if p := os.Getenv("AWS_CONFIG_FILE"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".aws", "config")
}

// resolveAWSAccount resolves the AWS account id targeted by an AWS CLI command
// by extracting --profile and looking it up in ~/.aws/config.
func (e *evaluator) resolveAWSAccount(cmd string) string {
	profile := ExtractAWSProfile(cmd)
	if profile == "" {
		return ""
	}
	profiles := e.loadAWSProfiles()
	return AccountForProfile(profiles, profile, map[string]bool{})
}

// AccountForProfile resolves profile -> account, following source_profile
// chains (with a visited set to avoid cycles). Returns "" if unresolvable.
func AccountForProfile(profiles map[string]awsProfileInfo, profile string, visited map[string]bool) string {
	if visited[profile] {
		return ""
	}
	visited[profile] = true
	info, ok := profiles[profile]
	if !ok {
		return ""
	}
	if acct := AccountFromRoleARN(info.roleARN); acct != "" {
		return acct
	}
	if info.ssoAccountID != "" {
		return info.ssoAccountID
	}
	if info.sourceProfile != "" {
		return AccountForProfile(profiles, info.sourceProfile, visited)
	}
	return ""
}

// loadAWSProfiles returns the cached parsed ~/.aws/config, parsing it lazily
// on first call. Thread-safe; the cache is invalidated on Reload.
func (e *evaluator) loadAWSProfiles() map[string]awsProfileInfo {
	e.awsCfgMu.Lock()
	defer e.awsCfgMu.Unlock()
	if e.awsProfiles != nil {
		return e.awsProfiles
	}
	path := AWSConfigPath()
	if path == "" {
		e.awsProfiles = map[string]awsProfileInfo{}
		return e.awsProfiles
	}
	b, err := os.ReadFile(path)
	if err != nil {
		slog.Debug("aws config unreadable; AWS posture will use default_posture", "path", path, "err", err)
		e.awsProfiles = map[string]awsProfileInfo{}
		return e.awsProfiles
	}
	e.awsProfiles = ParseAWSConfig(string(b))
	return e.awsProfiles
}

// ParseAWSConfig parses an AWS config file (INI-like) into a profile->info map.
// Sections are [default] or [profile <name>]; keys are key = value. Comments
// (# or ;) and blank lines are ignored.
func ParseAWSConfig(content string) map[string]awsProfileInfo {
	profiles := map[string]awsProfileInfo{}
	current := ""
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inner := strings.TrimSpace(line[1 : len(line)-1])
			if inner == "default" {
				current = "default"
			} else if strings.HasPrefix(inner, "profile ") {
				current = strings.TrimSpace(inner[len("profile "):])
			} else {
				current = "" // non-profile section (e.g. sso-session), skip
			}
			continue
		}
		if current == "" {
			continue
		}
		key, val, ok := SplitAWSConfigKV(line)
		if !ok {
			continue
		}
		info := profiles[current]
		switch key {
		case "role_arn":
			info.roleARN = val
		case "sso_account_id":
			info.ssoAccountID = val
		case "source_profile":
			info.sourceProfile = val
		}
		profiles[current] = info
	}
	return profiles
}

// SplitAWSConfigKV splits a "key = value" (or "key=value") line, trimming the
// value of surrounding quotes/whitespace. Returns ok=false if no "=" present.
func SplitAWSConfigKV(line string) (key, val string, ok bool) {
	idx := strings.Index(line, "=")
	if idx < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:idx])
	val = strings.TrimSpace(line[idx+1:])
	val = strings.Trim(val, `"'`)
	return key, val, true
}
