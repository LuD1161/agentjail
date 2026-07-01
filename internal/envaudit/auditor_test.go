package envaudit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCheckRoot_NonRoot verifies that no finding is added when not running as root.
func TestCheckRoot_NonRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test requires non-root; running as root")
	}
	result := &AuditResult{Findings: []Finding{}}
	CheckRoot(result)
	for _, f := range result.Findings {
		if f.Check == "root" {
			t.Error("expected no root finding when not running as root")
		}
	}
}

// TestCheckAmbientEnvVars_Detected verifies that set env vars are detected.
func TestCheckAmbientEnvVars_Detected(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret-key")
	t.Setenv("PGPASSWORD", "test-pg-pass")

	result := &AuditResult{Findings: []Finding{}}
	CheckAmbientEnvVars(result)

	foundAWS := false
	foundPG := false
	for _, f := range result.Findings {
		if f.Check == "ambient_env_var" {
			if strings.Contains(f.Message, "AWS_SECRET_ACCESS_KEY") {
				foundAWS = true
			}
			if strings.Contains(f.Message, "PGPASSWORD") {
				foundPG = true
			}
		}
	}
	if !foundAWS {
		t.Error("expected finding for AWS_SECRET_ACCESS_KEY")
	}
	if !foundPG {
		t.Error("expected finding for PGPASSWORD")
	}
}

// TestCheckAmbientEnvVars_NotSet verifies no finding when env vars are not set.
func TestCheckAmbientEnvVars_NotSet(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("PGPASSWORD", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("AWS_SESSION_TOKEN", "")

	result := &AuditResult{Findings: []Finding{}}
	CheckAmbientEnvVars(result)

	for _, f := range result.Findings {
		if f.Check == "ambient_env_var" {
			t.Errorf("unexpected ambient_env_var finding: %s", f.Message)
		}
	}
}

// TestCheckAmbientCredFiles_Detected verifies that a readable credentials file is detected.
func TestCheckAmbientCredFiles_Detected(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	awsDir := filepath.Join(tmpHome, ".aws")
	if err := os.MkdirAll(awsDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	credFile := filepath.Join(awsDir, "credentials")
	if err := os.WriteFile(credFile, []byte("[default]\naws_access_key_id = AKIA..."), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	result := &AuditResult{Findings: []Finding{}}
	CheckAmbientCredFiles(result)

	found := false
	for _, f := range result.Findings {
		if f.Check == "ambient_cred_file" && strings.Contains(f.Message, "credentials") {
			found = true
		}
	}
	if !found {
		t.Error("expected ambient_cred_file finding for ~/.aws/credentials")
	}
}

// TestHasCriticalFindings verifies the critical finding detection.
func TestHasCriticalFindings(t *testing.T) {
	tests := []struct {
		name     string
		findings []Finding
		want     bool
	}{
		{
			name:     "no findings",
			findings: []Finding{},
			want:     false,
		},
		{
			name: "only warnings",
			findings: []Finding{
				{Severity: SeverityWarning, Check: "test", Message: "warning"},
			},
			want: false,
		},
		{
			name: "has critical",
			findings: []Finding{
				{Severity: SeverityWarning, Check: "test", Message: "warning"},
				{Severity: SeverityCritical, Check: "root", Message: "running as root"},
			},
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := &AuditResult{Findings: tc.findings}
			got := HasCriticalFindings(result)
			if got != tc.want {
				t.Errorf("HasCriticalFindings = %v; want %v", got, tc.want)
			}
		})
	}
}

// TestRunAudit verifies that RunAudit returns a non-nil result.
func TestRunAudit(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret")

	result := RunAudit()
	if result == nil {
		t.Fatal("RunAudit returned nil")
	}

	foundEnvVar := false
	for _, f := range result.Findings {
		if f.Check == "ambient_env_var" {
			foundEnvVar = true
		}
	}
	if !foundEnvVar {
		t.Error("expected ambient_env_var finding when AWS_SECRET_ACCESS_KEY is set")
	}
}
