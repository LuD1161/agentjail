package shieldapp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/envaudit"
)

// TestCheckRoot_NonRoot verifies that no finding is added when not running as root.
func TestCheckRoot_NonRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test requires non-root; running as root")
	}
	result := &envaudit.AuditResult{Findings: []envaudit.Finding{}}
	envaudit.CheckRoot(result)
	for _, f := range result.Findings {
		if f.Check == "root" {
			t.Error("expected no root finding when not running as root")
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

	result := &envaudit.AuditResult{Findings: []envaudit.Finding{}}
	envaudit.CheckAmbientCredFiles(result)

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

// TestCheckAmbientCredFiles_NotPresent verifies no finding when files don't exist.
func TestCheckAmbientCredFiles_NotPresent(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	result := &envaudit.AuditResult{Findings: []envaudit.Finding{}}
	envaudit.CheckAmbientCredFiles(result)

	for _, f := range result.Findings {
		if f.Check == "ambient_cred_file" {
			t.Errorf("unexpected ambient_cred_file finding: %s", f.Message)
		}
	}
}

// TestCheckAmbientEnvVars_Detected verifies that set env vars are detected.
func TestCheckAmbientEnvVars_Detected(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret-key")
	t.Setenv("PGPASSWORD", "test-pg-pass")

	result := &envaudit.AuditResult{Findings: []envaudit.Finding{}}
	envaudit.CheckAmbientEnvVars(result)

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

	result := &envaudit.AuditResult{Findings: []envaudit.Finding{}}
	envaudit.CheckAmbientEnvVars(result)

	for _, f := range result.Findings {
		if f.Check == "ambient_env_var" {
			t.Errorf("unexpected ambient_env_var finding: %s", f.Message)
		}
	}
}

// TestHasCriticalFindings verifies the critical finding detection.
func TestHasCriticalFindings(t *testing.T) {
	tests := []struct {
		name     string
		findings []envaudit.Finding
		want     bool
	}{
		{
			name:     "no findings",
			findings: []envaudit.Finding{},
			want:     false,
		},
		{
			name: "only warnings",
			findings: []envaudit.Finding{
				{Severity: envaudit.SeverityWarning, Check: "test", Message: "warning"},
			},
			want: false,
		},
		{
			name: "has critical",
			findings: []envaudit.Finding{
				{Severity: envaudit.SeverityWarning, Check: "test", Message: "warning"},
				{Severity: envaudit.SeverityCritical, Check: "root", Message: "running as root"},
			},
			want: true,
		},
		{
			name: "only info",
			findings: []envaudit.Finding{
				{Severity: envaudit.SeverityInfo, Check: "test", Message: "info"},
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := &envaudit.AuditResult{Findings: tc.findings}
			got := envaudit.HasCriticalFindings(result)
			if got != tc.want {
				t.Errorf("hasCriticalFindings = %v; want %v", got, tc.want)
			}
		})
	}
}

// TestPrintAuditWarnings verifies that warnings are printed to stderr.
func TestPrintAuditWarnings(t *testing.T) {
	result := &envaudit.AuditResult{
		Findings: []envaudit.Finding{
			{Severity: envaudit.SeverityCritical, Check: "root", Message: "running as root", Detail: "should be non-root"},
			{Severity: envaudit.SeverityWarning, Check: "ambient_env_var", Message: "AWS_SECRET_ACCESS_KEY is set"},
			{Severity: envaudit.SeverityInfo, Check: "iam_role", Message: "instance role: dev-role"},
		},
	}

	// Capture stderr by redirecting os.Stderr.
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	printAuditWarnings(result)
	w.Close()
	os.Stderr = oldStderr

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if !strings.Contains(output, "CRITICAL") {
		t.Error("expected CRITICAL in output")
	}
	if !strings.Contains(output, "WARNING") {
		t.Error("expected WARNING in output")
	}
	if !strings.Contains(output, "INFO") {
		t.Error("expected INFO in output")
	}
	if !strings.Contains(output, "running as root") {
		t.Error("expected 'running as root' in output")
	}
}

// TestWriteAuditJSON verifies JSON output to a file.
func TestWriteAuditJSON(t *testing.T) {
	result := &envaudit.AuditResult{
		Findings: []envaudit.Finding{
			{Severity: envaudit.SeverityCritical, Check: "root", Message: "running as root"},
		},
		IsEC2: true,
	}

	path := filepath.Join(t.TempDir(), "audit.json")
	if err := writeAuditJSON(result, path); err != nil {
		t.Fatalf("writeAuditJSON: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var parsed envaudit.AuditResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(parsed.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(parsed.Findings))
	}
	if parsed.Findings[0].Check != "root" {
		t.Errorf("expected check 'root', got %q", parsed.Findings[0].Check)
	}
	if !parsed.IsEC2 {
		t.Error("expected IsEC2=true")
	}
}

// TestWriteAuditJSON_Stdout verifies JSON output to stdout.
func TestWriteAuditJSON_Stdout(t *testing.T) {
	result := &envaudit.AuditResult{
		Findings: []envaudit.Finding{
			{Severity: envaudit.SeverityInfo, Check: "test", Message: "hello"},
		},
	}

	// Capture stdout.
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := writeAuditJSON(result, "-")
	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("writeAuditJSON: %v", err)
	}

	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(r)
	var parsed envaudit.AuditResult
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(parsed.Findings) != 1 || parsed.Findings[0].Message != "hello" {
		t.Errorf("unexpected output: %s", buf.String())
	}
}

// TestRunAudit verifies that RunAudit returns a result with the expected checks.
func TestRunAudit(t *testing.T) {
	// Set an env var to trigger a finding.
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret")

	result := envaudit.RunAudit()
	if result == nil {
		t.Fatal("RunAudit returned nil")
	}
	if len(result.Findings) == 0 {
		t.Skip("no findings (not root, no cred files, not on EC2) — test environment is clean")
	}

	// At least the ambient_env_var finding should be present.
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

// TestCheckIMDS_NotEC2 verifies that IMDS checks are skipped when not on EC2.
func TestCheckIMDS_NotEC2(t *testing.T) {
	result := &envaudit.AuditResult{Findings: []envaudit.Finding{}}
	envaudit.CheckIMDS(result)

	for _, f := range result.Findings {
		if f.Check == "imds_version" {
			t.Skipf("IMDS responded — appears to be on EC2. Finding: %s", f.Message)
		}
	}
}

// TestFindingSeverity verifies that severity constants are correct.
func TestFindingSeverity(t *testing.T) {
	if envaudit.SeverityCritical != "critical" {
		t.Errorf("SeverityCritical = %q; want 'critical'", envaudit.SeverityCritical)
	}
	if envaudit.SeverityWarning != "warning" {
		t.Errorf("SeverityWarning = %q; want 'warning'", envaudit.SeverityWarning)
	}
	if envaudit.SeverityInfo != "info" {
		t.Errorf("SeverityInfo = %q; want 'info'", envaudit.SeverityInfo)
	}
}
