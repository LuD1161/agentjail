// Package main is agentjail-shield. This file contains the environment audit
// that checks for over-permissive configuration before launching the agent.
//
// The audit is best-effort and non-blocking: warnings are printed to stderr,
// and the agent is still launched (unless --audit-strict is set and critical
// findings are detected).
//
// Checks:
//   - Root: warn if running as root (uid 0)
//   - Ambient cred files: warn if ~/.aws/credentials exists and is readable
//   - Ambient env vars: warn if AWS_SECRET_ACCESS_KEY is set (pre-stripping)
//   - IMDS version: warn if IMDSv1 is enabled (should be IMDSv2)
//   - IAM role breadth: warn if the instance role name suggests AdministratorAccess

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FindingSeverity classifies an audit finding.
type FindingSeverity string

const (
	SeverityCritical FindingSeverity = "critical"
	SeverityWarning  FindingSeverity = "warning"
	SeverityInfo     FindingSeverity = "info"
)

// Finding represents a single audit check result.
type Finding struct {
	Severity FindingSeverity `json:"severity"`
	Check    string          `json:"check"`
	Message  string          `json:"message"`
	Detail   string          `json:"detail,omitempty"`
}

// AuditResult is the full audit output.
type AuditResult struct {
	Findings []Finding `json:"findings"`
	IsEC2    bool      `json:"is_ec2"`
}

// runAudit performs environment checks and returns the findings.
// All checks are best-effort: failures in individual checks do not
// abort the audit.
func runAudit() *AuditResult {
	result := &AuditResult{Findings: []Finding{}}

	checkRoot(result)
	checkAmbientCredFiles(result)
	checkAmbientEnvVars(result)
	checkIMDS(result)

	return result
}

// checkRoot warns if the process is running as root.
func checkRoot(result *AuditResult) {
	if currentUID() == 0 {
		result.Findings = append(result.Findings, Finding{
			Severity: SeverityCritical,
			Check:    "root",
			Message:  "running as root (uid 0)",
			Detail:   "agents should run as a non-root user; the shield does not require elevated privileges",
		})
	}
}

// checkAmbientCredFiles warns if ~/.aws/credentials exists and is readable.
func checkAmbientCredFiles(result *AuditResult) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return
	}

	credPaths := []string{
		filepath.Join(home, ".aws", "credentials"),
		filepath.Join(home, ".ssh", "id_rsa"),
	}

	for _, p := range credPaths {
		if _, err := os.ReadFile(p); err == nil {
			result.Findings = append(result.Findings, Finding{
				Severity: SeverityWarning,
				Check:    "ambient_cred_file",
				Message:  fmt.Sprintf("ambient credential file is readable: %s", p),
				Detail:   "the shield denies access to this file via Landlock/Seatbelt, but its presence indicates ambient creds on the host",
			})
		}
	}
}

// checkAmbientEnvVars warns if credential env vars are set (before stripping).
func checkAmbientEnvVars(result *AuditResult) {
	credVars := []string{
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"PGPASSWORD",
		"GITHUB_TOKEN",
	}

	for _, v := range credVars {
		if os.Getenv(v) != "" {
			result.Findings = append(result.Findings, Finding{
				Severity: SeverityWarning,
				Check:    "ambient_env_var",
				Message:  fmt.Sprintf("ambient credential env var is set: %s", v),
				Detail:   "this will be stripped by env stripping before the agent launches; the warning is for audit visibility",
			})
		}
	}
}

// imdsTimeout is the timeout for IMDS HTTP requests.  Short to avoid
// blocking the launch when not on EC2 (the connection to 169.254.169.254
// will hang until the timeout on non-EC2 hosts).
const imdsTimeout = 2 * time.Second

const imdsBaseURL = "http://169.254.169.254"

// checkIMDS checks the EC2 instance metadata service version and the
// instance role name.  Best-effort: if IMDS is unreachable (non-EC2 host),
// the check is skipped silently.
func checkIMDS(result *AuditResult) {
	client := &http.Client{Timeout: imdsTimeout}

	// Try IMDSv2: PUT /latest/api/token
	token, err := getIMDSv2Token(client)
	if err != nil {
		// IMDSv2 not available — try IMDSv1 to see if we're on EC2 at all.
		if isIMDSv1Available(client) {
			result.IsEC2 = true
			result.Findings = append(result.Findings, Finding{
				Severity: SeverityCritical,
				Check:    "imds_version",
				Message:  "IMDSv1 is enabled (IMDSv2 token request failed, IMDSv1 responded)",
				Detail:   "IMDSv1 should be disabled; use IMDSv2 with hop-limit=1 to prevent SSRF",
			})
			// Try to get the role name via IMDSv1.
			checkIMDSRole(client, "", result)
		}
		return
	}

	// IMDSv2 is available — verify we can reach the metadata service.
	result.IsEC2 = true
	resp, err := imdsGet(client, "/latest/meta-data/", token)
	if err != nil {
		return
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return
	}
	_ = resp.Body.Close()

	// Get the instance role name.
	checkIMDSRole(client, token, result)
}

// getIMDSv2Token requests a session token from IMDSv2.
func getIMDSv2Token(client *http.Client) (string, error) {
	req, err := http.NewRequest("PUT", imdsBaseURL+"/latest/api/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "300")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("IMDSv2 token request returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// isIMDSv1Available checks if IMDSv1 responds (GET /latest/meta-data/ without token).
func isIMDSv1Available(client *http.Client) bool {
	resp, err := client.Get(imdsBaseURL + "/latest/meta-data/")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// imdsGet performs an IMDS GET request with an optional IMDSv2 token.
func imdsGet(client *http.Client, path, token string) (*http.Response, error) {
	req, err := http.NewRequest("GET", imdsBaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("X-aws-ec2-metadata-token", token)
	}
	return client.Do(req)
}

// checkIMDSRole gets the instance role name from IMDS and warns if it
// suggests AdministratorAccess.
func checkIMDSRole(client *http.Client, token string, result *AuditResult) {
	resp, err := imdsGet(client, "/latest/meta-data/iam/security-credentials/", token)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	roleName := strings.TrimSpace(string(body))
	if roleName == "" {
		return
	}

	// Heuristic: warn if the role name suggests admin access.
	// A proper check would call iam:list-attached-role-policies, but that
	// requires AWS credentials and SigV4 signing — out of scope for the
	// best-effort audit.
	roleLower := strings.ToLower(roleName)
	if strings.Contains(roleLower, "admin") || strings.Contains(roleLower, "administrator") {
		result.Findings = append(result.Findings, Finding{
			Severity: SeverityCritical,
			Check:    "iam_role",
			Message:  fmt.Sprintf("instance role name suggests administrator access: %s", roleName),
			Detail:   "an admin role grants the agent broad permissions; consider using a scoped role via agentjail-secrets",
		})
	} else {
		result.Findings = append(result.Findings, Finding{
			Severity: SeverityInfo,
			Check:    "iam_role",
			Message:  fmt.Sprintf("instance role: %s", roleName),
		})
	}
}

// hasCriticalFindings returns true if the audit result contains any
// critical-severity findings.
func hasCriticalFindings(result *AuditResult) bool {
	for _, f := range result.Findings {
		if f.Severity == SeverityCritical {
			return true
		}
	}
	return false
}

// printAuditWarnings prints human-readable warnings to stderr.
func printAuditWarnings(result *AuditResult) {
	for _, f := range result.Findings {
		switch f.Severity {
		case SeverityCritical:
			fmt.Fprintf(os.Stderr, "agentjail-shield AUDIT [CRITICAL]: %s: %s\n", f.Check, f.Message)
			if f.Detail != "" {
				fmt.Fprintf(os.Stderr, "  %s\n", f.Detail)
			}
		case SeverityWarning:
			fmt.Fprintf(os.Stderr, "agentjail-shield AUDIT [WARNING]: %s: %s\n", f.Check, f.Message)
		case SeverityInfo:
			fmt.Fprintf(os.Stderr, "agentjail-shield AUDIT [INFO]: %s: %s\n", f.Check, f.Message)
		}
	}
}

// writeAuditJSON writes the audit result as JSON to the given path.
// If path is "-", writes to stdout.
func writeAuditJSON(result *AuditResult, path string) error {
	var w io.Writer
	if path == "-" {
		w = os.Stdout
	} else {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
