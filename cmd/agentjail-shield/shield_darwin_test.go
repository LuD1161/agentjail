//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
)

// ---- Unit tests: sbpl profile generation ----

// TestGenerateSBProfileContainsDenyBlock verifies the generated sbpl profile
// has both deny blocks and the expected subpath entries.
func TestGenerateSBProfileContainsDenyBlock(t *testing.T) {
	cfg := config.Default()
	home := "/Users/testuser"
	profile := generateSBProfile(cfg, home)

	// Must start with the version header and allow default.
	if !strings.HasPrefix(profile, "(version 1)") {
		t.Error("profile does not start with (version 1)")
	}
	if !strings.Contains(profile, "(allow default)") {
		t.Error("profile missing (allow default)")
	}

	// Must contain the write-deny block.
	if !strings.Contains(profile, "(deny file-write*") {
		t.Error("profile missing (deny file-write* block")
	}

	// Must contain the read-deny block.
	if !strings.Contains(profile, "(deny file-read*") {
		t.Error("profile missing (deny file-read* block")
	}
}

// TestGenerateSBProfileSensitivePaths verifies that well-known sensitive paths
// appear in the profile with the correct home directory substitution.
func TestGenerateSBProfileSensitivePaths(t *testing.T) {
	cfg := config.Default()
	home := "/Users/me"
	profile := generateSBProfile(cfg, home)

	wantSubpaths := []string{
		`"/Users/me/.ssh"`,
		`"/Users/me/.aws"`,
		`"/Users/me/.gnupg"`,
		`"/Users/me/.agentjail"`,
		`"/etc"`,
		`"/private/etc"`,
		`"/var"`,
		`"/private/var"`,
	}
	for _, sub := range wantSubpaths {
		if !strings.Contains(profile, sub) {
			t.Errorf("profile missing subpath %s", sub)
		}
	}
}

// TestGenerateSBProfileRegexPatterns verifies that regex patterns for
// sensitive extensions appear in the profile.
func TestGenerateSBProfileRegexPatterns(t *testing.T) {
	cfg := config.Default()
	home := "/Users/me"
	profile := generateSBProfile(cfg, home)

	wantRegexes := []string{
		`\.env`,
		`id_(rsa|ed25519|ecdsa|dsa)`,
		`\.(pem|p12|pfx|jks|keystore|key)`,
	}
	for _, rx := range wantRegexes {
		if !strings.Contains(profile, rx) {
			t.Errorf("profile missing regex pattern %s", rx)
		}
	}
}

// TestGenerateSBProfileExtraDeny verifies that ExtraDeny entries from
// policy.yaml are included in the write-deny block.
func TestGenerateSBProfileExtraDeny(t *testing.T) {
	cfg := &config.PolicyConfig{
		File: config.FileConfig{
			ExtraDeny: []string{"/Users/me/secrets-vault", "/mnt/nfs/prod"},
		},
	}
	home := "/Users/me"
	profile := generateSBProfile(cfg, home)

	for _, p := range []string{`"/Users/me/secrets-vault"`, `"/mnt/nfs/prod"`} {
		if !strings.Contains(profile, p) {
			t.Errorf("ExtraDeny path %s not found in profile", p)
		}
	}
}

// TestGenerateSBProfileNilConfig verifies the profile generates correctly
// even when cfg is nil (baseline-only).
func TestGenerateSBProfileNilConfig(t *testing.T) {
	profile := generateSBProfile(nil, "/Users/me")
	if !strings.Contains(profile, "(deny file-write*") {
		t.Error("nil cfg: profile missing write-deny block")
	}
}

// ---- Unit tests: network sbpl profile generation ----

// TestGenerateSBProfile_WithNetwork verifies that when a host list with known
// IPs is supplied (used for logging only in sbpl), the generated sbpl profile
// contains the required network rules:
//   - (deny network*) as the default (last rule, first-match wins)
//   - (allow network-outbound (literal "/private/var/run/mDNSResponder")) for macOS DNS
//   - (allow network-outbound (remote udp "*:53")) for DNS UDP
//   - (allow network-outbound (remote ip "localhost:*")) for loopback
//   - (allow network-outbound (remote tcp "*:443")) for HTTPS
//   - (allow network-outbound (remote tcp "*:80")) for HTTP
//
// Note: sbpl does NOT support literal IP addresses in (remote ip "IP:port") —
// only "*" and "localhost" are valid host values.  The allowedIPs parameter
// is logged at startup but does not change the sbpl allow/deny structure.
// This is a documented Tier 1.5 limitation (sbpl does not support literal IPs).
func TestGenerateSBProfile_WithNetwork(t *testing.T) {
	cfg := config.Default()
	home := "/Users/testuser"
	// Supply IPs that represent what would be resolved at startup; they are
	// logged but not emitted as sbpl rules (sbpl limitation).
	allowedIPs := []string{"140.82.112.6", "140.82.113.4"}
	// withNetproxy=false: test the port-only mode (baseline behaviour).
	profile := generateSBProfileWithIPs(cfg, home, allowedIPs, false)

	// Must contain the global network deny.
	if !strings.Contains(profile, "(deny network*)") {
		t.Errorf("profile missing (deny network*); got:\n%s", profile)
	}

	// Must contain mDNSResponder socket allow (required for DNS on macOS).
	if !strings.Contains(profile, `"/private/var/run/mDNSResponder"`) {
		t.Errorf("profile missing mDNSResponder literal allow; got:\n%s", profile)
	}

	// Must contain DNS UDP allow.
	if !strings.Contains(profile, `(remote udp "*:53")`) {
		t.Errorf("profile missing DNS allow (remote udp *:53); got:\n%s", profile)
	}

	// Must contain loopback allow.
	if !strings.Contains(profile, `(remote ip "localhost:*")`) {
		t.Errorf("profile missing loopback allow; got:\n%s", profile)
	}

	// Must contain HTTPS allow.
	if !strings.Contains(profile, `(remote tcp "*:443")`) {
		t.Errorf("profile missing HTTPS allow (remote tcp *:443); got:\n%s", profile)
	}

	// Must contain HTTP allow.
	if !strings.Contains(profile, `(remote tcp "*:80")`) {
		t.Errorf("profile missing HTTP allow (remote tcp *:80); got:\n%s", profile)
	}

	// The (deny network*) appears at the end of the profile as the catch-all.
	// For network rules, sbpl allows more-specific rules (e.g. remote tcp "*:443")
	// to override the general (deny network*) regardless of ordering.  We still
	// emit deny at the end (after the allows) as the conventional pattern.
	denyIdx := strings.Index(profile, "(deny network*)")
	if denyIdx == -1 {
		t.Error("profile missing (deny network*) catch-all")
	}
	// The allows appear before the deny in the profile (conventional ordering).
	for _, allow := range []string{
		`(remote udp "*:53")`,
		`(remote tcp "*:443")`,
		`(remote tcp "*:80")`,
		`(remote ip "localhost:*")`,
	} {
		allowIdx := strings.Index(profile, allow)
		if allowIdx == -1 {
			continue // already reported above
		}
		if allowIdx > denyIdx {
			t.Logf("NOTE: allow rule %q appears AFTER (deny network*) — verify this still works if moving rules", allow)
		}
	}

	// sbpl limitation: literal IPs must NOT appear as (remote ip "IP:*") rules
	// because that syntax is rejected by sandbox-exec.  Verify we don't emit them.
	for _, ip := range allowedIPs {
		badRule := fmt.Sprintf(`(remote ip "%s:`, ip)
		if strings.Contains(profile, badRule) {
			t.Errorf("profile contains unsupported sbpl IP rule %q — sandbox-exec will reject this", badRule)
		}
	}
}

// TestGenerateSBProfile_NetworkNilCfg verifies the profile still contains
// network deny + DNS allow even with a nil config (no allowed hosts).
func TestGenerateSBProfile_NetworkNilCfg(t *testing.T) {
	profile := generateSBProfileWithIPs(nil, "/Users/me", nil, false)
	if !strings.Contains(profile, "(deny network*)") {
		t.Error("nil cfg: profile missing (deny network*)")
	}
	if !strings.Contains(profile, `(remote udp "*:53")`) {
		t.Error("nil cfg: profile missing DNS allow")
	}
	if !strings.Contains(profile, `(remote tcp "*:443")`) {
		t.Error("nil cfg: profile missing HTTPS allow")
	}
}

// TestResolveAllowedHosts_FailsGracefully verifies that a non-resolvable
// hostname is skipped without returning an error or panicking.
func TestResolveAllowedHosts_FailsGracefully(t *testing.T) {
	cfg := &config.PolicyConfig{
		Network: config.NetworkConfig{
			// Mix of a valid loopback hostname and a definitely-non-resolvable one.
			AllowedHosts: []string{
				"this-host-does-not-exist-agentjail-test-12345.invalid",
				"localhost", // should resolve to 127.0.0.1 / ::1 but those are skipped (loopback)
			},
		},
	}
	// Should not panic or return error; may return empty slice.
	ips := resolveAllowedHosts(cfg)
	// The non-resolvable host must be silently skipped (ips may be empty).
	for _, ip := range ips {
		if strings.Contains(ip, "12345") {
			t.Errorf("unexpected IP %q from non-resolvable host in result", ip)
		}
	}
	t.Logf("resolveAllowedHosts returned (expected empty or loopback-filtered): %v", ips)
}

// ---- Integration tests: actual sandbox enforcement ----

// skipIfNoSandboxExec skips the test if /usr/bin/sandbox-exec is absent.
func skipIfNoSandboxExec(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(sandboxExecPath); err != nil {
		t.Skipf("sandbox-exec not found at %s: %v", sandboxExecPath, err)
	}
}

// buildShieldBinary builds the agentjail-shield binary into a temp dir and
// returns its path.  Skips if go build fails.
func buildShieldBinary(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	out := filepath.Join(tmp, "agentjail-shield")
	// Find the repo root by walking up from this file's package.
	repoRoot := findRepoRoot(t)
	cmd := exec.Command("go", "build", "-o", out, "./cmd/agentjail-shield/")
	cmd.Dir = repoRoot
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build agentjail-shield: %v", err)
	}
	return out
}

// findRepoRoot walks up from the test binary's directory looking for go.work.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	// Start from the package source directory (reliable in `go test`).
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (go.work)")
		}
		dir = parent
	}
}

// TestSandboxBlocksSensitiveWrite verifies that agentjail-shield prevents
// writing to ~/.ssh/ even when the write is performed via a shell redirect
// (the canonical bypass that motivated ADR 0001).
func TestSandboxBlocksSensitiveWrite(t *testing.T) {
	skipIfNoSandboxExec(t)
	shieldBin := buildShieldBinary(t)

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}

	testFile := filepath.Join(home, ".ssh", "agentjail-shield-test-write")
	// Make sure the file doesn't already exist from a previous failed run.
	_ = os.Remove(testFile)
	t.Cleanup(func() { os.Remove(testFile) })

	// Run the shield wrapping a shell that tries to write to ~/.ssh/
	cmd := exec.Command(shieldBin, "--",
		"sh", "-c", fmt.Sprintf("printf 'x' > %s 2>&1; echo exit=$?", testFile))
	out, _ := cmd.CombinedOutput()
	output := string(out)
	t.Logf("shield output: %s", output)

	// The write must have been blocked: either the command returned a non-zero
	// exit from the shell redirect failing, or sandbox-exec itself exited
	// non-zero.  What matters is the file does NOT exist.
	if _, statErr := os.Stat(testFile); statErr == nil {
		t.Errorf("TestSandboxBlocksSensitiveWrite FAILED: file %s was created despite sandbox", testFile)
	} else {
		t.Logf("PASS: file %s was not created (sandbox blocked the write)", testFile)
	}

	// Also check that the output contains evidence of permission denial.
	if !strings.Contains(strings.ToLower(output), "not permitted") &&
		!strings.Contains(strings.ToLower(output), "permission") &&
		!strings.Contains(strings.ToLower(output), "denied") &&
		!strings.Contains(output, "exit=1") &&
		cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == 0 {
		t.Logf("NOTE: output did not contain 'not permitted' — check sandbox-exec behaviour: %s", output)
	}
}

// TestSandboxAllowsSafeWrite verifies that agentjail-shield does NOT block
// writes to /tmp (which the agent legitimately uses).
func TestSandboxAllowsSafeWrite(t *testing.T) {
	skipIfNoSandboxExec(t)
	shieldBin := buildShieldBinary(t)

	testFile := fmt.Sprintf("/tmp/agentjail-shield-test-%d", os.Getpid())
	_ = os.Remove(testFile)
	t.Cleanup(func() { os.Remove(testFile) })

	cmd := exec.Command(shieldBin, "--",
		"sh", "-c", fmt.Sprintf("printf 'hello' > %s && echo written_ok", testFile))
	out, err := cmd.CombinedOutput()
	output := string(out)
	t.Logf("shield output: %s", output)

	if err != nil {
		t.Errorf("TestSandboxAllowsSafeWrite: expected exit 0 but got error: %v (output: %s)", err, output)
	}

	if _, statErr := os.Stat(testFile); statErr != nil {
		t.Errorf("TestSandboxAllowsSafeWrite FAILED: file %s was NOT created: %v", testFile, statErr)
	} else {
		t.Logf("PASS: file %s was created (sandbox allowed the write)", testFile)
	}
}

// TestProfilePrintFlag verifies that --profile-print outputs the sbpl profile
// to stderr and exits 0.
func TestProfilePrintFlag(t *testing.T) {
	skipIfNoSandboxExec(t)
	shieldBin := buildShieldBinary(t)

	cmd := exec.Command(shieldBin, "--profile-print", "--", "sh")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		// exit 0 expected
		t.Errorf("--profile-print exited non-zero: %v", err)
	}
	profile := stderr.String()
	if !strings.Contains(profile, "(version 1)") {
		t.Errorf("--profile-print output missing (version 1); got: %s", profile)
	}
	if !strings.Contains(profile, "(deny file-write*") {
		t.Errorf("--profile-print output missing deny block; got: %s", profile)
	}
}

// ---- New tests: netproxy integration ----

// TestSBProfile_WithNetproxy verifies that when withNetproxy=true the sbpl
// profile restricts the agent to localhost-only outbound TCP (no wildcard
// *:443 / *:80 rules).  The agent must funnel all HTTPS through the proxy.
func TestSBProfile_WithNetproxy(t *testing.T) {
	cfg := config.Default()
	home := "/Users/testuser"
	allowedIPs := []string{"140.82.112.6"} // informational only
	profile := generateSBProfileWithIPs(cfg, home, allowedIPs, true)

	// Must contain the global network deny.
	if !strings.Contains(profile, "(deny network*)") {
		t.Errorf("profile missing (deny network*); got:\n%s", profile)
	}

	// Must contain loopback allow (where the proxy lives).
	if !strings.Contains(profile, `(remote ip "localhost:*")`) {
		t.Errorf("profile missing loopback allow; got:\n%s", profile)
	}

	// Must contain DNS allows (proxy needs to resolve upstream hosts).
	if !strings.Contains(profile, `(remote udp "*:53")`) {
		t.Errorf("profile missing DNS allow; got:\n%s", profile)
	}
	if !strings.Contains(profile, `"/private/var/run/mDNSResponder"`) {
		t.Errorf("profile missing mDNSResponder allow; got:\n%s", profile)
	}

	// Must NOT contain wildcard *:443 or *:80 (those bypass the proxy).
	if strings.Contains(profile, `(remote tcp "*:443")`) {
		t.Errorf("withNetproxy profile must NOT have wildcard *:443 rule; got:\n%s", profile)
	}
	if strings.Contains(profile, `(remote tcp "*:80")`) {
		t.Errorf("withNetproxy profile must NOT have wildcard *:80 rule; got:\n%s", profile)
	}

	// Confirm sbpl IP rules are absent (sbpl rejects them anyway).
	for _, ip := range allowedIPs {
		badRule := fmt.Sprintf(`(remote ip "%s:`, ip)
		if strings.Contains(profile, badRule) {
			t.Errorf("profile contains unsupported sbpl IP rule %q", badRule)
		}
	}
}

// TestSBProfile_NoNetproxy verifies the port-only profile (withNetproxy=false)
// still contains the *:443 and *:80 wildcard rules for backward compatibility.
func TestSBProfile_NoNetproxy(t *testing.T) {
	cfg := config.Default()
	profile := generateSBProfileWithIPs(cfg, "/Users/me", nil, false)

	if !strings.Contains(profile, `(remote tcp "*:443")`) {
		t.Errorf("port-only profile must have *:443 allow; got:\n%s", profile)
	}
	if !strings.Contains(profile, `(remote tcp "*:80")`) {
		t.Errorf("port-only profile must have *:80 allow; got:\n%s", profile)
	}
}

// TestFindNetproxyBinary_NotFound verifies that findNetproxyBinary returns an
// error when none of the search locations exist.
func TestFindNetproxyBinary_NotFound(t *testing.T) {
	// Clear $AGENTJAIL_NETPROXY so the env var path doesn't interfere.
	t.Setenv("AGENTJAIL_NETPROXY", "")

	// Use a fake os.Args[0] that points to a temp dir where the binary won't be.
	// We can't easily override os.Args[0] in a test, but we can verify the
	// general case by checking the error message.
	_, err := findNetproxyBinary()
	// If the binary happens to exist on the test machine (e.g. a dev installed it),
	// we skip the "not found" check.
	if err == nil {
		t.Log("findNetproxyBinary found a binary — this is valid on dev machines that have it installed; skipping not-found check")
		return
	}
	// Verify the error message is helpful.
	errStr := err.Error()
	if !strings.Contains(errStr, "agentjail-netproxy") {
		t.Errorf("error message should mention 'agentjail-netproxy'; got: %q", errStr)
	}
}

// TestStartNetproxy_NotFound verifies that startNetproxy returns a clear error
// when the binary path is bogus.
func TestStartNetproxy_NotFound(t *testing.T) {
	_, err := startNetproxy("/nonexistent/agentjail-netproxy", "127.0.0.1:9199", "/tmp/policy.yaml")
	if err == nil {
		t.Fatal("expected error starting nonexistent binary")
	}
	t.Logf("got expected error: %v", err)
}

// TestStartNetproxy_NeverBinds verifies that startNetproxy returns a clear error
// when the binary starts but never listens on the expected port.
func TestStartNetproxy_NeverBinds(t *testing.T) {
	// Use 'sleep' as a fake binary that doesn't bind.
	sleepBin, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep not found; skipping")
	}
	_, err = startNetproxy(sleepBin, "127.0.0.1:9198", "/tmp/policy.yaml")
	if err == nil {
		t.Fatal("expected error when netproxy doesn't bind")
	}
	if !strings.Contains(err.Error(), "200ms") {
		t.Errorf("error should mention 200ms timeout; got: %q", err.Error())
	}
	t.Logf("got expected error: %v", err)
}

// TestNoNetproxyFlag_PortOnlyProfile verifies that the --no-netproxy flag
// causes the profile to contain wildcard *:443 rules (port-only mode).
func TestNoNetproxyFlag_PortOnlyProfile(t *testing.T) {
	skipIfNoSandboxExec(t)
	shieldBin := buildShieldBinary(t)

	cmd := exec.Command(shieldBin, "--no-netproxy", "--profile-print", "--", "sh")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	_ = cmd.Run()
	profile := stderr.String()

	if !strings.Contains(profile, `(remote tcp "*:443")`) {
		t.Errorf("--no-netproxy profile should have *:443 allow; got:\n%s", profile)
	}
}

// ---- New credential-store path tests ----

// TestSensitiveReadPaths_NewCredentialStores verifies that the new credential
// store directories are included in the read-deny list.
func TestSensitiveReadPaths_NewCredentialStores(t *testing.T) {
	home := "/Users/testuser"
	paths := sensitiveReadPaths(home)
	want := []string{
		home + "/.docker",
		home + "/.kube",
		home + "/Library/Keychains",
	}
	for _, w := range want {
		found := false
		for _, p := range paths {
			if p == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("sensitiveReadPaths missing %q", w)
		}
	}
}

// TestSensitiveWritePaths_NewCredentialStores verifies that the new credential
// store directories are included in the write-deny list.
func TestSensitiveWritePaths_NewCredentialStores(t *testing.T) {
	home := "/Users/testuser"
	paths := sensitiveWritePaths(home)
	want := []string{
		home + "/.docker",
		home + "/.kube",
		home + "/.cargo",
		home + "/Library/Keychains",
	}
	for _, w := range want {
		found := false
		for _, p := range paths {
			if p == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("sensitiveWritePaths missing %q", w)
		}
	}
}

// TestProfileContainsNpmrcRegex verifies that ~/.npmrc anchored regex appears
// in both the write-deny and read-deny blocks of the generated sbpl profile.
func TestProfileContainsNpmrcRegex(t *testing.T) {
	cfg := config.Default()
	home := "/Users/testuser"
	profile := generateSBProfile(cfg, home)

	wantRegex := `/Users/[^/]+/\.npmrc$`
	if !strings.Contains(profile, wantRegex) {
		t.Errorf("profile missing anchored .npmrc regex %q;\nprofile:\n%s", wantRegex, profile)
	}
}

// TestProfileContainsDockerConfigPath verifies that ~/.docker subpath appears
// in the generated sbpl profile (covers config.json and the whole directory).
func TestProfileContainsDockerConfigPath(t *testing.T) {
	cfg := config.Default()
	home := "/Users/testuser"
	profile := generateSBProfile(cfg, home)

	wantSubpath := `"/Users/testuser/.docker"`
	if !strings.Contains(profile, wantSubpath) {
		t.Errorf("profile missing .docker subpath %q;\nprofile:\n%s", wantSubpath, profile)
	}
}

// TestNpmrcBakNotCaughtByRegex verifies that the anchored .npmrc regex does NOT
// match .npmrc.bak (a common backup file that must not be blocked).
func TestNpmrcBakNotCaughtByRegex(t *testing.T) {
	cfg := config.Default()
	home := "/Users/testuser"
	profile := generateSBProfile(cfg, home)

	// The profile must contain the exact-match regex but NOT a pattern that
	// would match .npmrc.bak.  We validate indirectly by confirming the $ anchor
	// is present (which prevents suffix matches like .npmrc.bak).
	if !strings.Contains(profile, `\.npmrc$`) {
		t.Errorf("profile is missing the dollar-anchored .npmrc regex; suffix like .npmrc.bak could match")
	}
	// Confirm the profile does NOT contain a pattern like \.npmrc\. which would catch .npmrc.bak
	if strings.Contains(profile, `\.npmrc\.`) {
		t.Errorf("profile contains a pattern that could over-match .npmrc.bak")
	}
}

// TestProjectLocalNpmrcNotBlockedBySubpath verifies that a project-local
// .npmrc (e.g. /Users/dev/myproject/.npmrc) is NOT caught by subpath rules.
// The subpath rules cover ~/.docker, ~/.kube, ~/.cargo, etc. — not all of ~/.
// A project-local .npmrc would only be caught by the regex, which is anchored
// to the home root and requires the file to be directly under /Users/<user>/.
func TestProjectLocalNpmrcNotBlockedBySubpath(t *testing.T) {
	home := "/Users/dev"
	paths := sensitiveWritePaths(home)
	// The subpath list must NOT include the bare home directory (that would
	// block everything under ~/).
	for _, p := range paths {
		if p == home {
			t.Errorf("sensitiveWritePaths must not include the bare home directory %q — this would block all project files", p)
		}
	}
	// Specifically: /Users/dev/myproject should not be prefix-matched by any entry.
	projectPath := home + "/myproject/.npmrc"
	for _, p := range paths {
		if strings.HasPrefix(projectPath, p+"/") || projectPath == p {
			// /Users/dev/.docker, /Users/dev/.kube etc. are fine —
			// myproject/.npmrc is NOT under those; this is checking
			// that the home itself isn't in the list.
			if p == home || p == home+"/" {
				t.Errorf("subpath %q would block project-local files under %q", p, home)
			}
		}
	}
}
