//go:build darwin

package shieldapp

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/grantctl"
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

// TestResolveAllowedHosts_SkipsWildcardsWithoutLookup verifies that a
// wildcard entry (e.g. "*.claude.ai") never reaches net.LookupHost -- it is
// classified via config.ClassifyHost and skipped outright, since
// "*.claude.ai" can never resolve as a literal DNS name. This is a
// regression test for the "wildcard-DNS theater" cleanup (ADR 0041): before
// the fix, every wildcard entry logged a spurious "could not resolve …
// skipping" line on every shield launch.
func TestResolveAllowedHosts_SkipsWildcardsWithoutLookup(t *testing.T) {
	// Use a NetworkConfig-only PolicyConfig is not enough to isolate wildcard
	// handling (EffectiveAllowedHosts always merges in the exact essential
	// hosts too). Instead, verify directly that config.ClassifyHost marks a
	// "*.…" entry as Wildcard, and that resolveAllowedHosts does not error or
	// panic on a host list containing only wildcard entries plus one
	// deliberately non-resolvable exact host -- i.e. every entry in the list
	// is either skipped (wildcard) or fails-and-is-skipped (exact,
	// non-resolvable), so the function must return cleanly with no IPs
	// attributable to the wildcard entry.
	hp := config.ClassifyHost("*.this-wildcard-must-not-be-looked-up.invalid")
	if !hp.Wildcard {
		t.Fatalf("expected ClassifyHost(%q).Wildcard = true", hp.Pattern)
	}

	cfg := &config.PolicyConfig{
		Network: config.NetworkConfig{
			AllowedHosts: []string{"*.this-wildcard-must-not-be-looked-up.invalid"},
		},
	}
	// Should not panic. Essential exact hosts may still resolve to real IPs
	// if the test environment has network access -- this test only asserts
	// the wildcard entry itself contributes nothing and causes no error.
	ips := resolveAllowedHosts(cfg)
	t.Logf("resolveAllowedHosts with a wildcard-only editable list returned: %v", ips)
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

	// Run the shield wrapping a shell that tries to write to ~/.ssh/.
	// --no-netproxy: this test exercises the FILE sandbox only; without it the
	// shield would try to start/register netproxy and fail closed if :9100 is
	// occupied by an unverifiable listener (see ensureSessionProxy), which is
	// unrelated to the file-write behavior under test.
	cmd := exec.Command(shieldBin, "--no-netproxy", "--",
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

	// --no-netproxy: this test exercises the FILE sandbox only (safe write to
	// /tmp). Without it the shield would try to start/register netproxy and,
	// if :9100 is occupied by an unverifiable listener, fail closed -- unrelated
	// to the write-allow behavior under test.
	cmd := exec.Command(shieldBin, "--no-netproxy", "--",
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

// TestFindNetproxyBinary_NotFound lives in netproxy_test.go (cross-platform).
// ensureSessionProxy (start / register / fail-closed) is likewise tested
// cross-platform in netproxy_test.go.

// TestGenerateSBProfile_DeniesControlSocket verifies the netproxy-mode profile
// explicitly denies the agent the netproxy control socket. Seatbelt's
// (allow default) base would otherwise permit the AF_UNIX connect, letting the
// sandboxed agent reach the control plane and widen its own allowlist.
func TestGenerateSBProfile_DeniesControlSocket(t *testing.T) {
	cfg := config.Default()
	home := "/Users/me"
	profile := generateSBProfileWithNetproxy(cfg, home)

	wantDeny := `(deny network-outbound
    (literal "/Users/me/.agentjail/run/netproxy-ctl.sock"))`
	if !strings.Contains(profile, wantDeny) {
		t.Errorf("netproxy profile must deny the control socket; missing:\n%s\n\ngot:\n%s", wantDeny, profile)
	}
}

// TestGenerateSBProfile_DeniesGrantControlSocket verifies the generated sbpl
// profile denies network-outbound to the daemon's grant control socket,
// mirroring the netproxy-ctl.sock deny above.
func TestGenerateSBProfile_DeniesGrantControlSocket(t *testing.T) {
	cfg := config.Default()
	home := "/Users/me"
	profile := generateSBProfileWithNetproxy(cfg, home)

	expected := grantctl.ControlSocketPathForHome(home)
	wantDeny := fmt.Sprintf("(deny network-outbound\n    (literal %q))", expected)
	if !strings.Contains(profile, wantDeny) {
		t.Errorf("profile must deny the grant control socket; missing:\n%s\n\ngot:\n%s", wantDeny, profile)
	}
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
	// ~/Library/Keychains must NOT be read-denied: the shielded agent's own
	// process needs its login keychain readable for Claude Code auth. See
	// docs/adr/0037-macos-keychain-access-shielded-agent.md.
	for _, p := range paths {
		if p == home+"/Library/Keychains" {
			t.Errorf("sensitiveReadPaths must NOT contain %q", home+"/Library/Keychains")
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
	// ~/Library/Keychains must NOT be write-denied: the shielded agent's own
	// process needs its login keychain writable for Claude Code auth/token
	// refresh. See docs/adr/0037-macos-keychain-access-shielded-agent.md.
	for _, p := range paths {
		if p == home+"/Library/Keychains" {
			t.Errorf("sensitiveWritePaths must NOT contain %q", home+"/Library/Keychains")
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

// TestGenerateSBProfile_ClaudeWriteCarveOut verifies the fix for the darwin
// vs linux allow-list drift: ~/.claude must be write-allowed (Claude Code
// needs to create files like ~/.claude/session-env/<uuid>), while paths that
// must stay denied (~/.ssh, ~/.agentjail) remain denied. ~/Library/Keychains
// is intentionally granted (read+write) by default -- see
// docs/adr/0037-macos-keychain-access-shielded-agent.md.
func TestGenerateSBProfile_ClaudeWriteCarveOut(t *testing.T) {
	cfg := config.Default()
	home := "/Users/testuser"
	profile := generateSBProfile(cfg, home)

	// (i) file-write* to <home>/.claude must be allowed via an explicit
	// carve-out subpath rule appearing after the deny block.
	claudeAllow := `(allow file-write*
    (subpath "/Users/testuser/.claude"))`
	if !strings.Contains(profile, claudeAllow) {
		t.Errorf("profile missing file-write* allow carve-out for ~/.claude; got:\n%s", profile)
	}
	// ~/.claude must NOT appear in the write-deny subpath block anymore.
	denyBlockEnd := strings.Index(profile, "(deny file-read*")
	writeBlock := profile
	if denyBlockEnd != -1 {
		writeBlock = profile[:denyBlockEnd]
	}
	// The write-deny block (before the carve-out allows) must not itself
	// list ~/.claude among the (subpath ...) denies. We check this by
	// ensuring the deny block up to the first allow carve-out doesn't
	// contain the bare subpath entry.
	denyOnlyEnd := strings.Index(writeBlock, "(allow file-write*")
	if denyOnlyEnd != -1 {
		denyOnly := writeBlock[:denyOnlyEnd]
		if strings.Contains(denyOnly, `(subpath "/Users/testuser/.claude")`) {
			t.Errorf("~/.claude must not be in the file-write* deny block; got deny block:\n%s", denyOnly)
		}
	}

	// (ii) file-write* to <home>/.ssh and <home>/.agentjail must still be denied
	// — no allow carve-out must exist for either.
	for _, p := range []string{"/Users/testuser/.ssh", "/Users/testuser/.agentjail"} {
		denyRule := fmt.Sprintf(`(subpath %q)`, p)
		if !strings.Contains(profile, denyRule) {
			t.Errorf("profile missing write-deny subpath for %s", p)
		}
		allowRule := fmt.Sprintf("(allow file-write*\n    (subpath %q))", p)
		if strings.Contains(profile, allowRule) {
			t.Errorf("profile must NOT contain a write-allow carve-out for %s", p)
		}
	}

	// (iii) ~/Library/Keychains must NOT be deny-listed (read or write) --
	// the shielded agent's own process is granted its login keychain by
	// default so Claude Code auth/token-refresh works. See
	// docs/adr/0037-macos-keychain-access-shielded-agent.md.
	keychainDenySubpath := `(subpath "/Users/testuser/Library/Keychains")`
	writeDenyEnd := strings.Index(profile, "(allow file-write*")
	if writeDenyEnd != -1 && strings.Contains(profile[:writeDenyEnd], keychainDenySubpath) {
		t.Errorf("profile must NOT contain a write-deny subpath for ~/Library/Keychains; got deny block:\n%s", profile[:writeDenyEnd])
	}
	readDenyStart := strings.Index(profile, "(deny file-read*")
	readDenyEnd := strings.Index(profile, "(allow file-read*")
	if readDenyStart != -1 && readDenyEnd != -1 && strings.Contains(profile[readDenyStart:readDenyEnd], keychainDenySubpath) {
		t.Errorf("profile must NOT contain a read-deny subpath for ~/Library/Keychains; got deny block:\n%s", profile[readDenyStart:readDenyEnd])
	}
}

// ---- Darwin TMPDIR / AF_UNIX carve-out tests ----

// TestValidateDarwinTempDir table-tests the pure validation/carve-out logic
// in validateDarwinTempDir, independent of the process's actual TMPDIR (see
// darwinUserTempDirs, which is the thin os.TempDir()-reading wrapper around
// this function).
func TestValidateDarwinTempDir(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string // nil means "must return nil (no carve-out)"
	}{
		{
			name: "var_folders_form",
			in:   "/var/folders/x/y/T",
			want: []string{"/private/var/folders/x/y/T", "/var/folders/x/y/T"},
		},
		{
			name: "private_var_folders_form",
			in:   "/private/var/folders/x/y/T",
			want: []string{"/private/var/folders/x/y/T", "/var/folders/x/y/T"},
		},
		{name: "bare_tmp", in: "/tmp", want: nil},
		{name: "empty", in: "", want: nil},
		{name: "arbitrary_path", in: "/Users/me", want: nil},
		{name: "var_folders_root_only", in: "/var/folders", want: nil},
		{name: "subpath_of_T", in: "/var/folders/x/y/T/sub", want: nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := validateDarwinTempDir(c.in)
			if c.want == nil {
				if got != nil {
					t.Fatalf("validateDarwinTempDir(%q) = %v, want nil", c.in, got)
				}
				return
			}
			if len(got) != len(c.want) {
				t.Fatalf("validateDarwinTempDir(%q) = %v, want %v", c.in, got, c.want)
			}
			gotSet := map[string]bool{}
			for _, g := range got {
				gotSet[g] = true
			}
			for _, w := range c.want {
				if !gotSet[w] {
					t.Errorf("validateDarwinTempDir(%q) missing %q; got %v", c.in, w, got)
				}
			}
		})
	}

	// Never returns a dangerously broad path regardless of input.
	dangerous := map[string]bool{"/": true, "/var": true, "/private/var": true, "/tmp": true, "/private/tmp": true}
	for _, c := range cases {
		for _, g := range validateDarwinTempDir(c.in) {
			if dangerous[g] {
				t.Errorf("validateDarwinTempDir(%q) returned dangerous broad path %q", c.in, g)
			}
		}
	}
}

// withSyntheticDarwinTempDir sets TMPDIR to a synthetic, deterministic
// /var/folders/<xx>/<yyy>/T path for the duration of the test and restores
// the previous value on cleanup. This makes profile-content assertions
// deterministic regardless of how the test binary was invoked -- notably,
// this repo's convention of exporting TMPDIR=/tmp for sandboxed `go test`
// runs would otherwise make os.TempDir() return "/tmp", a value
// validateDarwinTempDir correctly rejects (no carve-out).
func withSyntheticDarwinTempDir(t *testing.T) (canonical, symlink string) {
	t.Helper()
	const synthetic = "/var/folders/zz/agentjailtest01/T"
	old, hadOld := os.LookupEnv("TMPDIR")
	if err := os.Setenv("TMPDIR", synthetic); err != nil {
		t.Fatalf("Setenv TMPDIR: %v", err)
	}
	t.Cleanup(func() {
		if hadOld {
			os.Setenv("TMPDIR", old)
		} else {
			os.Unsetenv("TMPDIR")
		}
	})
	return "/private" + synthetic, synthetic
}

// TestGenerateSBProfile_DarwinTempDirCarveOut verifies the generated sbpl
// profile carves out the per-user TMPDIR for file-write and AF_UNIX
// bind/connect, per the bind-broad/connect-narrow threat model: network-bind
// is allowed for /tmp, /private/tmp, and the T dir; network-outbound
// (connect) is allowed ONLY for the T dir, never bare /tmp or /private/tmp.
func TestGenerateSBProfile_DarwinTempDirCarveOut(t *testing.T) {
	canonical, symlink := withSyntheticDarwinTempDir(t)

	cfg := config.Default()
	home := "/Users/testuser"
	profile := generateSBProfileWithIPs(cfg, home, nil, false)

	// file-write* allow for both forms of the T dir.
	for _, dir := range []string{canonical, symlink} {
		want := fmt.Sprintf("(allow file-write*\n    (subpath %q))", dir)
		if !strings.Contains(profile, want) {
			t.Errorf("profile missing file-write* allow for %s; got:\n%s", dir, profile)
		}
	}

	// network-bind allow for /tmp, /private/tmp, and both T dir forms.
	for _, dir := range []string{"/private/tmp", "/tmp", canonical, symlink} {
		want := fmt.Sprintf("(allow network-bind\n    (subpath %q))", dir)
		if !strings.Contains(profile, want) {
			t.Errorf("profile missing network-bind allow for %s; got:\n%s", dir, profile)
		}
	}

	// network-outbound allow for the T dir forms only.
	for _, dir := range []string{canonical, symlink} {
		want := fmt.Sprintf("(allow network-outbound\n    (subpath %q))", dir)
		if !strings.Contains(profile, want) {
			t.Errorf("profile missing network-outbound allow for %s; got:\n%s", dir, profile)
		}
	}

	// Must NOT allow network-outbound subpath for bare /tmp or /private/tmp
	// (the shim-egress risk the bind-broad/connect-narrow split guards against).
	for _, dir := range []string{"/tmp", "/private/tmp"} {
		bad := fmt.Sprintf("(allow network-outbound\n    (subpath %q))", dir)
		if strings.Contains(profile, bad) {
			t.Errorf("profile must NOT allow network-outbound subpath for %s; got:\n%s", dir, profile)
		}
	}

	// Must not contain a bare (subpath "/var") ALLOW anywhere (that would
	// undo the broad /var write-deny rather than carving out just the T dir).
	if strings.Contains(profile, "(allow file-write*\n    (subpath \"/var\"))") {
		t.Errorf("profile must not allow-carve-out the whole /var tree; got:\n%s", profile)
	}

	// Position: the temp-dir allows must appear before (deny network*).
	denyIdx := strings.Index(profile, "(deny network*)")
	if denyIdx == -1 {
		t.Fatal("profile missing (deny network*)")
	}
	for _, dir := range []string{canonical, symlink} {
		idx := strings.Index(profile, fmt.Sprintf("(allow network-outbound\n    (subpath %q))", dir))
		if idx == -1 || idx > denyIdx {
			t.Errorf("network-outbound allow for %s must appear before (deny network*); idx=%d denyIdx=%d", dir, idx, denyIdx)
		}
	}
	for _, dir := range []string{canonical, symlink} {
		idx := strings.Index(profile, fmt.Sprintf("(allow file-write*\n    (subpath %q))", dir))
		if idx == -1 || idx > denyIdx {
			t.Errorf("file-write* allow for %s must appear before (deny network*); idx=%d denyIdx=%d", dir, idx, denyIdx)
		}
	}
}

// TestSandboxExec_DarwinTempDirCarveOuts is a REAL sandbox-exec integration
// test: it writes the generated profile to disk and execs python3 under
// sandbox-exec to exercise actual AF_UNIX bind/connect and file-write
// enforcement, not just profile text. Skipped on non-darwin, when
// sandbox-exec is absent, when python3 is absent, or when the ambient
// os.TempDir() does not match the expected per-user T directory shape
// (e.g. under this repo's TMPDIR=/tmp go-test convention -- in that case
// darwinUserTempDirs() legitimately returns nil and there is no carve-out
// to exercise).
func TestSandboxExec_DarwinTempDirCarveOuts(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only sandbox-exec integration test")
	}
	skipIfNoSandboxExec(t)
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not found")
	}

	tmpdir := os.TempDir()
	if validateDarwinTempDir(tmpdir) == nil {
		t.Skipf("os.TempDir() = %q is not a valid per-user T directory shape; skipping (expected when TMPDIR is overridden, e.g. this repo's TMPDIR=/tmp go-test convention)", tmpdir)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}
	cfg := config.Default()
	profile := generateSBProfile(cfg, home)

	dir := t.TempDir()
	profilePath := filepath.Join(dir, "test.sb")
	if err := os.WriteFile(profilePath, []byte(profile), 0o644); err != nil {
		t.Fatalf("write profile: %v", err)
	}

	// Minimal, robust python3 script: performs each probe, catches OSError
	// individually so one denial doesn't abort the remaining probes, and
	// prints "key=ok" or "key=denied:<errno>" per line for the Go test to parse.
	script := `
import os, socket

def report(key, fn):
    try:
        fn()
        print(key + "=ok")
    except OSError as e:
        print(key + "=denied:" + str(e))

tmpdir = os.environ.get("TMPDIR", "/tmp")
pid = os.getpid()

tmp_sock_path = "/tmp/agentjail-shield-test-bind-%d.sock" % pid
tmpdir_sock_path = os.path.join(tmpdir, "agentjail-shield-test-bind2-%d.sock" % pid)

def bind_tmp():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        os.remove(tmp_sock_path)
    except OSError:
        pass
    s.bind(tmp_sock_path)
    s.listen(1)

def bindconnect_tmpdir():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        os.remove(tmpdir_sock_path)
    except OSError:
        pass
    s.bind(tmpdir_sock_path)
    s.listen(1)
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect(tmpdir_sock_path)

def write_tmpdir():
    p = os.path.join(tmpdir, "agentjail-shield-test-write-%d.txt" % pid)
    with open(p, "w") as f:
        f.write("x")

def write_vardb():
    p = "/private/var/db/agentjail-shield-test-%d.txt" % pid
    with open(p, "w") as f:
        f.write("x")

def connect_tmp():
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect(tmp_sock_path)

report("bind_tmp", bind_tmp)
report("bindconnect_tmpdir", bindconnect_tmpdir)
report("write_tmpdir", write_tmpdir)
report("write_vardb", write_vardb)
report("connect_tmp", connect_tmp)
`

	cmd := exec.Command(sandboxExecPath, "-f", profilePath, "/usr/bin/python3", "-c", script)
	cmd.Env = os.Environ()
	out, runErr := cmd.CombinedOutput()
	output := string(out)
	t.Logf("sandbox-exec output:\n%s", output)
	if runErr != nil {
		t.Logf("sandbox-exec exited non-zero (may be expected if a probe denial surfaces as a process error): %v", runErr)
	}

	results := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			results[parts[0]] = parts[1]
		}
	}

	check := func(key, label string, wantOK bool) {
		got, ok := results[key]
		if !ok {
			t.Errorf("%s: no result reported (script may have crashed before printing); full output:\n%s", label, output)
			return
		}
		isOK := got == "ok"
		if isOK != wantOK {
			t.Errorf("%s: got %q, want ok=%v", label, got, wantOK)
		}
	}

	check("bind_tmp", "(a) AF_UNIX bind in /tmp", true)
	check("bindconnect_tmpdir", "(b) AF_UNIX bind+connect in $TMPDIR", true)
	check("write_tmpdir", "(c) file-write in $TMPDIR", true)
	check("write_vardb", "(d) file-write to /private/var/db", false)
	check("connect_tmp", "(e) AF_UNIX connect to socket in /tmp", false)
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
