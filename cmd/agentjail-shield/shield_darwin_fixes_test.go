//go:build darwin

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
)

// ---- FIX1: darwin env leak (ADR 0039) ----

// TestBuildBaseEnv_NonBlocklistedSecretDoesNotSurvive is the FIX1 regression
// test: an arbitrary, non-blocklisted, non-baseline env var (e.g. a secret a
// user exported ad hoc in their shell) must NOT reach the sandboxed agent's
// environment. Before FIX1, darwin called sandbox.StripEnv directly on the
// host environment -- a denylist that only catches known-bad names -- so
// MY_SECRET would have leaked straight through. buildBaseEnv now runs
// sandbox.BuildCleanEnv (allowlist) first.
func TestBuildBaseEnv_NonBlocklistedSecretDoesNotSurvive(t *testing.T) {
	hostEnv := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/Users/testuser",
		"MY_SECRET=super-sensitive-value",
		"SOME_RANDOM_TOKEN=abc123",
	}
	cfg := config.Default()
	got := buildBaseEnv(hostEnv, cfg)

	for _, kv := range got {
		if strings.HasPrefix(kv, "MY_SECRET=") {
			t.Errorf("MY_SECRET leaked into agent env: %v", got)
		}
		if strings.HasPrefix(kv, "SOME_RANDOM_TOKEN=") {
			t.Errorf("SOME_RANDOM_TOKEN leaked into agent env: %v", got)
		}
	}
	var sawPath bool
	for _, kv := range got {
		if strings.HasPrefix(kv, "PATH=") {
			sawPath = true
		}
	}
	if !sawPath {
		t.Errorf("expected allowlisted PATH to survive buildBaseEnv, got %v", got)
	}
}

// TestBuildBaseEnv_SSHAuthSockNotInBaseline documents FIX1's explicit
// non-goal: SSH_AUTH_SOCK is credential-bearing (an agent socket grants
// signing capability) and must stay out of EnvAllowlistBaseline. Users who
// need it opt in via secrets.env_passthrough.
func TestBuildBaseEnv_SSHAuthSockNotInBaseline(t *testing.T) {
	hostEnv := []string{"SSH_AUTH_SOCK=/tmp/ssh-agent.sock", "PATH=/usr/bin"}
	got := buildBaseEnv(hostEnv, config.Default())
	for _, kv := range got {
		if strings.HasPrefix(kv, "SSH_AUTH_SOCK=") {
			t.Errorf("SSH_AUTH_SOCK must not survive buildBaseEnv by default: %v", got)
		}
	}
}

// ---- FIX2: OAuth callback TCP bind (Approach A) ----

// TestGenerateSBProfile_OAuthCallbackBindPorts verifies that resolved OAuth
// callback ports (from ~/.claude/.credentials.json) get both a
// network-bind and network-inbound allow rule for local tcp on that exact
// port -- Approach A, shipped (see FIX2 in shield_contract.go /
// docs/adr/0039).
func TestGenerateSBProfile_OAuthCallbackBindPorts(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0700); err != nil {
		t.Fatal(err)
	}
	creds := map[string]any{
		"mcpOAuth": map[string]any{
			"linear|abc": map[string]string{"redirectUri": "http://localhost:52819/callback"},
		},
	}
	data, _ := json.Marshal(creds)
	if err := os.WriteFile(filepath.Join(home, ".claude", ".credentials.json"), data, 0600); err != nil {
		t.Fatal(err)
	}

	profile := generateSBProfile(config.Default(), home)

	if !strings.Contains(profile, `(allow network-bind
    (local tcp "*:52819"))`) {
		t.Errorf("profile missing network-bind allow for OAuth port 52819; got:\n%s", profile)
	}
	if !strings.Contains(profile, `(allow network-inbound
    (local tcp "*:52819"))`) {
		t.Errorf("profile missing network-inbound allow for OAuth port 52819; got:\n%s", profile)
	}
}

// TestGenerateSBProfile_NoOAuthPorts verifies no bind/inbound rules are
// emitted when there is no credentials file (common case: fresh install,
// no MCP OAuth yet).
func TestGenerateSBProfile_NoOAuthPorts(t *testing.T) {
	home := t.TempDir() // no .claude/.credentials.json
	profile := generateSBProfile(config.Default(), home)
	// The DNS UDP bind/inbound rule is always present ("(local udp ...)");
	// only the OAuth TCP bind/inbound rules ("(local tcp "*:<port>")") must
	// be absent when there is no credentials file.
	if strings.Contains(profile, `(local tcp "*:`) {
		t.Errorf("profile should not contain OAuth TCP bind rules with no credentials file; got:\n%s", profile)
	}
}

// ---- FIX2 (Approach B attempt): real sandbox-exec loopback-scope probe ----

// buildProbeBinary compiles the tiny TCP-bind probe helper used by the
// loopback-scope tests. Skips (not fails) if go build is unavailable.
func buildProbeBinary(t *testing.T) string {
	t.Helper()
	repoRoot := findRepoRoot(t)
	src := filepath.Join(repoRoot, "cmd", "agentjail-shield", "test", "bindprobe")
	if _, err := os.Stat(src); err != nil {
		t.Skip("bindprobe source not present")
	}
	out := filepath.Join(t.TempDir(), "bindprobe")
	cmd := exec.Command("go", "build", "-o", out, src)
	cmd.Dir = repoRoot
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Skipf("could not build bindprobe: %v", err)
	}
	return out
}

// runBindProbe runs the probe binary under sandbox-exec with the given sbpl
// profile body (already-complete .sb text) and address, returning
// "OK" / "DENIED:<err>" / raw stdout for inspection.
func runBindProbe(t *testing.T, profileBody, addr string) string {
	t.Helper()
	probe := buildProbeBinary(t)
	sbFile := filepath.Join(t.TempDir(), "probe.sb")
	if err := os.WriteFile(sbFile, []byte(profileBody), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(sandboxExecPath, "-f", sbFile, probe, addr)
	out, _ := cmd.CombinedOutput()
	return strings.TrimSpace(string(out))
}

// TestDarwinLoopbackScopedBindForm_NotEnforced is the FIX2 Approach-B
// attempt required by the plan: a REAL sandbox-exec integration test that
// tries the two candidate sbpl forms for a loopback-only TCP bind and
// records what actually happens.
//
//   - `(local ip "127.0.0.1:*")` -- rejected outright by sandbox-exec's
//     parser ("host must be * or localhost in network address"); not usable.
//   - `(local tcp "localhost:*")` -- parses, but measured to allow BOTH a
//     127.0.0.1 bind AND a 0.0.0.0 bind. It is NOT loopback-scoped; it is
//     equivalent (for enforcement purposes) to `"*:*"` with a fixed port
//     range of "any".
//
// Neither form enforces loopback-only, so per the plan's decision rule,
// Approach B is NOT shipped; Approach A (any-interface, per-port bind) ships
// instead -- see darwinCapabilities() and the OAuth bind rules in
// generateSBProfileWithIPs.
func TestDarwinLoopbackScopedBindForm_NotEnforced(t *testing.T) {
	skipIfNoSandboxExec(t)
	probe := buildProbeBinary(t)
	_ = probe

	localTCPProfile := `(version 1)
(allow default)
(deny network-bind)
(allow network-bind
    (local tcp "localhost:*"))
`
	loopbackOK := runBindProbe(t, localTCPProfile, "127.0.0.1:0")
	anyIfaceResult := runBindProbe(t, localTCPProfile, "0.0.0.0:0")

	t.Logf(`(local tcp "localhost:*"): 127.0.0.1:0 -> %s`, loopbackOK)
	t.Logf(`(local tcp "localhost:*"): 0.0.0.0:0 -> %s`, anyIfaceResult)

	if !strings.HasSuffix(loopbackOK, "=OK") {
		t.Fatalf(`(local tcp "localhost:*") unexpectedly denied a loopback bind: %s`, loopbackOK)
	}
	if !strings.HasSuffix(anyIfaceResult, "=OK") {
		t.Skipf(`(local tcp "localhost:*") DENIED a 0.0.0.0 bind (%s) -- this would mean the form IS loopback-scoped; re-evaluate shipping Approach B`, anyIfaceResult)
	}
	// Both succeeded: confirmed NOT loopback-scoped. This is the expected,
	// documented outcome that justifies shipping Approach A instead.
}

// TestDarwinLiteralIPBindForm_RejectedBySandboxExec confirms the other
// candidate form, `(local ip "127.0.0.1:*")`, is rejected by sandbox-exec's
// parser and therefore cannot be used at all (matches the existing
// documented sbpl limitation that only "*" and "localhost" are valid host
// components -- see resolveAllowedHosts's doc comment).
func TestDarwinLiteralIPBindForm_RejectedBySandboxExec(t *testing.T) {
	skipIfNoSandboxExec(t)
	profile := `(version 1)
(allow default)
(deny network-bind)
(allow network-bind
    (local ip "127.0.0.1:*"))
`
	sbFile := filepath.Join(t.TempDir(), "probe.sb")
	if err := os.WriteFile(sbFile, []byte(profile), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(sandboxExecPath, "-f", sbFile, "/bin/echo", "unused")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected sandbox-exec to reject literal-IP local form, but it ran: %s", out)
	}
	if !strings.Contains(string(out), "host must be") {
		t.Logf("sandbox-exec rejected the profile as expected, but with unexpected message: %s", out)
	}
}

// ---- FIX3: darwin per-file carve-outs (known_hosts) ----

// TestGenerateSBProfile_KnownHostsReadCarveOut is the FIX3 profile-string
// test: every ReadOnly PerFile grant in PerFileGrants() must render an
// explicit file-read* allow literal, appearing AFTER the ~/.ssh deny
// subpath (last-match-wins), and the ~/.ssh subpath deny itself must remain
// present (the carve-out is per-file, not a tree-wide re-allow).
func TestGenerateSBProfile_KnownHostsReadCarveOut(t *testing.T) {
	cfg := config.Default()
	home := "/Users/testuser"
	profile := generateSBProfile(cfg, home)

	for _, g := range PerFileGrants() {
		if !g.PerFile || g.Mode != ReadOnly {
			continue
		}
		wantAllow := fmt.Sprintf("(allow file-read*\n    (literal %q))", home+"/"+g.Path)
		if !strings.Contains(profile, wantAllow) {
			t.Errorf("profile missing per-file read allow for %s; want substring:\n%s\ngot:\n%s", g.Path, wantAllow, profile)
		}
		// No file-write* literal for the same path.
		wantNoWrite := fmt.Sprintf("(allow file-write*\n    (literal %q))", home+"/"+g.Path)
		if strings.Contains(profile, wantNoWrite) {
			t.Errorf("profile must NOT contain a file-write* allow for ReadOnly grant %s", g.Path)
		}
	}

	// The ~/.ssh subpath deny must still be present (per-file carve-out does
	// not reopen the whole tree).
	if !strings.Contains(profile, fmt.Sprintf("(subpath %q)", home+"/.ssh")) {
		t.Error("profile missing ~/.ssh subpath deny after per-file carve-out was added")
	}
}

// TestSandboxEnforcesKnownHostsReadOnly is the FIX3 real sandbox-exec
// enforcement test: using a fake $HOME under t.TempDir() (never the real
// ~/.ssh), verify:
//   - reading known_hosts succeeds
//   - reading id_rsa fails (EPERM)
//   - creating a new file under .ssh fails (EPERM)
func TestSandboxEnforcesKnownHostsReadOnly(t *testing.T) {
	skipIfNoSandboxExec(t)
	shieldBin := buildShieldBinary(t)

	fakeHome := t.TempDir()
	sshDir := filepath.Join(fakeHome, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatal(err)
	}
	knownHosts := filepath.Join(sshDir, "known_hosts")
	if err := os.WriteFile(knownHosts, []byte("example.com ssh-ed25519 AAAA...\n"), 0600); err != nil {
		t.Fatal(err)
	}
	idRSA := filepath.Join(sshDir, "id_rsa")
	if err := os.WriteFile(idRSA, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n"), 0600); err != nil {
		t.Fatal(err)
	}

	env := append(os.Environ(), "HOME="+fakeHome)

	// (a) read known_hosts must succeed.
	readKnown := exec.Command(shieldBin, "--no-netproxy", "--",
		"sh", "-c", fmt.Sprintf("cat %s >/dev/null 2>&1; echo exit=$?", knownHosts))
	readKnown.Env = env
	out, _ := readKnown.CombinedOutput()
	t.Logf("read known_hosts output: %s", out)
	if !strings.Contains(string(out), "exit=0") {
		t.Errorf("FAILED: reading known_hosts under sandbox did not succeed; output: %s", out)
	}

	// (b) read id_rsa must fail.
	readID := exec.Command(shieldBin, "--no-netproxy", "--",
		"sh", "-c", fmt.Sprintf("cat %s >/dev/null 2>&1; echo exit=$?", idRSA))
	readID.Env = env
	out2, _ := readID.CombinedOutput()
	t.Logf("read id_rsa output: %s", out2)
	if strings.Contains(string(out2), "exit=0") {
		t.Errorf("FAILED: reading id_rsa under sandbox unexpectedly succeeded; output: %s", out2)
	}

	// (c) creating a new file under .ssh must fail.
	newFile := filepath.Join(sshDir, "agentjail-shield-fix3-test")
	_ = os.Remove(newFile)
	t.Cleanup(func() { os.Remove(newFile) })
	writeNew := exec.Command(shieldBin, "--no-netproxy", "--",
		"sh", "-c", fmt.Sprintf("printf x > %s 2>&1; echo exit=$?", newFile))
	writeNew.Env = env
	out3, _ := writeNew.CombinedOutput()
	t.Logf("write new .ssh file output: %s", out3)
	if _, statErr := os.Stat(newFile); statErr == nil {
		t.Errorf("FAILED: a new file was created under ~/.ssh despite the sandbox: %s", newFile)
	}
}

// ---- FIX4: darwin capability rendering (parity/capability test) ----

// TestDarwinCapability_HonorsPatternsGrantsAndFallbackPorts is the darwin
// half of FIX4's capability/parity test: the generated profile must render
// every SensitiveFilePatterns() entry, every ReadOnly PerFile PathGrant
// literal, and EXACTLY NoNetproxyFallbackPorts() as the port-only-mode
// wildcard allow set -- no more, no fewer.
func TestDarwinCapability_HonorsPatternsGrantsAndFallbackPorts(t *testing.T) {
	cfg := config.Default()
	home := "/Users/testuser"
	profile := generateSBProfile(cfg, home) // port-only (no netproxy) mode

	for _, p := range SensitiveFilePatterns() {
		if !strings.Contains(profile, p.Regex) {
			t.Errorf("profile missing pattern %q from SensitiveFilePatterns()", p.Regex)
		}
	}
	for _, g := range PerFileGrants() {
		if !g.PerFile || g.Mode != ReadOnly {
			continue
		}
		wantAllow := fmt.Sprintf("(allow file-read*\n    (literal %q))", home+"/"+g.Path)
		if !strings.Contains(profile, wantAllow) {
			t.Errorf("profile missing per-file grant literal for %s", g.Path)
		}
	}
	for _, port := range NoNetproxyFallbackPorts() {
		want := fmt.Sprintf(`(remote tcp "*:%d")`, port)
		if !strings.Contains(profile, want) {
			t.Errorf("profile missing fallback port allow %s", want)
		}
	}
	// Exactly the contract's ports -- no extra wildcard TCP allow beyond 80/443.
	extraTCP := strings.Count(profile, `(remote tcp "*:`)
	if extraTCP != len(NoNetproxyFallbackPorts()) {
		t.Errorf("profile has %d wildcard (remote tcp *:PORT) allows, want exactly %d (%v)",
			extraTCP, len(NoNetproxyFallbackPorts()), NoNetproxyFallbackPorts())
	}

	// darwin's named non-parity: loopback-scoped bind is Unsupported (see
	// darwinCapabilities' doc comment); filename-pattern-deny is NOT listed
	// as Unsupported because darwin fully honors it above.
	caps := darwinCapabilities()
	if _, ok := caps.Unsupported[CapFilenamePatternDeny]; ok {
		t.Error("darwin should NOT list CapFilenamePatternDeny as Unsupported -- it renders every pattern")
	}
	if _, ok := caps.Unsupported[CapLoopbackScopedBind]; !ok {
		t.Error("darwin should name CapLoopbackScopedBind as Unsupported (Approach A ships, not loopback-scoped)")
	}
}
