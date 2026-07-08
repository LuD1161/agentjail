//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// ---- P3: isSensitiveMCPTarget / findTopLevelDir ----

// TestFindTopLevelDir verifies the existing directory-walk helper behaves as
// documented -- used as a baseline before exercising the sensitivity check
// that consumes its output.
func TestFindTopLevelDir(t *testing.T) {
	cases := []struct {
		name, dir, parent, want string
	}{
		{"nested venv bin", "/home/user/.headroom-venv/bin", "/home/user", "/home/user/.headroom-venv"},
		{"direct child", "/home/user/.ssh", "/home/user", "/home/user/.ssh"},
		{"not under parent", "/opt/tool/bin", "/home/user", ""},
		{"parent itself", "/home/user", "/home/user", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := findTopLevelDir(c.dir, c.parent); got != c.want {
				t.Errorf("findTopLevelDir(%q, %q) = %q, want %q", c.dir, c.parent, got, c.want)
			}
		})
	}
}

// TestIsSensitiveMCPTarget_RejectsPoisonedSSHAWSGnupgPaths is the regression
// guard for P3: an MCP server command resolving into ~/.ssh, ~/.aws, or
// ~/.gnupg (directly, or into a subdirectory) must be flagged sensitive so
// the caller refuses to grant it, even though ~/.claude.json (the source of
// mcpServers[].command) is agent-writable.
func TestIsSensitiveMCPTarget_RejectsPoisonedSSHAWSGnupgPaths(t *testing.T) {
	home := "/home/user"
	sensitive := []string{
		"/home/user/.ssh",
		"/home/user/.ssh/anything",
		"/home/user/.aws",
		"/home/user/.aws/credentials-dir",
		"/home/user/.gnupg",
		"/home/user/.gnupg/private-keys-v1.d",
	}
	for _, target := range sensitive {
		t.Run(target, func(t *testing.T) {
			if !isSensitiveMCPTarget(target, home) {
				t.Errorf("isSensitiveMCPTarget(%q, %q) = false, want true", target, home)
			}
		})
	}
}

// TestIsSensitiveMCPTarget_AllowsLegitimateMCPDirs verifies the check does
// not false-positive on ordinary MCP server install locations (venvs, npm
// global installs, etc.) that legitimately need to be granted.
func TestIsSensitiveMCPTarget_AllowsLegitimateMCPDirs(t *testing.T) {
	home := "/home/user"
	legit := []string{
		"/home/user/.headroom-venv",
		"/home/user/.npm-global",
		"/home/user/mcp-servers/foo",
		"/opt/mcp-tool/bin",
		"/usr/local/bin",
		home, // the home dir itself is never "sensitive" on its own
	}
	for _, target := range legit {
		t.Run(target, func(t *testing.T) {
			if isSensitiveMCPTarget(target, home) {
				t.Errorf("isSensitiveMCPTarget(%q, %q) = true, want false", target, home)
			}
		})
	}
}

// TestIsSensitiveMCPTarget_EmptyInputs guards against nil-home/empty-target
// panics -- both should safely report "not sensitive" rather than crash the
// shield at launch.
func TestIsSensitiveMCPTarget_EmptyInputs(t *testing.T) {
	if isSensitiveMCPTarget("", "/home/user") {
		t.Error("isSensitiveMCPTarget(\"\", home) = true, want false")
	}
	if isSensitiveMCPTarget("/home/user/.ssh", "") {
		t.Error("isSensitiveMCPTarget(target, \"\") = true, want false")
	}
}

// ---- P4: allowConfigDirExcludingCredentials ----

// TestAllowConfigDirExcludingCredentials_SkipsCredentialSubdirs verifies the
// child-by-child ~/.config grant skips every ConfigCredentialSubdirs() entry
// (gh, gcloud, containers, git) while still granting legitimate MCP-tool
// subdirectories of ~/.config.
func TestAllowConfigDirExcludingCredentials_SkipsCredentialSubdirs(t *testing.T) {
	configDir := t.TempDir()

	// Credential-bearing subdirs that must NOT be granted.
	denied := ConfigCredentialSubdirs()
	for _, d := range denied {
		if err := os.MkdirAll(filepath.Join(configDir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A legitimate MCP tool config dir that MUST be granted.
	legit := filepath.Join(configDir, "some-mcp-tool")
	if err := os.MkdirAll(legit, 0o755); err != nil {
		t.Fatal(err)
	}

	var granted []string
	fakeAllow := func(path string, access uint64) error {
		granted = append(granted, path)
		return nil
	}

	allowConfigDirExcludingCredentials(configDir, fakeAllow, 0)

	grantedSet := make(map[string]bool, len(granted))
	for _, g := range granted {
		grantedSet[g] = true
	}

	for _, d := range denied {
		p := filepath.Join(configDir, d)
		if grantedSet[p] {
			t.Errorf("credential subdir %s was granted, want skipped", p)
		}
	}
	if !grantedSet[legit] {
		t.Errorf("legitimate subdir %s was not granted, want granted", legit)
	}
}

// TestAllowConfigDirExcludingCredentials_MissingDirIsNoop verifies a
// nonexistent ~/.config does not panic or error -- it should behave like
// allowPath's own "path absent → skip" semantics.
func TestAllowConfigDirExcludingCredentials_MissingDirIsNoop(t *testing.T) {
	called := false
	fakeAllow := func(path string, access uint64) error {
		called = true
		return nil
	}
	allowConfigDirExcludingCredentials(filepath.Join(t.TempDir(), "does-not-exist"), fakeAllow, 0)
	if called {
		t.Error("allowPath was called for a nonexistent ~/.config; want no-op")
	}
}
