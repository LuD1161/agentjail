package projectpolicy

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
)

// writeOverlay creates <dir>/.agentjail/policy.yaml with the given content.
func writeOverlay(t *testing.T, dir, content string) string {
	t.Helper()
	pdir := filepath.Join(dir, ProjectDirName)
	if err := os.MkdirAll(pdir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(pdir, ProjectPolicyFile)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write overlay: %v", err)
	}
	return path
}

func markGitRoot(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
}

func TestFindOverlay_AscendsToGitRoot(t *testing.T) {
	repo := t.TempDir()
	markGitRoot(t, repo)
	overlayPath := writeOverlay(t, repo, "network:\n  allowed_hosts: [db.internal]\n")
	sub := filepath.Join(repo, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	o, err := FindOverlay(sub, "/home/nobody")
	if err != nil {
		t.Fatalf("FindOverlay: %v", err)
	}
	if o == nil || o.Path != overlayPath {
		t.Fatalf("expected to find %s from a subdir, got %+v", overlayPath, o)
	}
	if o.ContentHash == "" {
		t.Error("expected a content hash")
	}
}

func TestFindOverlay_DoesNotEscapeGitRoot(t *testing.T) {
	outer := t.TempDir()
	writeOverlay(t, outer, "network:\n  allowed_hosts: [evil.com]\n") // ABOVE the repo
	repo := filepath.Join(outer, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	markGitRoot(t, repo) // repo is the git root; outer's overlay must be invisible

	o, err := FindOverlay(repo, "/home/nobody")
	if err != nil {
		t.Fatalf("FindOverlay: %v", err)
	}
	if o != nil {
		t.Fatalf("must not find an overlay above the git root, got %s", o.Path)
	}
}

func TestFindOverlay_SkipsHomeDir(t *testing.T) {
	home := t.TempDir()
	writeOverlay(t, home, "network:\n  allowed_hosts: [x]\n") // this is the GLOBAL ~/.agentjail
	o, err := FindOverlay(home, home)
	if err != nil {
		t.Fatalf("FindOverlay: %v", err)
	}
	if o != nil {
		t.Fatalf("home ~/.agentjail must never be treated as a project overlay, got %s", o.Path)
	}
}

func TestFindOverlay_NotInRepoOnlyChecksStart(t *testing.T) {
	base := t.TempDir() // no .git anywhere
	writeOverlay(t, base, "network:\n  allowed_hosts: [y]\n")
	sub := filepath.Join(base, "child")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	// From the child (no repo), we must NOT ascend to base.
	if o, _ := FindOverlay(sub, "/home/nobody"); o != nil {
		t.Errorf("outside a repo, must not ascend past startDir; found %s", o.Path)
	}
	// From base itself, it is found.
	if o, _ := FindOverlay(base, "/home/nobody"); o == nil {
		t.Error("overlay in startDir should be found even outside a repo")
	}
}

func TestTrustStore_HashGated(t *testing.T) {
	dir := t.TempDir()
	tsPath := TrustStorePath(dir)
	ts, err := LoadTrustStore(tsPath)
	if err != nil {
		t.Fatalf("load empty: %v", err)
	}
	o := &Overlay{Path: "/repo/.agentjail/policy.yaml", ContentHash: "hash-v1"}
	if ts.IsTrusted(o) {
		t.Fatal("nothing should be trusted initially")
	}
	ts.Trust(o)
	if !ts.IsTrusted(o) {
		t.Fatal("overlay should be trusted after Trust")
	}
	// Same path, different hash (file edited) -> NOT trusted.
	edited := &Overlay{Path: o.Path, ContentHash: "hash-v2"}
	if ts.IsTrusted(edited) {
		t.Fatal("edited overlay (hash changed) must revoke trust")
	}
	// Persist + reload.
	if err := ts.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	ts2, err := LoadTrustStore(tsPath)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !ts2.IsTrusted(o) {
		t.Fatal("trust must survive save/reload")
	}
	if !ts2.Untrust(o.Path) || ts2.IsTrusted(o) {
		t.Fatal("Untrust should remove the entry")
	}
}

func TestResolve_UntrustedIgnored(t *testing.T) {
	repo := t.TempDir()
	markGitRoot(t, repo)
	writeOverlay(t, repo, "network:\n  allowed_hosts: [db.internal]\n")
	base := config.Default()
	tsPath := TrustStorePath(t.TempDir())

	res, err := Resolve(base, repo, "/home/nobody", tsPath)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Status != StatusUntrusted {
		t.Errorf("status = %q; want ignored_untrusted", res.Status)
	}
	if slices.Contains(res.Config.EffectiveAllowedHosts(), "db.internal") {
		t.Error("untrusted overlay must NOT widen the allowlist")
	}
}

func TestResolve_TrustedApplied(t *testing.T) {
	repo := t.TempDir()
	markGitRoot(t, repo)
	writeOverlay(t, repo, "network:\n  allowed_hosts: [db.internal]\n")
	base := config.Default()

	// Trust the overlay first.
	o, err := FindOverlay(repo, "/home/nobody")
	if err != nil || o == nil {
		t.Fatalf("find: %v (%v)", err, o)
	}
	tsPath := TrustStorePath(t.TempDir())
	ts, _ := LoadTrustStore(tsPath)
	ts.Trust(o)
	if err := ts.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	res, err := Resolve(base, repo, "/home/nobody", tsPath)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Status != StatusApplied {
		t.Fatalf("status = %q; want applied", res.Status)
	}
	eff := res.Config.EffectiveAllowedHosts()
	if !slices.Contains(eff, "db.internal") {
		t.Errorf("trusted overlay host missing from effective hosts: %v", eff)
	}
	if !slices.Contains(eff, "api.anthropic.com") {
		t.Errorf("essentials must remain after overlay merge: %v", eff)
	}
}

func TestResolve_TrustedThenEditedRevoked(t *testing.T) {
	repo := t.TempDir()
	markGitRoot(t, repo)
	writeOverlay(t, repo, "network:\n  allowed_hosts: [db.internal]\n")
	base := config.Default()
	o, _ := FindOverlay(repo, "/home/nobody")
	tsPath := TrustStorePath(t.TempDir())
	ts, _ := LoadTrustStore(tsPath)
	ts.Trust(o)
	_ = ts.Save()

	// Edit the overlay after trusting it -> hash changes -> trust revoked.
	writeOverlay(t, repo, "network:\n  allowed_hosts: [db.internal, evil.com]\n")
	res, err := Resolve(base, repo, "/home/nobody", tsPath)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Status != StatusUntrusted {
		t.Errorf("editing after trust must flip to untrusted, got %q", res.Status)
	}
	if slices.Contains(res.Config.EffectiveAllowedHosts(), "evil.com") {
		t.Error("edited-after-trust overlay must not apply")
	}
}

func TestResolve_NoOverlay(t *testing.T) {
	repo := t.TempDir()
	markGitRoot(t, repo)
	base := config.Default()
	res, err := Resolve(base, repo, "/home/nobody", TrustStorePath(t.TempDir()))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Status != StatusNoOverlay || res.Config != base {
		t.Errorf("no overlay should return base unchanged, got status=%q", res.Status)
	}
}
