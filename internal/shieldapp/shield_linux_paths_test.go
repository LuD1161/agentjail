//go:build linux

package shieldapp

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

// ---- cwd-encloses-home guard (Linux shield read-leak fix) ----

// TestCwdEnclosesHome verifies the guard that stops a wholesale cwd grant from
// swallowing the protected home subtree (~/.ssh etc.) when the shield is
// launched from $HOME or an ancestor of it.
func TestCwdEnclosesHome(t *testing.T) {
	const home = "/home/user"
	cases := []struct {
		name, cwd, home string
		want            bool
	}{
		{"cwd is home", "/home/user", home, true},
		{"cwd is home trailing slash", "/home/user/", home, true},
		{"cwd is ancestor /home", "/home", home, true},
		{"cwd is root", "/", home, true},
		{"cwd is a project under home", "/home/user/work/demo", home, false},
		{"cwd is a sibling dir", "/home/other", home, false},
		{"cwd is /tmp", "/tmp", home, false},
		{"cwd prefix-but-not-ancestor", "/home/user2", home, false},
		{"empty home", "/home/user", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := cwdEnclosesHome(c.cwd, c.home); got != c.want {
				t.Errorf("cwdEnclosesHome(%q, %q) = %v, want %v", c.cwd, c.home, got, c.want)
			}
		})
	}
}

// TestVisibleHomeChildren verifies the $HOME-workspace enumeration used by the
// cwd==home path: non-hidden children are granted, all dotfiles/dotdirs (where
// credentials live) are excluded, and the dir flag is reported correctly.
func TestVisibleHomeChildren(t *testing.T) {
	home := t.TempDir()
	// visible entries (granted)
	for _, d := range []string{"myproject", "Documents"} {
		if err := os.Mkdir(filepath.Join(home, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, "notes.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// hidden entries (must be excluded — this is the security invariant)
	for _, d := range []string{".ssh", ".aws", ".gnupg", ".config", ".claude"} {
		if err := os.Mkdir(filepath.Join(home, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{".netrc", ".npmrc", ".git-credentials"} {
		if err := os.WriteFile(filepath.Join(home, f), []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	got, err := visibleHomeChildren(home)
	if err != nil {
		t.Fatalf("visibleHomeChildren: %v", err)
	}
	byName := map[string]bool{}
	for _, c := range got {
		byName[filepath.Base(c.path)] = c.isDir
	}
	wantDir := map[string]bool{"myproject": true, "Documents": true, "notes.txt": false}
	if len(byName) != len(wantDir) {
		t.Fatalf("granted %v, want exactly %v", byName, wantDir)
	}
	for name, isDir := range wantDir {
		d, ok := byName[name]
		if !ok {
			t.Errorf("%q should be granted but wasn't", name)
		} else if d != isDir {
			t.Errorf("%q isDir=%v, want %v", name, d, isDir)
		}
	}
	for _, secret := range []string{".ssh", ".aws", ".gnupg", ".config", ".claude", ".netrc", ".npmrc", ".git-credentials"} {
		if _, leaked := byName[secret]; leaked {
			t.Errorf("SECURITY: hidden entry %q was granted as workspace", secret)
		}
	}
}

// ---- AGE-241: worktree / submodule gitdir grants ----

// gitGrantPaths flattens grants to paths for comparison.
func gitGrantPaths(gs []gitGrant) []string {
	var out []string
	for _, g := range gs {
		out = append(out, g.path)
	}
	return out
}

// worktreeFixture builds a main repo with a linked worktree and returns both
// checkout roots plus the main .git and the per-worktree gitdir.
func worktreeFixture(t *testing.T, root string) (main, wt, mainGit, wtGitdir string) {
	t.Helper()
	main = filepath.Join(root, "main")
	mainGit = filepath.Join(main, ".git")
	wtGitdir = filepath.Join(mainGit, "worktrees", "wt")
	wt = filepath.Join(root, "wt")
	for _, d := range []string{wtGitdir, filepath.Join(wt, "sub", "deeper")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(wtGitdir, "commondir"), []byte("../..\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: "+wtGitdir+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return main, wt, mainGit, wtGitdir
}

// TestGitDirGrants_WorktreeRoot guards the base AGE-241 case: the real gitdir
// and the main .git it points on to via commondir must both be granted.
func TestGitDirGrants_WorktreeRoot(t *testing.T) {
	_, wt, mainGit, wtGitdir := worktreeFixture(t, t.TempDir())
	got := gitGrantPaths(gitDirGrants(wt, "/home/user", ""))
	want := []string{filepath.Join(wt, ".git"), resolveSymlinks(wtGitdir), resolveSymlinks(mainGit)}
	if len(got) != len(want) {
		t.Fatalf("gitDirGrants(worktree root) = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("grant[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestGitDirGrants_WorktreeSubdir guards the discovery walk: git resolves its
// repo by ascending from cwd, so a cwd BELOW the worktree root must still grant
// the gitdir. Without the walk this returns nil and every git command fails.
func TestGitDirGrants_WorktreeSubdir(t *testing.T) {
	_, wt, mainGit, wtGitdir := worktreeFixture(t, t.TempDir())
	for _, sub := range []string{"sub", "sub/deeper"} {
		t.Run(sub, func(t *testing.T) {
			cwd := filepath.Join(wt, filepath.FromSlash(sub))
			got := gitGrantPaths(gitDirGrants(cwd, "/home/user", ""))
			want := []string{filepath.Join(wt, ".git"), resolveSymlinks(wtGitdir), resolveSymlinks(mainGit)}
			if len(got) != len(want) {
				t.Fatalf("gitDirGrants(%s) = %v, want %v", sub, got, want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Errorf("grant[%d] = %q, want %q", i, got[i], want[i])
				}
			}
		})
	}
}

// TestGitDirGrants_PointerFileIsFileScoped guards that the .git pointer is
// granted file-scoped: a dir-scoped mask on a regular file makes
// landlock_add_rule fail with EINVAL, silently dropping the grant.
func TestGitDirGrants_PointerFileIsFileScoped(t *testing.T) {
	_, wt, _, _ := worktreeFixture(t, t.TempDir())
	got := gitDirGrants(filepath.Join(wt, "sub"), "/home/user", "")
	if len(got) == 0 {
		t.Fatal("no grants")
	}
	if got[0].path != filepath.Join(wt, ".git") || got[0].isDir {
		t.Errorf("pointer grant = %+v, want the .git file with isDir=false", got[0])
	}
	for _, g := range got[1:] {
		if !g.isDir {
			t.Errorf("gitdir grant %q marked isDir=false, want dir-scoped", g.path)
		}
	}
}

// TestGitDirGrants_OrdinaryCloneRootNeedsNothing guards that the common case
// takes no extra grant: .git is a directory inside cwd, already covered.
func TestGitDirGrants_OrdinaryCloneRootNeedsNothing(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "main")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := gitDirGrants(repo, "/home/user", ""); got != nil {
		t.Errorf("gitDirGrants(ordinary clone root) = %v, want nil", got)
	}
}

// TestGitDirGrants_OrdinaryCloneSubdir guards that an ancestor's .git directory
// is granted: the cwd grant covers only the subdir, not the repo root's .git.
func TestGitDirGrants_OrdinaryCloneSubdir(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "main")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(repo, "sub", "deeper")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	got := gitDirGrants(sub, "/home/user", "")
	if len(got) != 1 || got[0].path != filepath.Join(repo, ".git") || !got[0].isDir {
		t.Errorf("gitDirGrants(clone subdir) = %+v, want the repo .git dir", got)
	}
}

// TestGitDirGrants_WalkStopsAtHome guards that discovery never ascends into
// $HOME or above: a ~/.git dotfiles repo is the home allowlist's business.
func TestGitDirGrants_WalkStopsAtHome(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	cwd := filepath.Join(home, "project", "sub")
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := gitDirGrants(cwd, home, ""); len(got) != 0 {
		t.Errorf("SECURITY: discovery ascended to $HOME and granted %v", gitGrantPaths(got))
	}
}

// TestGitDirGrants_NotARepo guards that a cwd with no repo above it yields none.
func TestGitDirGrants_NotARepo(t *testing.T) {
	if got := gitDirGrants(t.TempDir(), "/home/user", ""); got != nil {
		t.Errorf("gitDirGrants(no .git) = %v, want nil", got)
	}
}

// TestGitDirGrants_RelativeGitdirSubmodule covers the submodule shape, whose
// .git file holds a path relative to the submodule root.
func TestGitDirGrants_RelativeGitdirSubmodule(t *testing.T) {
	root := t.TempDir()
	super := filepath.Join(root, "super")
	modGit := filepath.Join(super, ".git", "modules", "lib")
	sub := filepath.Join(super, "lib")
	for _, d := range []string{modGit, sub} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(sub, ".git"), []byte("gitdir: ../.git/modules/lib\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := gitGrantPaths(gitDirGrants(sub, "/home/user", ""))
	want := []string{filepath.Join(sub, ".git"), resolveSymlinks(modGit)}
	if len(got) != len(want) || got[1] != want[1] {
		t.Errorf("gitDirGrants(submodule) = %v, want %v", got, want)
	}
}

// TestGitDirGrants_ExplicitGitDirEnv covers GIT_DIR taking precedence over the
// .git file, per git's own resolution order.
func TestGitDirGrants_ExplicitGitDirEnv(t *testing.T) {
	root := t.TempDir()
	elsewhere := filepath.Join(root, "elsewhere.git")
	if err := os.MkdirAll(elsewhere, 0o755); err != nil {
		t.Fatal(err)
	}
	got := gitGrantPaths(gitDirGrants(filepath.Join(root, "work"), "/home/user", elsewhere))
	if len(got) != 1 || got[0] != resolveSymlinks(elsewhere) {
		t.Errorf("gitDirGrants(GIT_DIR) = %v, want [%s]", got, elsewhere)
	}
}

// TestGitDirGrants_RefusesPoisonedPointer is the security guard: a .git file is
// writable by anything that can write the checkout, so a pointer aimed at $HOME
// or a credential dir must be refused rather than followed into a wide grant.
func TestGitDirGrants_RefusesPoisonedPointer(t *testing.T) {
	home := t.TempDir()
	for _, target := range []string{home, filepath.Dir(home), "/", filepath.Join(home, ".ssh")} {
		t.Run(target, func(t *testing.T) {
			wt := filepath.Join(t.TempDir(), "wt")
			if err := os.MkdirAll(wt, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: "+target+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			for _, g := range gitDirGrants(wt, home, "") {
				if g.path == target {
					t.Errorf("SECURITY: poisoned .git pointing at %q was granted", target)
				}
			}
		})
	}
}

// TestSafeGitGrant verifies the pointer-target guard in isolation.
func TestSafeGitGrant(t *testing.T) {
	const home = "/home/user"
	cases := []struct {
		name, path string
		want       bool
	}{
		{"normal gitdir", "/home/user/work/main/.git/worktrees/wt", true},
		{"is home", home, false},
		{"ancestor of home", "/home", false},
		{"root", "/", false},
		{"ssh dir", "/home/user/.ssh", false},
		{"aws subdir", "/home/user/.aws/x", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := safeGitGrant(c.path, home); got != c.want {
				t.Errorf("safeGitGrant(%q, %q) = %v, want %v", c.path, home, got, c.want)
			}
		})
	}
}
