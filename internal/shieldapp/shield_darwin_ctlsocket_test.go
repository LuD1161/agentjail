//go:build darwin

package shieldapp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	config "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/grantctl"
	"github.com/LuD1161/agentjail/internal/proxyctl"
	"github.com/LuD1161/agentjail/internal/sandbox"
)

// These tests guard the ordering invariant that AGE-216 proved is load-bearing.
//
// They cannot prove the sandbox actually denies anything -- macOS refuses to
// nest a Seatbelt sandbox, so sandbox-exec cannot run inside a shielded session
// or in CI. The execution proof lives in test/sbpl-probe/ (real binary, real
// AF_UNIX connect, clean macOS guest). What these tests DO is fail fast if the
// rule ORDER regresses, which is the thing that silently broke: a control-socket
// deny emitted before an allow naming the same path loses (last-match-wins), and
// the unfiltered (deny network*) catch-all does NOT backstop it, because it does
// not override an earlier filtered allow.

const testHome = "/Users/testuser"

func ctlProfile(t *testing.T) string {
	t.Helper()
	return generateSBProfileWithNetproxy(&config.PolicyConfig{}, testHome)
}

func ctlProfileWithSSHAuthSock(t *testing.T, sock string) string {
	t.Helper()
	return generateSBProfileWithTrustedSSHAuthSock(&config.PolicyConfig{}, testHome, nil, true, sandbox.SSHAuthSock{Path: sock})
}

// Every control socket must carry an explicit deny. secrets.sock had none until
// AGE-216: it was covered only by the catch-all, while ADR 0067 claimed the
// profile denied "the control socket paths".
func TestDarwinEveryControlSocketHasExplicitDeny(t *testing.T) {
	profile := ctlProfile(t)
	for _, p := range ControlSocketPaths(testHome) {
		want := fmt.Sprintf("(deny network-outbound\n    (literal %q))", p)
		if !strings.Contains(profile, want) {
			t.Errorf("profile missing explicit deny for control socket %s\nwant rule:\n%s", p, want)
		}
	}
}

// The regression that mattered: a deny is only the final word if no later allow
// names the same path. Assert every control-socket deny is emitted after the
// last (allow network-outbound ...) in the profile.
func TestDarwinControlSocketDeniesEmittedAfterAllNetworkAllows(t *testing.T) {
	profile := ctlProfile(t)

	lastAllow := strings.LastIndex(profile, "(allow network-outbound")
	if lastAllow == -1 {
		t.Fatal("no (allow network-outbound ...) in profile; test would be vacuous")
	}
	for _, p := range ControlSocketPaths(testHome) {
		deny := fmt.Sprintf("(deny network-outbound\n    (literal %q))", p)
		at := strings.Index(profile, deny)
		if at == -1 {
			t.Errorf("no deny emitted for %s", p)
			continue
		}
		if at < lastAllow {
			t.Errorf("deny for %s is emitted BEFORE a later (allow network-outbound ...) "+
				"(deny at %d, last allow at %d). sbpl is last-match-wins among same-specificity "+
				"rules, so that later allow would override this deny and the (deny network*) "+
				"catch-all would NOT backstop it. Emit control-socket denies last.", p, at, lastAllow)
		}
	}
}

// SSH_AUTH_SOCK is attacker-influenced in principle (it is read from the
// shield's env at generation time). An allow naming a control socket must never
// be emitted, independent of ordering.
func TestDarwinSSHAuthSockGuardSuppressesControlSocketAllow(t *testing.T) {
	for _, sock := range ControlSocketPaths(testHome) {
		profile := ctlProfileWithSSHAuthSock(t, sock)
		bad := fmt.Sprintf("(allow network-outbound\n    (path %q))", sock)
		if strings.Contains(profile, bad) {
			t.Errorf("SSH_AUTH_SOCK=%s produced an allow rule for a control socket:\n%s", sock, bad)
		}
	}
	// A path inside the control-socket dir, even one not yet bound.
	if strings.Contains(ctlProfileWithSSHAuthSock(t, proxyctl.ControlSocketDirForHome(testHome)+"/planted.sock"), "planted.sock") {
		t.Error("a path inside the control-socket dir was allowed into the profile")
	}
}

// Guard the guard: a legitimate ssh-agent socket must still be allowed, or the
// suppression test above could pass simply because nothing is ever emitted.
func TestDarwinSSHAuthSockLegitimatePathStillAllowed(t *testing.T) {
	legit := "/private/tmp/com.apple.launchd.abc123/Listeners"
	profile := ctlProfileWithSSHAuthSock(t, legit)
	want := fmt.Sprintf("(allow network-outbound\n    (path %q))", legit)
	if !strings.Contains(profile, want) {
		t.Errorf("legitimate SSH_AUTH_SOCK %s was not allowed; the guard is over-broad and ssh would break", legit)
	}
}

// ControlSocketPaths is the single source of truth (ADR 0034). If a socket is
// added to the control plane and not to this list, the deny is silently missing
// -- exactly how secrets.sock ended up uncovered.
func TestDarwinControlSocketPathsCoversKnownSockets(t *testing.T) {
	got := ControlSocketPaths(testHome)
	want := []string{
		proxyctl.ControlSocketPathForHome(testHome),
		grantctl.ControlSocketPathForHome(testHome),
		sandbox.SecretsSocketPathForHome(testHome),
	}
	if len(got) != len(want) {
		t.Fatalf("ControlSocketPaths returned %d paths, want %d: %v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("ControlSocketPaths[%d] = %s, want %s", i, got[i], w)
		}
	}
	// secrets.sock is NOT under run/ -- guard the layout assumption that a
	// single subpath rule would silently get wrong.
	if strings.HasPrefix(sandbox.SecretsSocketPathForHome(testHome), proxyctl.ControlSocketDirForHome(testHome)) {
		t.Error("secrets.sock is now under the run/ dir; the deny rules could be collapsed, but check the probe first")
	}
}

// TestDarwinIsControlSocketPathTmpSymlinkCanonicalization proves the
// resolvePathBestEffort fix by execution: an unbound control socket named
// through an ALIASED PARENT must still be recognized.
//
// This test deliberately targets secrets.sock, and deliberately passes home in
// its resolved (/private/tmp) form while naming the socket in its aliased
// (/tmp) form. Both choices are load-bearing -- an earlier version of this test
// used netproxy-ctl.sock with home in /tmp form and could not fail:
//
//   - secrets.sock lives at ~/.agentjail/secrets.sock, OUTSIDE the control-socket
//     dir, so it is guarded ONLY by the exact-path comparison. The two run/ sockets
//     are caught by the separate "inside ctlDir" check, which resolves an EXISTING
//     directory and therefore succeeds even with a broken path resolver -- masking
//     the bug entirely.
//   - naming home and the probe path through the SAME alias makes both sides fall
//     back to filepath.Clean identically, so they compare equal by accident.
//
// The socket file itself is never created: EvalSymlinks fails on a missing leaf,
// which is exactly the case (profile generated before the socket is bound) the
// old Clean-only fallback got wrong. Mutation-tested -- reverting
// resolvePathBestEffort to the Clean-only fallback fails this test.
func TestDarwinIsControlSocketPathTmpSymlinkCanonicalization(t *testing.T) {
	fi, err := os.Lstat("/tmp")
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Skip("/tmp is not a symlink on this system; the aliasing this test targets does not apply")
	}

	// Home in RESOLVED form, so the control-socket path the guard compares
	// against is /private/tmp/... while the probe below names /tmp/... .
	aliasedHome, err := os.MkdirTemp("/tmp", "age216-ctlsock-home-")
	if err != nil {
		t.Fatalf("MkdirTemp under /tmp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(aliasedHome) })

	resolvedHome, err := filepath.EvalSymlinks(aliasedHome)
	if err != nil {
		t.Fatalf("EvalSymlinks(%s): %v", aliasedHome, err)
	}
	if resolvedHome == aliasedHome {
		t.Skipf("%s did not resolve to a distinct path; nothing to canonicalize", aliasedHome)
	}

	// The parent must exist so a correct resolver has an ancestor to resolve;
	// the socket leaf must NOT, so EvalSymlinks on the full path fails.
	if err := os.MkdirAll(filepath.Join(resolvedHome, ".agentjail"), 0o700); err != nil {
		t.Fatalf("MkdirAll ~/.agentjail: %v", err)
	}
	aliasedSecrets := sandbox.SecretsSocketPathForHome(aliasedHome)
	if _, err := os.Lstat(aliasedSecrets); !os.IsNotExist(err) {
		t.Fatalf("precondition: %s must not exist (err=%v)", aliasedSecrets, err)
	}

	// The guard resolves home to /private/tmp/...; we hand it the /tmp/... alias
	// of the same socket. A Clean-only resolver leaves these unequal and, since
	// secrets.sock is outside the ctlDir, returns false -- emitting an
	// (allow network-outbound) for the credential broker's socket.
	if !isControlSocketPath(aliasedSecrets, resolvedHome) {
		t.Errorf("isControlSocketPath(%q, home=%q) = false, want true.\n"+
			"An unbound secrets.sock named through the /tmp alias evaded the guard; "+
			"SSH_AUTH_SOCK set to this path would emit an allow rule for the credential broker.",
			aliasedSecrets, resolvedHome)
	}
}

func TestDarwinIsControlSocketPath(t *testing.T) {
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"netproxy ctl", proxyctl.ControlSocketPathForHome(testHome), true},
		{"daemon ctl", grantctl.ControlSocketPathForHome(testHome), true},
		{"secrets", sandbox.SecretsSocketPathForHome(testHome), true},
		{"inside ctl dir", proxyctl.ControlSocketDirForHome(testHome) + "/other.sock", true},
		{"unclean traversal into ctl dir", testHome + "/.agentjail/run/../run/daemon-ctl.sock", true},
		{"legit launchd listener", "/private/tmp/com.apple.launchd.x/Listeners", false},
		{"unrelated home path", testHome + "/.ssh/agent.sock", false},
		// testHome ("/Users/testuser") does not exist, so these exercise the
		// nonexistent-final-component path through resolvePathBestEffort:
		// EvalSymlinks fails on the leaf (and on every ancestor here, since
		// none of /Users/testuser/... exists either), so resolution falls
		// back to filepath.Clean -- the guard must still catch these.
		{"not-yet-bound socket inside ctl dir", proxyctl.ControlSocketDirForHome(testHome) + "/never-bound.sock", true},
		{"unclean secrets socket path", testHome + "/.agentjail/./secrets.sock", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isControlSocketPath(tc.path, testHome); got != tc.want {
				t.Errorf("isControlSocketPath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}
