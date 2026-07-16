//go:build darwin

package shieldapp

import (
	"fmt"
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

// Every control socket must carry an explicit deny. secrets.sock had none until
// AGE-216: it was covered only by the catch-all, while ADR 0067 claimed the
// profile denied "the control socket paths".
func TestDarwinEveryControlSocketHasExplicitDeny(t *testing.T) {
	profile := ctlProfile(t)
	for _, p := range controlSocketPaths(testHome) {
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
	for _, p := range controlSocketPaths(testHome) {
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
	for _, sock := range controlSocketPaths(testHome) {
		t.Setenv("SSH_AUTH_SOCK", sock)
		profile := ctlProfile(t)
		bad := fmt.Sprintf("(allow network-outbound\n    (path %q))", sock)
		if strings.Contains(profile, bad) {
			t.Errorf("SSH_AUTH_SOCK=%s produced an allow rule for a control socket:\n%s", sock, bad)
		}
	}
	// A path inside the control-socket dir, even one not yet bound.
	t.Setenv("SSH_AUTH_SOCK", proxyctl.ControlSocketDirForHome(testHome)+"/planted.sock")
	if strings.Contains(ctlProfile(t), "planted.sock") {
		t.Error("a path inside the control-socket dir was allowed into the profile")
	}
}

// Guard the guard: a legitimate ssh-agent socket must still be allowed, or the
// suppression test above could pass simply because nothing is ever emitted.
func TestDarwinSSHAuthSockLegitimatePathStillAllowed(t *testing.T) {
	legit := "/private/tmp/com.apple.launchd.abc123/Listeners"
	t.Setenv("SSH_AUTH_SOCK", legit)
	profile := ctlProfile(t)
	want := fmt.Sprintf("(allow network-outbound\n    (path %q))", legit)
	if !strings.Contains(profile, want) {
		t.Errorf("legitimate SSH_AUTH_SOCK %s was not allowed; the guard is over-broad and ssh would break", legit)
	}
}

// controlSocketPaths is the single source of truth (ADR 0034). If a socket is
// added to the control plane and not to this list, the deny is silently missing
// -- exactly how secrets.sock ended up uncovered.
func TestDarwinControlSocketPathsCoversKnownSockets(t *testing.T) {
	got := controlSocketPaths(testHome)
	want := []string{
		proxyctl.ControlSocketPathForHome(testHome),
		grantctl.ControlSocketPathForHome(testHome),
		sandbox.SecretsSocketPathForHome(testHome),
	}
	if len(got) != len(want) {
		t.Fatalf("controlSocketPaths returned %d paths, want %d: %v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("controlSocketPaths[%d] = %s, want %s", i, got[i], w)
		}
	}
	// secrets.sock is NOT under run/ -- guard the layout assumption that a
	// single subpath rule would silently get wrong.
	if strings.HasPrefix(sandbox.SecretsSocketPathForHome(testHome), proxyctl.ControlSocketDirForHome(testHome)) {
		t.Error("secrets.sock is now under the run/ dir; the deny rules could be collapsed, but check the probe first")
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isControlSocketPath(tc.path, testHome); got != tc.want {
				t.Errorf("isControlSocketPath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}
