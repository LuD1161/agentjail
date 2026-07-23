package daemonapp

import (
	"os"
	"testing"
	"time"
)

func TestMaybeDowngrade_ShieldedFilesystemRule(t *testing.T) {
	tr := newShieldAttestTracker()
	now := time.Now()
	tr.attest(os.Getpid(), now) // this test process stands in for the shield

	// A filesystem rule + a descendant agent (self) → downgraded.
	na, wa, ok := tr.maybeDowngrade("deny", "command_policy/no-bash-touch-sensitive-path", "cat ~/.ssh/id_rsa", os.Getpid(), now)
	if !ok || na != "allow" || wa != "deny" {
		t.Fatalf("want allow/deny/true, got %s/%s/%v", na, wa, ok)
	}
}

func TestMaybeDowngrade_PrivilegeEscalationStrict(t *testing.T) {
	tr := newShieldAttestTracker()
	now := time.Now()
	tr.attest(os.Getpid(), now)

	// A filesystem rule the sandbox covers, but sudo escapes the agent's UID,
	// so the command must NOT be downgraded even when shielded.
	for _, cmd := range []string{"sudo cat /etc/master.passwd", "doas cat /etc/hosts", "x; sudo rm /etc/hosts", "cat /etc/x | sudo tee /etc/y"} {
		na, _, ok := tr.maybeDowngrade("deny", "command_policy/no-bash-touch-sensitive-path", cmd, os.Getpid(), now)
		if ok || na != "deny" {
			t.Fatalf("escalating cmd %q must stay deny, got %s/%v", cmd, na, ok)
		}
	}
	// A non-escalating command that merely mentions "sudo" as a substring is
	// still downgraded (token boundary, not substring).
	if _, _, ok := tr.maybeDowngrade("deny", "command_policy/no-bash-touch-sensitive-path", "cat ./sudoku/.env", os.Getpid(), now); !ok {
		t.Fatal("non-escalating command must still downgrade")
	}
}

func TestMaybeDowngrade_NonFilesystemRuleStrict(t *testing.T) {
	tr := newShieldAttestTracker()
	now := time.Now()
	tr.attest(os.Getpid(), now)

	// A non-filesystem rule stays deny even when shielded.
	na, _, ok := tr.maybeDowngrade("deny", "command_policy/no-sudo", "sudo whoami", os.Getpid(), now)
	if ok || na != "deny" {
		t.Fatalf("no-sudo must stay deny under shield, got %s/%v", na, ok)
	}
}

func TestMaybeDowngrade_UnshieldedStrict(t *testing.T) {
	tr := newShieldAttestTracker()
	now := time.Now()
	// No attestation for any ancestor → not shielded → strict.
	na, _, ok := tr.maybeDowngrade("deny", "command_policy/no-bash-touch-sensitive-path", "cat ~/.ssh/id_rsa", os.Getpid(), now)
	if ok || na != "deny" {
		t.Fatalf("unshielded must stay deny, got %s/%v", na, ok)
	}
}

func TestIsShielded_ExpiredAndDeadPruned(t *testing.T) {
	tr := newShieldAttestTracker()
	now := time.Now()
	tr.attest(os.Getpid(), now)

	// Past the TTL → pruned, not shielded.
	if tr.isShielded(os.Getpid(), now.Add(shieldAttestTTL+time.Minute)) {
		t.Fatal("expired attestation must not count as shielded")
	}
	// A PID that never existed as an ancestor → not shielded.
	tr.attest(os.Getpid(), now)
	if tr.isShielded(1, now) {
		t.Fatal("pid 1 must never be shielded")
	}
}
