package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/keyring"
	"github.com/LuD1161/agentjail/internal/sshagent"
)

// ── Repair (ADR 0086-doctor-repairs-diagnosed) ──────────────────────────

// Membership of repairRegistry IS the definition of "safely repairable", so a
// new entry must be a deliberate edit here too. Shield, hooks, and the
// Protection attestation are absent on purpose.
func TestOnlyDiagnosedRepairsAreRegistered(t *testing.T) {
	want := map[repairID]bool{repairDaemon: true, repairPathShim: true, repairServiceDef: true, repairApparmorUserns: true}
	for id := range repairRegistry {
		if !want[id] {
			t.Errorf("unexpected repair %q registered — every repair needs an ADR entry naming why it is safe", id)
		}
	}
	for id := range want {
		if _, ok := repairRegistry[id]; !ok {
			t.Errorf("repair %q missing from the registry", id)
		}
	}
}

// The Protection section attests history; a repair there would rewrite the
// record rather than fix state.
func TestProtectionFindingsAreNeverRepairable(t *testing.T) {
	for _, c := range checkProtection(t.TempDir()) {
		if c.repair != "" {
			t.Errorf("protection check %q carries repair %q; the record must not be repairable", c.label, c.repair)
		}
	}
}

// A missing shield is an install action, not a repair.
func TestShieldFailureStaysAdviceOnly(t *testing.T) {
	for _, c := range checkShield(t.TempDir()) {
		if c.repair != "" {
			t.Errorf("shield check %q carries repair %q; want advice-only", c.label, c.repair)
		}
	}
}

// stubRepair builds a registry whose apply/recheck are observable.
func stubRepair(applyErr error, post checkStatus, calls *int) map[repairID]repairAction {
	return map[repairID]repairAction{
		repairDaemon: {
			label: "stub repair",
			apply: func(string) error { *calls++; return applyErr },
			recheck: func(string) doctorCheck {
				return doctorCheck{label: "Socket", status: post, detail: "post-repair state"}
			},
		},
	}
}

var failedDaemonCheck = doctorCheck{label: "Socket", status: statusFail, repair: repairDaemon}

func TestRepairPassAppliesAndVerifies(t *testing.T) {
	calls := 0
	out, _, code := captureOutput(t, func() int {
		return runRepairPass(t.TempDir(), stubRepair(nil, statusOK, &calls), []doctorCheck{failedDaemonCheck}, 0)
	})
	if calls != 1 {
		t.Fatalf("apply called %d times, want 1", calls)
	}
	if code != 0 {
		t.Errorf("exit = %d, want 0 for a verified repair\n%s", code, out)
	}
	if !strings.Contains(out, "Repaired and verified.") {
		t.Errorf("output does not report the verified repair:\n%s", out)
	}
}

func TestRepairPassFailedApplyIsLoudAndNonZero(t *testing.T) {
	calls := 0
	out, _, code := captureOutput(t, func() int {
		return runRepairPass(t.TempDir(), stubRepair(errors.New("launchctl exploded"), statusOK, &calls), []doctorCheck{failedDaemonCheck}, 0)
	})
	if code != 1 {
		t.Errorf("exit = %d, want 1 when a repair fails\n%s", code, out)
	}
	if !strings.Contains(out, "repair FAILED") || !strings.Contains(out, "launchctl exploded") {
		t.Errorf("a failed repair must name the failure:\n%s", out)
	}
	if strings.Contains(out, "Repaired and verified.") {
		t.Errorf("claimed success after a failed repair:\n%s", out)
	}
}

// The dangerous case: the repair returned nil but the check still fails.
// Reporting apply's return instead of the re-check would fake protection.
func TestRepairPassUnverifiedRepairIsNotSuccess(t *testing.T) {
	calls := 0
	out, _, code := captureOutput(t, func() int {
		return runRepairPass(t.TempDir(), stubRepair(nil, statusFail, &calls), []doctorCheck{failedDaemonCheck}, 0)
	})
	if code != 1 {
		t.Errorf("exit = %d, want 1 when the post-repair check still fails\n%s", code, out)
	}
	if !strings.Contains(out, "did NOT restore") {
		t.Errorf("output must say the repair did not take:\n%s", out)
	}
}

// Nothing failed => nothing is applied, even under --fix.
func TestRepairPassSkipsWhenChecksPass(t *testing.T) {
	calls := 0
	out, _, code := captureOutput(t, func() int {
		return runRepairPass(t.TempDir(), stubRepair(nil, statusOK, &calls), nil, 0)
	})
	if calls != 0 {
		t.Errorf("apply ran %d times with no failed check; a repair must be gated on its diagnosis", calls)
	}
	if code != 0 || !strings.Contains(out, "Nothing to repair") {
		t.Errorf("exit = %d, out = %q; want 0 and a no-op", code, out)
	}
}

// --fix must not paper over failures it cannot repair.
func TestRepairPassUnrepairableFailuresStillExitNonZero(t *testing.T) {
	calls := 0
	out, _, code := captureOutput(t, func() int {
		return runRepairPass(t.TempDir(), stubRepair(nil, statusOK, &calls), nil, 1)
	})
	if calls != 0 {
		t.Errorf("apply ran %d times, want 0", calls)
	}
	if code != 1 || !strings.Contains(out, "install --all") {
		t.Errorf("exit = %d, out = %q; want 1 and install advice", code, out)
	}
}

// Default doctor is diagnose-only: a failing repairable check mutates nothing.
func TestDoctorWithoutFixNeverMutates(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	calls := 0
	restore := repairRegistry
	repairRegistry = stubRepair(nil, statusOK, &calls)
	t.Cleanup(func() { repairRegistry = restore })

	out, _, code := captureOutput(t, func() int { return runDoctor(diagnoseOnly) })
	if calls != 0 {
		t.Errorf("doctor repaired %d thing(s) without --fix", calls)
	}
	if code != 1 {
		t.Errorf("exit = %d, want 1 on a home with no daemon socket\n%s", code, out)
	}
	if !strings.Contains(out, "doctor --fix") {
		t.Errorf("diagnose-only run should point at --fix:\n%s", out)
	}
}

// --fix on the AGE-212 shape (no daemon socket) reaches the daemon repair.
func TestDoctorFixRepairsTheDiagnosedDaemon(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	calls := 0
	restore := repairRegistry
	repairRegistry = stubRepair(nil, statusOK, &calls)
	t.Cleanup(func() { repairRegistry = restore })

	out, _, _ := captureOutput(t, func() int { return runDoctor(repairFailures) })
	if calls != 1 {
		t.Errorf("daemon repair applied %d times, want 1\n%s", calls, out)
	}
}

// ── Daemon liveness ─────────────────────────────────────────────────────

// A dial-and-close cannot tell a live daemon from a wedged one, and --fix
// gates a restart on this verdict.
func TestDaemonLivenessCheckGatesRepair(t *testing.T) {
	cases := []struct {
		name       string
		liveness   daemonLiveness
		wantStatus checkStatus
		wantRepair repairID
	}{
		{"healthy ping", daemonHealthy, statusOK, ""},
		{"socket absent", daemonSocketAbsent, statusFail, repairDaemon},
		{"nothing listening", daemonNoListener, statusFail, repairDaemon},
		{"connected but wedged", daemonUnresponsive, statusFail, repairDaemon},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := daemonLivenessCheck(tc.liveness, "/tmp/daemon.sock", errors.New("probe detail"))
			if c.status != tc.wantStatus {
				t.Errorf("status = %q, want %q", c.status, tc.wantStatus)
			}
			if c.repair != tc.wantRepair {
				t.Errorf("repair = %q, want %q", c.repair, tc.wantRepair)
			}
		})
	}
}

func TestDaemonVersionCheckDetectsSkew(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		liveness  daemonLiveness
		running   string
		installed string
		status    checkStatus
		repair    repairID
	}{
		{name: "matching", liveness: daemonHealthy, running: "v1.3.0", installed: "v1.3.0", status: statusOK},
		{name: "stale", liveness: daemonHealthy, running: "v1.2.0", installed: "v1.3.0", status: statusFail, repair: repairDaemon},
		{name: "old protocol", liveness: daemonHealthy, installed: "v1.3.0", status: statusFail, repair: repairDaemon},
		{name: "offline", liveness: daemonNoListener, installed: "v1.3.0", status: statusSkip},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := daemonVersionCheck(tc.liveness, tc.running, tc.installed)
			if got.status != tc.status || got.repair != tc.repair {
				t.Fatalf("check = %#v, want status=%q repair=%q", got, tc.status, tc.repair)
			}
		})
	}
}

// A shim the user never opted into must never be installed by a repair.
func TestPathShimRepairIsGatedOnRecordedConsent(t *testing.T) {
	home := t.TempDir()
	if c := pathShimCheck(home); c.status != statusSkip || c.repair != "" {
		t.Fatalf("no consent should read as a non-repairable skip, got status=%q repair=%q", c.status, c.repair)
	}
	if err := restorePathShim(home); err == nil {
		t.Error("restorePathShim installed a shim with no recorded opt-in")
	}
}

// The scoped AppArmor profile needs root once, so doctor --fix must refuse to
// load it unless the user recorded consent. See ADR 0104-shield-apparmor-userns.
func TestApparmorUsernsRepairIsGatedOnRecordedConsent(t *testing.T) {
	home := t.TempDir()
	if err := repairApparmorUsernsApply(home); err == nil {
		t.Error("repairApparmorUsernsApply loaded the profile with no recorded opt-in")
	}
}

func TestDoctorSSHAgentCheck(t *testing.T) {
	tests := []struct {
		name       string
		status     sshagent.Status
		wantStatus checkStatus
		wantSubstr string
	}{
		{
			name: "ready",
			status: sshagent.Status{
				Readiness: sshagent.ReadinessReady,
				KeyState:  sshagent.KeyStatePresent,
				KeyPaths:  []string{"/home/user/.ssh/id_ed25519"},
			},
			wantStatus: "ok",
			wantSubstr: "loaded",
		},
		{
			name: "keys on disk but agent has none loaded",
			status: sshagent.Status{
				Readiness: sshagent.ReadinessNoKeys,
				KeyState:  sshagent.KeyStatePresent,
				KeyPaths:  []string{"/home/user/.ssh/id_ed25519"},
			},
			wantStatus: "warn",
			wantSubstr: "ssh-add",
		},
		{
			name: "no agent reachable, keys on disk",
			status: sshagent.Status{
				Readiness: sshagent.ReadinessNoAgent,
				KeyState:  sshagent.KeyStatePresent,
				KeyPaths:  []string{"/home/user/.ssh/id_ed25519"},
			},
			wantStatus: "warn",
			wantSubstr: "ssh-add",
		},
		{
			name: "no keys on disk",
			status: sshagent.Status{
				Readiness: sshagent.ReadinessNoAgent,
				KeyState:  sshagent.KeyStateAbsent,
			},
			wantStatus: "skip",
			wantSubstr: "no ssh keys",
		},
		{
			name: "ready and pinned identity blind spot",
			status: sshagent.Status{
				Readiness:           sshagent.ReadinessReady,
				KeyState:            sshagent.KeyStatePresent,
				KeyPaths:            []string{"/home/user/.ssh/id_ed25519"},
				PinnedIdentityPaths: []string{"/home/user/.ssh/id_ed25519"},
			},
			wantStatus: "warn",
			wantSubstr: "IdentityFile=none",
		},
		{
			name: "deploy-key-only pinned, no id_* keys on disk - still warns, not skip",
			status: sshagent.Status{
				Readiness:           sshagent.ReadinessReady,
				KeyState:            sshagent.KeyStateAbsent,
				PinnedIdentityPaths: []string{"/home/user/.ssh/github_deploy"},
			},
			wantStatus: "warn",
			wantSubstr: "IdentityFile=none",
		},
		{
			name: "ready and not pinned",
			status: sshagent.Status{
				Readiness: sshagent.ReadinessReady,
				KeyState:  sshagent.KeyStatePresent,
				KeyPaths:  []string{"/home/user/.ssh/id_ed25519"},
			},
			wantStatus: "ok",
			wantSubstr: "loaded",
		},
		{
			name: "no keys on disk and not pinned",
			status: sshagent.Status{
				Readiness: sshagent.ReadinessNoAgent,
				KeyState:  sshagent.KeyStateAbsent,
			},
			wantStatus: "skip",
			wantSubstr: "no ssh keys",
		},
		{
			name: "shielded missing socket reports inactive Git-over-SSH capability",
			status: sshagent.Status{
				Execution: sshagent.ExecutionShielded,
				KeyState:  sshagent.KeyStateUnknown,
				Readiness: sshagent.ReadinessNoAgent,
			},
			wantStatus: "warn",
			wantSubstr: "not active",
		},
		{
			name: "shielded requested delegation with missing socket warns",
			status: sshagent.Status{
				Execution:  sshagent.ExecutionShielded,
				Delegation: sshagent.DelegationRequested,
				KeyState:   sshagent.KeyStateUnknown,
				Readiness:  sshagent.ReadinessNoAgent,
			},
			wantStatus: "warn",
			wantSubstr: "delegation was requested but is unavailable",
		},
		{
			name: "shielded requested delegation with stale socket warns",
			status: sshagent.Status{
				Execution:  sshagent.ExecutionShielded,
				Delegation: sshagent.DelegationRequested,
				KeyState:   sshagent.KeyStateUnknown,
				Readiness:  sshagent.ReadinessNoAgent,
				SockPath:   "/tmp/stale-agent.sock",
			},
			wantStatus: "warn",
			wantSubstr: "delegation was requested but the delegated SSH_AUTH_SOCK is unusable",
		},
		{
			name: "shielded empty agent warns",
			status: sshagent.Status{
				Execution: sshagent.ExecutionShielded,
				KeyState:  sshagent.KeyStateUnknown,
				Readiness: sshagent.ReadinessNoKeys,
				SockPath:  "/tmp/agent.sock",
			},
			wantStatus: "warn",
			wantSubstr: "no loaded identities",
		},
		{
			name: "shielded usable delegated agent warns about unrestricted signing authority",
			status: sshagent.Status{
				Execution:  sshagent.ExecutionShielded,
				Delegation: sshagent.DelegationRequested,
				KeyState:   sshagent.KeyStateUnknown,
				Readiness:  sshagent.ReadinessReady,
				SockPath:   "/tmp/agent.sock",
			},
			wantStatus: "warn",
			wantSubstr: "not host- or repository-scoped",
		},
		{
			name: "unshielded unreadable key directory is unknown, not skipped",
			status: sshagent.Status{
				KeyState:  sshagent.KeyStateUnknown,
				Readiness: sshagent.ReadinessNoAgent,
			},
			wantStatus: "warn",
			wantSubstr: "availability is unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := sshAgentCheck(tt.status)
			if c.label != "ssh-agent" {
				t.Errorf("label = %q, want %q", c.label, "ssh-agent")
			}
			if c.status != tt.wantStatus {
				t.Errorf("status = %q, want %q", c.status, tt.wantStatus)
			}
			if !strings.Contains(c.detail, tt.wantSubstr) {
				t.Errorf("detail = %q, want substring %q", c.detail, tt.wantSubstr)
			}
			if c.status == "fail" {
				t.Errorf("sshAgentCheck must never return status=fail (user env state, not an install defect)")
			}
		})
	}
}

// ── Body encryption posture (AGE-254, ADR 0092-persist-request-bodies) ──

// ErrKeychainLocked wraps ErrNoKeychain, so a wrong-order branch gives locked
// hosts the "nothing to unlock" advice. These are the two advices.
func TestBodyEncryptionPostureAdvice(t *testing.T) {
	for _, tc := range []struct {
		name       string
		posture    bodyKEKPosture
		err        error
		wantStatus checkStatus
		wantSubstr []string
		notSubstr  []string
	}{
		{
			name:       "keychain tier names the backend and the tier",
			posture:    bodyKEKPosture{tier: keyring.TierKeychain, backend: "secret-service"},
			err:        nil,
			wantStatus: statusOK,
			wantSubstr: []string{"secret-service", "os-keychain", "whole-$HOME backup"},
			notSubstr:  []string{"IN THE CLEAR", "REDUCED"},
		},
		{
			name:       "file-kek tier is ok but qualified",
			posture:    bodyKEKPosture{tier: keyring.TierFileKEK, backend: "file-kek"},
			err:        nil,
			wantStatus: statusOK,
			wantSubstr: []string{"REDUCED", "file-kek", "~/.config/agentjail/kek", "0600", "does NOT survive a whole-$HOME backup"},
			notSubstr:  []string{"IN THE CLEAR"},
		},
		{
			name:       "memory tier warns it is not durable",
			posture:    bodyKEKPosture{tier: keyring.TierMemory, backend: "memory"},
			err:        nil,
			wantStatus: statusWarn,
			wantSubstr: []string{"memory", "unreadable"},
		},
		{
			name:       "unknown tier refuses to state a posture",
			posture:    bodyKEKPosture{tier: keyring.Tier("wat"), backend: "stub"},
			err:        nil,
			wantStatus: statusWarn,
			wantSubstr: []string{"unknown tier"},
		},
		{
			name:       "locked advises unlocking",
			err:        fmt.Errorf("%w: default collection is locked", keyring.ErrKeychainLocked),
			wantStatus: statusWarn,
			wantSubstr: []string{"LOCKED", "unlock", "auto-unlock", "IN THE CLEAR"},
			notSubstr:  []string{"nothing to unlock"},
		},
		{
			name:       "absent advises there is nothing to unlock",
			err:        fmt.Errorf("%w: no session bus", keyring.ErrNoKeychain),
			wantStatus: statusWarn,
			wantSubstr: []string{"no OS keychain", "nothing to unlock", "IN THE CLEAR"},
			notSubstr:  []string{"auto-unlock"},
		},
		{
			name:       "unknown error still reports plaintext",
			err:        errors.New("dbus exploded"),
			wantStatus: statusWarn,
			wantSubstr: []string{"IN THE CLEAR"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := bodyEncryptionCheck(tc.posture, tc.err)
			if c.status != tc.wantStatus {
				t.Errorf("status = %q, want %q (detail: %s)", c.status, tc.wantStatus, c.detail)
			}
			for _, s := range tc.wantSubstr {
				if !strings.Contains(c.detail, s) {
					t.Errorf("detail missing %q: %s", s, c.detail)
				}
			}
			for _, s := range tc.notSubstr {
				if strings.Contains(c.detail, s) {
					t.Errorf("detail must not contain %q: %s", s, c.detail)
				}
			}
		})
	}
}

// A degraded posture is not a broken install: bodies still record, in the
// clear, and doctor must not start exiting non-zero for it.
func TestBodyEncryptionNeverGatesExitOrRepairs(t *testing.T) {
	for _, err := range []error{nil, keyring.ErrKeychainLocked, keyring.ErrNoKeychain, errors.New("boom")} {
		c := bodyEncryptionCheck(bodyKEKPosture{tier: keyring.TierKeychain, backend: "stub"}, err)
		if c.status == statusFail {
			t.Errorf("err=%v gave statusFail; degraded encryption must never fail doctor", err)
		}
		if c.repair != "" {
			t.Errorf("err=%v carries repair %q; want advice-only", err, c.repair)
		}
	}
	for _, s := range doctorSections() {
		if s.name == "Network Interception" && s.gatesExit {
			t.Fatal("Network Interception now gates exit; body encryption posture would fail the install")
		}
	}
}

// The keychain hands the same secret to a same-uid agent, so no detail may
// claim otherwise (keyring package doc; ADR 0092 D3 is the agent control).
func TestBodyEncryptionNeverClaimsAgentProtection(t *testing.T) {
	for _, tier := range []keyring.Tier{keyring.TierKeychain, keyring.TierFileKEK, keyring.TierMemory} {
		for _, err := range []error{nil, keyring.ErrKeychainLocked, keyring.ErrNoKeychain} {
			d := strings.ToLower(bodyEncryptionCheck(bodyKEKPosture{tier: tier, backend: "stub"}, err).detail)
			for _, banned := range []string{"from the agent", "against the agent", "protects the agent", "agent cannot read"} {
				if strings.Contains(d, banned) {
					t.Errorf("tier=%s err=%v detail implies protection against the agent (%q): %s", tier, err, banned, d)
				}
			}
		}
	}
}

// The anti-silent-downgrade guard (ADR 0097-linux-kek-fallback): a file KEK
// falls to a whole-$HOME backup, so its message may never read as a flat
// "encrypted". Deleting the caveat must break this test, not pass quietly.
func TestBodyEncryptionFileKEKStatesBackupLimitation(t *testing.T) {
	c := bodyEncryptionCheck(bodyKEKPosture{tier: keyring.TierFileKEK, backend: "file-kek"}, nil)

	if !strings.Contains(c.detail, "does NOT survive a whole-$HOME backup") {
		t.Fatalf("file-kek detail omits the whole-$HOME-backup limitation, which flattens it to an\n"+
			"equivalent of the keychain tier — the exact silent downgrade AGE-254 exists to prevent.\ndetail: %s", c.detail)
	}
	// The qualification is worthless if the key's location is not named.
	if !strings.Contains(c.detail, "~/.config/agentjail/kek") {
		t.Errorf("file-kek detail does not name the key file: %s", c.detail)
	}
	// Naming os-keychain as the stronger tier is honest; claiming to BE it is not.
	if !strings.HasPrefix(c.detail, "on, REDUCED (file-kek)") {
		t.Errorf("file-kek detail does not announce its reduced tier up front: %s", c.detail)
	}
}
