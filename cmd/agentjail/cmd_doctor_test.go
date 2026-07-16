package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/sshagent"
)

// ── Repair (ADR 0086-doctor-repairs-diagnosed) ──────────────────────────

// Membership of repairRegistry IS the definition of "safely repairable", so a
// new entry must be a deliberate edit here too. Shield, hooks, and the
// Protection attestation are absent on purpose.
func TestOnlyDiagnosedRepairsAreRegistered(t *testing.T) {
	want := map[repairID]bool{repairDaemon: true, repairPathShim: true, repairServiceDef: true}
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
				Readiness:  sshagent.ReadinessReady,
				KeysOnDisk: true,
				KeyPaths:   []string{"/home/user/.ssh/id_ed25519"},
			},
			wantStatus: "ok",
			wantSubstr: "loaded",
		},
		{
			name: "keys on disk but agent has none loaded",
			status: sshagent.Status{
				Readiness:  sshagent.ReadinessNoKeys,
				KeysOnDisk: true,
				KeyPaths:   []string{"/home/user/.ssh/id_ed25519"},
			},
			wantStatus: "warn",
			wantSubstr: "ssh-add",
		},
		{
			name: "no agent reachable, keys on disk",
			status: sshagent.Status{
				Readiness:  sshagent.ReadinessNoAgent,
				KeysOnDisk: true,
				KeyPaths:   []string{"/home/user/.ssh/id_ed25519"},
			},
			wantStatus: "warn",
			wantSubstr: "ssh-add",
		},
		{
			name: "no keys on disk",
			status: sshagent.Status{
				Readiness:  sshagent.ReadinessNoAgent,
				KeysOnDisk: false,
			},
			wantStatus: "skip",
			wantSubstr: "no ssh keys",
		},
		{
			name: "ready and pinned identity blind spot",
			status: sshagent.Status{
				Readiness:           sshagent.ReadinessReady,
				KeysOnDisk:          true,
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
				KeysOnDisk:          false,
				PinnedIdentityPaths: []string{"/home/user/.ssh/github_deploy"},
			},
			wantStatus: "warn",
			wantSubstr: "IdentityFile=none",
		},
		{
			name: "ready and not pinned",
			status: sshagent.Status{
				Readiness:  sshagent.ReadinessReady,
				KeysOnDisk: true,
				KeyPaths:   []string{"/home/user/.ssh/id_ed25519"},
			},
			wantStatus: "ok",
			wantSubstr: "loaded",
		},
		{
			name: "no keys on disk and not pinned",
			status: sshagent.Status{
				Readiness:  sshagent.ReadinessNoAgent,
				KeysOnDisk: false,
			},
			wantStatus: "skip",
			wantSubstr: "no ssh keys",
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
