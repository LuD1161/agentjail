package main

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/grantctl"
)

func setUpdateAudit(t *testing.T, fn func(grantctl.UpdateAuditStatus, string, string) error) {
	t.Helper()
	saved := updateAuditFn
	updateAuditFn = fn
	t.Cleanup(func() { updateAuditFn = saved })
}

func TestRollbackFailedUpdateReportsRecoveredActivation(t *testing.T) {
	var got struct {
		status  grantctl.UpdateAuditStatus
		version string
		goos    string
	}
	setUpdateAudit(t, func(status grantctl.UpdateAuditStatus, version, goos string) error {
		got.status, got.version, got.goos = status, version, goos
		return nil
	})

	if code := rollbackFailedUpdate(t.TempDir(), t.TempDir(), nil, "v1.4.0", "linux", errors.New("attestation failed"), nil); code != 1 {
		t.Fatalf("rollbackFailedUpdate() = %d, want 1", code)
	}
	if got.status != grantctl.UpdateAuditRolledBack || got.version != "v1.4.0" || got.goos != "linux" {
		t.Errorf("audit = (%q, %q, %q), want recovered update details", got.status, got.version, got.goos)
	}
}

func TestRollbackFailedUpdateReportsRollbackFailure(t *testing.T) {
	var got grantctl.UpdateAuditStatus
	setUpdateAudit(t, func(status grantctl.UpdateAuditStatus, _, _ string) error {
		got = status
		return nil
	})

	restartOld := func() error { return errors.New("previous daemon unavailable") }
	if code := rollbackFailedUpdate(t.TempDir(), t.TempDir(), nil, "v1.4.0", "linux", errors.New("attestation failed"), restartOld); code != 1 {
		t.Fatalf("rollbackFailedUpdate() = %d, want 1", code)
	}
	if got != grantctl.UpdateAuditRollbackFailed {
		t.Errorf("audit status = %q, want %q", got, grantctl.UpdateAuditRollbackFailed)
	}
}

func TestReportUpdateAuditDoesNotChangePrimaryOutcome(t *testing.T) {
	setUpdateAudit(t, func(grantctl.UpdateAuditStatus, string, string) error {
		return errors.New("audit store unavailable")
	})

	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	reportUpdateAudit(grantctl.UpdateAuditCompleted, "v1.4.0", "linux")
	_ = w.Close()
	os.Stderr = oldStderr
	var output bytes.Buffer
	_, _ = output.ReadFrom(r)
	_ = r.Close()
	if !strings.Contains(output.String(), "could not write update audit event") {
		t.Errorf("stderr = %q, want audit warning", output.String())
	}
}
