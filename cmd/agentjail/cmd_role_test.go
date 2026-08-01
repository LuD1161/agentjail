package main

import (
	"errors"
	"testing"
)

func stubRoleRestartBoundary(t *testing.T) {
	t.Helper()
	origHome := roleUserHomeDir
	origAuthorize := roleAuthorizeRestart
	origConfirm := roleConfirmRestart
	origRestart := roleRestartDaemon
	t.Cleanup(func() {
		roleUserHomeDir = origHome
		roleAuthorizeRestart = origAuthorize
		roleConfirmRestart = origConfirm
		roleRestartDaemon = origRestart
	})
	roleUserHomeDir = func() (string, error) { return "/home/agent", nil }
	roleAuthorizeRestart = func(string) error { return nil }
	roleConfirmRestart = func() bool { return true }
}

func TestRunDaemonRoleRestartUsesSupervisor(t *testing.T) {
	stubRoleRestartBoundary(t)
	var gotHome string
	roleRestartDaemon = func(home string) error {
		gotHome = home
		return nil
	}

	if got := runDaemonRole([]string{"restart"}); got != 0 {
		t.Fatalf("runDaemonRole(restart) = %d, want 0", got)
	}
	if gotHome != "/home/agent" {
		t.Fatalf("restart received home %q, want /home/agent", gotHome)
	}
}

func TestRunDaemonRoleRestartFailsWhenSupervisorFails(t *testing.T) {
	stubRoleRestartBoundary(t)
	roleRestartDaemon = func(string) error { return errors.New("launchd unavailable") }

	if got := runDaemonRole([]string{"restart"}); got != 1 {
		t.Fatalf("runDaemonRole(restart) = %d, want 1", got)
	}
}

func TestRunDaemonRoleRestartRequiresHostAuthorization(t *testing.T) {
	stubRoleRestartBoundary(t)
	roleAuthorizeRestart = func(string) error { return errors.New("permission denied") }
	confirmed := false
	roleConfirmRestart = func() bool {
		confirmed = true
		return true
	}
	restarted := false
	roleRestartDaemon = func(string) error {
		restarted = true
		return nil
	}

	if got := runDaemonRole([]string{"restart"}); got != 1 {
		t.Fatalf("runDaemonRole(restart) = %d, want 1", got)
	}
	if confirmed || restarted {
		t.Fatalf("authorization failure continued: confirmed=%v restarted=%v", confirmed, restarted)
	}
}

func TestRunDaemonRoleRestartRequiresHumanConfirmation(t *testing.T) {
	stubRoleRestartBoundary(t)
	roleConfirmRestart = func() bool { return false }
	restarted := false
	roleRestartDaemon = func(string) error {
		restarted = true
		return nil
	}

	if got := runDaemonRole([]string{"restart"}); got != 1 {
		t.Fatalf("runDaemonRole(restart) = %d, want 1", got)
	}
	if restarted {
		t.Fatal("restart ran after confirmation refusal")
	}
}
