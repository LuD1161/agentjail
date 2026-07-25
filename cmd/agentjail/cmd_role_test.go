package main

import (
	"errors"
	"testing"
)

func TestRunDaemonRoleRestartUsesSupervisor(t *testing.T) {
	origHome := roleUserHomeDir
	origRestart := roleRestartDaemon
	t.Cleanup(func() {
		roleUserHomeDir = origHome
		roleRestartDaemon = origRestart
	})

	roleUserHomeDir = func() (string, error) { return "/home/agent", nil }
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
	origHome := roleUserHomeDir
	origRestart := roleRestartDaemon
	t.Cleanup(func() {
		roleUserHomeDir = origHome
		roleRestartDaemon = origRestart
	})

	roleUserHomeDir = func() (string, error) { return "/home/agent", nil }
	roleRestartDaemon = func(string) error { return errors.New("launchd unavailable") }

	if got := runDaemonRole([]string{"restart"}); got != 1 {
		t.Fatalf("runDaemonRole(restart) = %d, want 1", got)
	}
}
