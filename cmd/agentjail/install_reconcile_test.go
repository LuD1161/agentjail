package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestReinstallAdoptsHealthyInstallationWithoutRestart(t *testing.T) {
	for _, payload := range []installationPayloadState{installationMatching, installationNewer} {
		state := installationState{PayloadState: payload, InstalledStatusSupported: true, RolesReady: true, ServiceReady: true, PolicyReady: true, CoreRulesReady: true, DaemonMatchesInstall: true}
		called := false
		err := reconcileDaemonInstallationState(t.TempDir(), io.Discard, nil, state, func(string, io.Writer, []string) error { called = true; return nil })
		if err != nil || called {
			t.Fatalf("healthy %s was replaced/restarted: called=%v err=%v", payload, called, err)
		}
	}
}

func TestReinstallRepairsUnhealthyMatchingInstallation(t *testing.T) {
	state := installationState{PayloadState: installationMatching, RolesReady: true, ServiceReady: true}
	called := false
	err := reconcileDaemonInstallationState(t.TempDir(), io.Discard, nil, state, func(string, io.Writer, []string) error { called = true; return nil })
	if err != nil || !called {
		t.Fatalf("unhealthy daemon was not repaired: called=%v err=%v", called, err)
	}
}

func TestReinstallRepairsMissingPolicyOrCoreRules(t *testing.T) {
	for _, missing := range []string{"policy", "rules"} {
		state := installationState{PayloadState: installationMatching, InstalledStatusSupported: true, RolesReady: true, ServiceReady: true, PolicyReady: true, CoreRulesReady: true, DaemonMatchesInstall: true}
		if missing == "policy" {
			state.PolicyReady = false
		} else {
			state.CoreRulesReady = false
		}
		called := false
		err := reconcileDaemonInstallationState(t.TempDir(), io.Discard, nil, state, func(string, io.Writer, []string) error { called = true; return nil })
		if err != nil || !called {
			t.Fatalf("missing %s did not trigger repair: called=%v err=%v", missing, called, err)
		}
	}
}

func TestReinstallDoesNotDowngradeNewerUnhealthyInstallation(t *testing.T) {
	state := installationState{PayloadState: installationNewer}
	called := false
	err := reconcileDaemonInstallationState(t.TempDir(), io.Discard, nil, state, func(string, io.Writer, []string) error { called = true; return nil })
	if err == nil || called {
		t.Fatalf("newer installation overwritten: called=%v err=%v", called, err)
	}
}

func TestFinishLocalInstallWiresCLIPathAndClearsRetirement(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SHELL", "/bin/zsh")
	t.Setenv("ZDOTDIR", "")
	t.Setenv("AGENTJAIL_NO_MODIFY_PATH", "")
	if err := retireInstallDir(filepath.Join(home, ".agentjail"), false); err != nil {
		t.Fatal(err)
	}
	if err := finishLocalInstall(home, []string{"--all", "--with-cli-path"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, ".agentjail", uninstallReceiptName)); !os.IsNotExist(err) {
		t.Fatalf("uninstall intent survived explicit setup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".zshrc")); err != nil {
		t.Fatalf("CLI PATH flag was ignored: %v", err)
	}
}
