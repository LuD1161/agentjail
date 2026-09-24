package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/LuD1161/agentjail/internal/selfupdate"
)

func TestInstallationPayloadClassification(t *testing.T) {
	for _, test := range []struct {
		name, candidate, installed string
		matches                    bool
		want                       installationPayloadState
	}{
		{"identical dev payload", "dev", "dev", true, installationMatching},
		{"identical release", "v1.8.2", "v1.8.2", true, installationMatching},
		{"older CLI", "v1.8.2", "v1.7.0", false, installationOlder},
		{"newer CLI", "v1.7.0", "v1.8.2", false, installationNewer},
		{"same version different payload", "v1.8.2", "v1.8.2", false, installationDifferent},
		{"unidentified existing CLI", "v1.8.2", "", false, installationUnknown},
		{"unidentified dev build", "dev", "v1.8.2", false, installationUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := classifyInstallationPayload(test.matches, test.candidate, test.installed)
			if got != test.want {
				t.Fatalf("state = %q, want %q", got, test.want)
			}
		})
	}
}

func TestInstallationInspectsCanonicalPayloadWithoutExecutingIt(t *testing.T) {
	home := t.TempDir()
	candidate := filepath.Join(t.TempDir(), cliBinaryName)
	binDir := filepath.Join(home, ".agentjail", "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{filepath.Dir(candidate), binDir} {
		for _, name := range []string{cliBinaryName, hookBinaryName} {
			if err := os.WriteFile(filepath.Join(directory, name), []byte(name), 0o700); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := selfupdate.EnsureRoleSymlinks(binDir); err != nil {
		t.Fatal(err)
	}
	spec := daemonServiceSpec(home)
	if err := os.MkdirAll(filepath.Dir(spec.path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(spec.path, []byte(spec.content), 0o600); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(home, ".agentjail", "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("custom policy"), 0o600); err != nil {
		t.Fatal(err)
	}
	rulesDir := filepath.Join(home, ".agentjail", "rules")
	if err := installCoreRules(rulesDir); err != nil {
		t.Fatal(err)
	}
	state := inspectInstallationState(home, candidate, "v1.8.2", func(string) (installedCLIStatus, error) {
		t.Fatal("identical installed payload must not be executed to identify it")
		return installedCLIStatus{}, nil
	})
	if state.PayloadState != installationMatching || !state.RolesReady || !state.ServiceReady || !state.PolicyReady || !state.CoreRulesReady || !state.InstalledStatusSupported || state.InstalledVersion != "v1.8.2" {
		t.Fatalf("installed payload was not adopted: %+v", state)
	}
	if state.DaemonMatchesInstall {
		t.Fatal("on-disk bytes must not attest a running daemon")
	}
	if err := os.Remove(policyPath); err != nil {
		t.Fatal(err)
	}
	state = inspectInstallationState(home, candidate, "v1.8.2", nil)
	if state.PolicyReady || !state.CoreRulesReady {
		t.Fatalf("missing policy passed setup readiness: %+v", state)
	}
	if err := os.WriteFile(policyPath, []byte("custom policy"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name := range allCoreRuleBytes() {
		path := filepath.Join(rulesDir, name+".rego")
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		state = inspectInstallationState(home, candidate, "v1.8.2", nil)
		if state.CoreRulesReady || !state.PolicyReady {
			t.Fatalf("missing core rule %q passed readiness: %+v", name, state)
		}
		if err := installCoreRules(rulesDir); err != nil {
			t.Fatal(err)
		}
	}
	customRule := filepath.Join(rulesDir, "custom.rego")
	if err := os.WriteFile(customRule, []byte("custom rule"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !inspectInstallationState(home, candidate, "v1.8.2", nil).CoreRulesReady {
		t.Fatal("user rules must not prevent adoption")
	}
	for name := range allCoreRuleBytes() {
		if err := os.WriteFile(filepath.Join(rulesDir, name+".rego"), []byte("stale managed rule"), 0o600); err != nil {
			t.Fatal(err)
		}
		break
	}
	if inspectInstallationState(home, candidate, "v1.8.2", nil).CoreRulesReady {
		t.Fatal("stale managed core rules were adopted")
	}
	if err := os.WriteFile(filepath.Join(binDir, hookBinaryName), []byte("stale-hook"), 0o700); err != nil {
		t.Fatal(err)
	}
	state = inspectInstallationState(home, candidate, "v1.8.2", func(string) (installedCLIStatus, error) { return installedCLIStatus{Version: "v1.8.2"}, nil })
	if state.PayloadState != installationDifferent || state.HookPayloadMatches {
		t.Fatalf("mixed hook/CLI install reported current: %+v", state)
	}
}

func TestInstallationNewerCLIUsesItsOwnVersionedReadiness(t *testing.T) {
	home := t.TempDir()
	binDir := filepath.Join(home, ".agentjail", "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(binDir, cliBinaryName)
	own := installationState{
		ProtocolVersion: installationStateProtocolVersion, PayloadState: installationMatching,
		CandidateVersion: "v1.9.0", InstalledVersion: "v1.9.0", DaemonVersion: "v1.9.0",
		CLIPresent: true, CLIPayloadMatches: true, HookPayloadMatches: true, InstalledStatusSupported: true,
		RolesReady: true, ServiceReady: true, PolicyReady: true, CoreRulesReady: true, DaemonMatchesInstall: true,
	}
	status := installedCLIStatus{ProtocolVersion: statusReportProtocolVersion, Version: "v1.9.0", Installation: &own}
	data, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\n[ \"$2\" = status ] || exit 3\nprintf '%s\\n' '"+string(data)+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	spec := daemonServiceSpec(home)
	if err := os.MkdirAll(filepath.Dir(spec.path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(spec.path, []byte("newer version's service definition"), 0o600); err != nil {
		t.Fatal(err)
	}
	state := inspectInstallationState(home, "/older-app/agentjail", "v1.8.2", readInstalledCLIStatus)
	if state.PayloadState != installationNewer || !state.readyForAdoption() {
		t.Fatalf("older template rejected a newer CLI's compatible projection: %+v", state)
	}
	if state.CLIPayloadMatches || state.HookPayloadMatches {
		t.Fatal("newer adoption must not claim a match to the older bundle")
	}
	for _, test := range []struct {
		name   string
		change func(*installedCLIStatus)
	}{
		{"missing projection", func(s *installedCLIStatus) { s.Installation = nil }},
		{"future contract", func(s *installedCLIStatus) { s.Installation.ProtocolVersion++ }},
		{"version mismatch", func(s *installedCLIStatus) { s.Installation.InstalledVersion = "v1.8.2" }},
		{"foreign candidate", func(s *installedCLIStatus) { s.Installation.CandidateVersion = "v1.8.2" }},
		{"unidentified CLI", func(s *installedCLIStatus) { s.Installation.CLIPayloadMatches = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			ownCopy := own
			statusCopy := status
			statusCopy.Installation = &ownCopy
			test.change(&statusCopy)
			state := inspectInstallationState(home, "/older-app/agentjail", "v1.8.2", func(string) (installedCLIStatus, error) { return statusCopy, nil })
			if state.PayloadState != installationNewer || state.InstalledStatusSupported || state.readyForAdoption() {
				t.Fatalf("unsupported newer installation was considered adoptable: %+v", state)
			}
		})
	}
	for _, field := range []string{"policy", "rules", "service", "daemon", "hook"} {
		t.Run("newer missing "+field, func(t *testing.T) {
			ownCopy := own
			switch field {
			case "policy":
				ownCopy.PolicyReady = false
			case "rules":
				ownCopy.CoreRulesReady = false
			case "service":
				ownCopy.ServiceReady = false
			case "daemon":
				ownCopy.DaemonVersion = "v1.8.2"
			case "hook":
				ownCopy.HookPayloadMatches = false
				ownCopy.PayloadState = installationDifferent
			}
			statusCopy := status
			statusCopy.Installation = &ownCopy
			state := inspectInstallationState(home, "/older-app/agentjail", "v1.8.2", func(string) (installedCLIStatus, error) { return statusCopy, nil })
			if !state.InstalledStatusSupported || state.readyForAdoption() {
				t.Fatalf("missing newer prerequisite did not permit explicit repair: %+v", state)
			}
		})
	}
}

func TestInstallationMissingDoesNotInvokeVersionReader(t *testing.T) {
	state := inspectInstallationState(t.TempDir(), "/missing/candidate", "v1.8.2", func(string) (installedCLIStatus, error) {
		t.Fatal("missing installed CLI must not be run")
		return installedCLIStatus{}, fmt.Errorf("unexpected")
	})
	if state.PayloadState != installationMissing || state.CLIPresent {
		t.Fatalf("unexpected missing installation: %+v", state)
	}
}

func TestRetiredInstallationRemainsExplicitlyReinstallable(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".agentjail")
	if err := retireInstallDir(root, false); err != nil {
		t.Fatal(err)
	}
	state := inspectInstallationState(home, "/fixture/bundled/agentjail", "v1.8.2", func(string) (installedCLIStatus, error) {
		t.Fatal("retired compatibility command must not be probed as an installed CLI")
		return installedCLIStatus{}, nil
	})
	if !state.ExplicitlyUninstalled || state.CLIPresent || state.PayloadState != installationMissing {
		t.Fatalf("retired installation cannot be explicitly reinstalled: %+v", state)
	}
	fixture, err := os.ReadFile("../../macos/AgentjailApproval/testdata/retired-installation.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected installationState
	if err := json.Unmarshal(fixture, &expected); err != nil {
		t.Fatal(err)
	}
	if state != expected {
		t.Fatalf("retirement state differs from shared native fixture: got %+v, want %+v", state, expected)
	}
	status := collectStatusReport(home)
	if status.Infrastructure.CLIInstalled || status.Infrastructure.HookBinaryInstalled || status.Infrastructure.DaemonBinaryInstalled {
		t.Fatalf("compatibility commands reported as operational binaries: %+v", status.Infrastructure)
	}
	if !status.Installation.ExplicitlyUninstalled || status.Installation.PayloadState != installationMissing {
		t.Fatalf("status changed explicit uninstall intent: %+v", status.Installation)
	}
	// A real payload invalidates the receipt even before successful install clears it.
	if err := os.WriteFile(filepath.Join(root, "bin", cliBinaryName), []byte("real CLI"), 0o700); err != nil {
		t.Fatal(err)
	}
	state = inspectInstallationState(home, "/fixture/bundled/agentjail", "v1.8.2", func(string) (installedCLIStatus, error) { return installedCLIStatus{Version: "v1.8.1"}, nil })
	if state.ExplicitlyUninstalled || !state.CLIPresent || state.PayloadState != installationOlder {
		t.Fatalf("receipt hid a real partial installation: %+v", state)
	}
}

func TestInstalledCLIVersionRequiresBoundedTypedOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agentjail")
	for _, test := range []struct {
		name, script, want string
		wantError          bool
	}{
		{"valid", `printf '{"protocol_version":1,"version":"v1.8.2"}'`, "v1.8.2", false},
		{"legacy version", `case "$2" in status) exit 2;; version) printf 'AgentJail\npolicy guardrails for agents\nv1.8.2 · darwin\n';; esac`, "v1.8.2", false},
		{"ambiguous version", `printf 'AgentJail v1.8.2 v1.7.0'`, "", true},
		{"unsupported", `printf '{"protocol_version":9,"version":"v1.8.2"}'`, "", true},
		{"empty", `printf '{"protocol_version":1,"version":""}'`, "", true},
		{"oversized", `printf '%070000d' 0`, "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte("#!/bin/sh\n"+test.script+"\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			got, err := readInstalledCLIStatus(path)
			if (err != nil) != test.wantError || got.Version != test.want {
				t.Fatalf("status = %+v, error = %v", got, err)
			}
		})
	}
}

func TestInstallationAdoptionRequiresSetupAndLiveVersion(t *testing.T) {
	ready := installationState{PayloadState: installationMatching, InstalledStatusSupported: true, RolesReady: true, ServiceReady: true, PolicyReady: true, CoreRulesReady: true, DaemonMatchesInstall: true}
	if !ready.readyForAdoption() {
		t.Fatal("matching healthy install was not adoptable")
	}
	for _, field := range []string{"roles", "service", "policy", "rules", "status", "daemon", "payload"} {
		state := ready
		switch field {
		case "roles":
			state.RolesReady = false
		case "service":
			state.ServiceReady = false
		case "policy":
			state.PolicyReady = false
		case "rules":
			state.CoreRulesReady = false
		case "status":
			state.InstalledStatusSupported = false
		case "daemon":
			state.DaemonMatchesInstall = false
		case "payload":
			state.PayloadState = installationDifferent
		}
		if state.readyForAdoption() {
			t.Errorf("install with %s mismatch was adopted", field)
		}
	}
}
