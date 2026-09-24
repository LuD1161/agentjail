package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/LuD1161/agentjail/internal/buildinfo"
	"github.com/LuD1161/agentjail/internal/selfupdate"
)

type installationPayloadState string

const installationStateProtocolVersion uint32 = 1

const (
	installationMissing   installationPayloadState = "missing"
	installationMatching  installationPayloadState = "matching"
	installationOlder     installationPayloadState = "older"
	installationNewer     installationPayloadState = "newer"
	installationDifferent installationPayloadState = "different"
	installationUnknown   installationPayloadState = "unknown"
)

type installationState struct {
	ProtocolVersion          uint32                   `json:"protocol_version"`
	PayloadState             installationPayloadState `json:"payload_state"`
	CandidateVersion         string                   `json:"candidate_version"`
	InstalledVersion         string                   `json:"installed_version,omitempty"`
	DaemonVersion            string                   `json:"daemon_version,omitempty"`
	CLIPresent               bool                     `json:"cli_present"`
	CLIPayloadMatches        bool                     `json:"cli_payload_matches"`
	HookPayloadMatches       bool                     `json:"hook_payload_matches"`
	RolesReady               bool                     `json:"roles_ready"`
	ServiceReady             bool                     `json:"service_ready"`
	PolicyReady              bool                     `json:"policy_ready"`
	CoreRulesReady           bool                     `json:"core_rules_ready"`
	InstalledStatusSupported bool                     `json:"installed_status_supported"`
	DaemonMatchesInstall     bool                     `json:"daemon_matches_install"`
	ExplicitlyUninstalled    bool                     `json:"explicitly_uninstalled"`
}

func (state installationState) readyForAdoption() bool {
	return (state.PayloadState == installationMatching || state.PayloadState == installationNewer) &&
		state.InstalledStatusSupported && state.RolesReady && state.ServiceReady &&
		state.PolicyReady && state.CoreRulesReady && state.DaemonMatchesInstall
}

func collectInstallationState(home string) installationState {
	executable, _ := os.Executable()
	if resolved, err := filepath.EvalSymlinks(executable); err == nil {
		executable = resolved
	}
	return inspectInstallationState(home, executable, buildinfo.Version, readInstalledCLIStatus)
}

func inspectInstallationState(home, candidateCLI, candidateVersion string, readStatus func(string) (installedCLIStatus, error)) installationState {
	binDir := filepath.Join(home, ".agentjail", "bin")
	installedCLI := filepath.Join(binDir, cliBinaryName)
	installedHook := filepath.Join(binDir, hookBinaryName)
	result := installationState{
		ProtocolVersion: installationStateProtocolVersion,
		PayloadState:    installationMissing, CandidateVersion: candidateVersion,
		CLIPresent: executableFile(installedCLI), ExplicitlyUninstalled: explicitlyUninstalled(home),
	}
	if result.ExplicitlyUninstalled {
		result.CLIPresent = false
		return result
	}
	if !result.CLIPresent {
		return result
	}
	result.PayloadState = installationUnknown
	result.CLIPayloadMatches = executableContentsMatch(candidateCLI, installedCLI)
	result.HookPayloadMatches = executableContentsMatch(filepath.Join(filepath.Dir(candidateCLI), hookBinaryName), installedHook)
	var installedStatus installedCLIStatus
	if result.CLIPayloadMatches {
		result.InstalledVersion = candidateVersion
		result.InstalledStatusSupported = true
	} else {
		installedStatus, _ = readStatus(installedCLI)
		result.InstalledVersion = installedStatus.Version
		result.InstalledStatusSupported = installedStatus.supportsInstallationState()
	}
	result.PayloadState = classifyInstallationPayload(result.CLIPayloadMatches && result.HookPayloadMatches, candidateVersion, result.InstalledVersion)
	// A newer CLI owns its service and rules contract. See ADR 0151-install-lifecycle.
	if result.PayloadState == installationNewer {
		if result.InstalledStatusSupported {
			own := installedStatus.Installation
			result.RolesReady = own.RolesReady && own.HookPayloadMatches
			result.ServiceReady = own.ServiceReady
			result.PolicyReady = own.PolicyReady
			result.CoreRulesReady = own.CoreRulesReady
			result.DaemonVersion = own.DaemonVersion
			result.DaemonMatchesInstall = own.DaemonMatchesInstall && own.DaemonVersion == result.InstalledVersion
		}
		return result
	}
	result.RolesReady = executableFile(installedHook)
	for _, role := range selfupdate.RoleNames {
		target, err := os.Readlink(filepath.Join(binDir, role))
		if err != nil || target != cliBinaryName {
			result.RolesReady = false
		}
	}
	spec := daemonServiceSpec(home)
	if content, err := os.ReadFile(spec.path); err == nil {
		result.ServiceReady = string(content) == spec.content
	}
	if info, err := os.Stat(filepath.Join(home, ".agentjail", "policy.yaml")); err == nil {
		result.PolicyReady = info.Mode().IsRegular()
	}
	result.CoreRulesReady = installedCoreRulesMatch(filepath.Join(home, ".agentjail", "rules"))
	liveness, runningVersion, err := probeDaemonDetails(filepath.Join(home, ".agentjail", "daemon.sock"), 200*time.Millisecond)
	result.DaemonVersion = runningVersion
	result.DaemonMatchesInstall = err == nil && liveness == daemonHealthy && result.InstalledVersion != "" && runningVersion == result.InstalledVersion
	return result
}

func installedCoreRulesMatch(rulesDir string) bool {
	for name, expected := range allCoreRuleBytes() {
		path := filepath.Join(rulesDir, name+".rego")
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() != int64(len(expected)) {
			return false
		}
		actual, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(actual, expected) {
			return false
		}
	}
	return true
}

func classifyInstallationPayload(matches bool, candidate, installed string) installationPayloadState {
	if matches {
		return installationMatching
	}
	if !selfupdate.IsValid(candidate) || !selfupdate.IsValid(installed) {
		return installationUnknown
	}
	if selfupdate.IsNewerVersion(candidate, installed) {
		return installationNewer
	}
	if selfupdate.IsNewerVersion(installed, candidate) {
		return installationOlder
	}
	return installationDifferent
}

func executableFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}

func executableContentsMatch(left, right string) bool {
	if !executableFile(left) || !executableFile(right) {
		return false
	}
	leftInfo, err := os.Stat(left)
	if err != nil {
		return false
	}
	rightInfo, err := os.Stat(right)
	if err != nil {
		return false
	}
	if os.SameFile(leftInfo, rightInfo) {
		return true
	}
	if leftInfo.Size() != rightInfo.Size() {
		return false
	}
	leftHash, err := executableDigest(left)
	if err != nil {
		return false
	}
	rightHash, err := executableDigest(right)
	return err == nil && leftHash == rightHash
}

func executableDigest(path string) ([sha256.Size]byte, error) {
	const maximumExecutableBytes = 256 << 20
	f, err := os.Open(path)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	defer f.Close()
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, maximumExecutableBytes+1))
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	if n > maximumExecutableBytes {
		return [sha256.Size]byte{}, fmt.Errorf("executable exceeds hash size bound")
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

type installedCLIStatus struct {
	ProtocolVersion uint32             `json:"protocol_version"`
	Version         string             `json:"version"`
	Installation    *installationState `json:"installation"`
}

func (status installedCLIStatus) supportsInstallationState() bool {
	state := status.Installation
	return status.ProtocolVersion == statusReportProtocolVersion && state != nil &&
		state.ProtocolVersion == installationStateProtocolVersion &&
		state.CLIPresent && state.CLIPayloadMatches && !state.ExplicitlyUninstalled &&
		state.CandidateVersion == status.Version && state.InstalledVersion == status.Version
}

func readInstalledCLIStatus(path string) (installedCLIStatus, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	output, commandErr := readInstalledCLIOutput(ctx, path, "--no-color", "status", "--json")
	var status installedCLIStatus
	if commandErr == nil && json.Unmarshal(output, &status) == nil && status.ProtocolVersion == statusReportProtocolVersion && len(status.Version) > 0 && len(status.Version) <= 64 {
		return status, nil
	}
	// Earlier CLIs predate status --json; their version command emits one semver.
	output, err := readInstalledCLIOutput(ctx, path, "--no-color", "version")
	if err != nil {
		return installedCLIStatus{}, err
	}
	if !strings.Contains(strings.ToLower(string(output)), "agentjail") {
		return installedCLIStatus{}, fmt.Errorf("installed CLI returned an unrecognized version response")
	}
	version := ""
	for _, field := range strings.Fields(string(output)) {
		if selfupdate.IsValid(field) {
			if version != "" && version != field {
				return installedCLIStatus{}, fmt.Errorf("installed CLI returned ambiguous versions")
			}
			version = field
		}
	}
	if version == "" {
		return installedCLIStatus{}, fmt.Errorf("installed CLI returned an unknown version")
	}
	return installedCLIStatus{Version: version}, nil
}

func readInstalledCLIOutput(ctx context.Context, path string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, path, args...)
	command.WaitDelay = 100 * time.Millisecond
	output := &installationStatusOutput{}
	command.Stdout = output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return nil, err
	}
	return output.data, nil
}

type installationStatusOutput struct{ data []byte }

func (output *installationStatusOutput) Write(data []byte) (int, error) {
	if len(output.data)+len(data) > 64*1024 {
		return 0, fmt.Errorf("installed CLI status exceeded size bound")
	}
	output.data = append(output.data, data...)
	return len(data), nil
}
