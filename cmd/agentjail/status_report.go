package main

import (
	"encoding/json"
	"io"
	"path/filepath"

	"github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/agents"
	"github.com/LuD1161/agentjail/internal/buildinfo"
)

const statusReportProtocolVersion uint32 = 1

type statusReport struct {
	ProtocolVersion uint32               `json:"protocol_version"`
	Version         string               `json:"version"`
	Infrastructure  statusInfrastructure `json:"infrastructure"`
	Policies        statusPolicies       `json:"policies"`
	Agents          []statusAgent        `json:"agents"`
}

type statusInfrastructure struct {
	CLIInstalled             bool `json:"cli_installed"`
	HookBinaryInstalled      bool `json:"hook_binary_installed"`
	DaemonBinaryInstalled    bool `json:"daemon_binary_installed"`
	ServiceDefinitionPresent bool `json:"service_definition_present"`
	DaemonRunning            bool `json:"daemon_running"`
}

type statusPolicies struct {
	Configured  bool `json:"configured"`
	Readable    bool `json:"readable"`
	ActiveRules int  `json:"active_rules"`
}

type statusAgent struct {
	ID            string `json:"id"`
	DisplayName   string `json:"display_name"`
	Detected      bool   `json:"detected"`
	HookInstalled bool   `json:"hook_installed"`
}

func printStatusJSONOutput(w io.Writer, home string) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(collectStatusReport(home))
}

func collectStatusReport(home string) statusReport {
	binDir := filepath.Join(home, ".agentjail", "bin")
	policyPath := filepath.Join(home, ".agentjail", "policy.yaml")
	servicePath := filepath.Join(home, "Library", "LaunchAgents", plistFilename)
	if currentGOOS != "darwin" {
		servicePath = filepath.Join(systemdUserUnitDir(home), systemdUnitFilename)
	}

	policyStatus := collectStatusPolicies(home, policyPath)
	env := buildAgentsEnv(home)
	agentStatuses := make([]statusAgent, 0, len(agents.Registry()))
	for _, agent := range agents.Registry() {
		detection := agent.Detect(env)
		hookStatus := agent.Status(env)
		agentStatuses = append(agentStatuses, statusAgent{
			ID:            agent.ID(),
			DisplayName:   agent.DisplayName(),
			Detected:      detection.Present,
			HookInstalled: hookStatus.Installed,
		})
	}

	version := buildinfo.Version
	if version == "" {
		version = "dev"
	}
	return statusReport{
		ProtocolVersion: statusReportProtocolVersion,
		Version:         version,
		Infrastructure: statusInfrastructure{
			CLIInstalled:             fileExists(filepath.Join(binDir, cliBinaryName)),
			HookBinaryInstalled:      fileExists(filepath.Join(binDir, hookBinaryName)),
			DaemonBinaryInstalled:    fileExists(filepath.Join(binDir, daemonBinaryName)),
			ServiceDefinitionPresent: fileExists(servicePath),
			DaemonRunning:            isDaemonRunning(filepath.Join(home, ".agentjail", "daemon.sock")),
		},
		Policies: policyStatus,
		Agents:   agentStatuses,
	}
}

func collectStatusPolicies(home, policyPath string) statusPolicies {
	if !fileExists(policyPath) {
		return statusPolicies{}
	}
	cfg, err := config.LoadOrDefault(policyPath)
	if err != nil {
		return statusPolicies{Configured: true}
	}

	rulesDir := filepath.Join(home, ".agentjail", "rules")
	active := 0
	locked := LockedRuleIDs()
	for _, entry := range ruleRegistry {
		switch entry.Source {
		case RuleSourceCore:
			if locked[entry.ID] || !isDisabledByConfig(cfg, entry.ID) {
				active++
			}
		case RuleSourceLibrary:
			stem := ruleIDToLibraryStem(entry.ID)
			if locked[entry.ID] || (fileExists(filepath.Join(rulesDir, stem+".rego")) && !isDisabledByConfig(cfg, entry.ID)) {
				active++
			}
		}
	}
	for _, info := range discoverCustomRulesWithInfo(rulesDir) {
		if len(info.ruleIDs) == 0 {
			if !isDisabledByConfig(cfg, info.stem) {
				active++
			}
			continue
		}
		for _, id := range info.ruleIDs {
			if !isDisabledByConfig(cfg, id) {
				active++
			}
		}
	}
	return statusPolicies{Configured: true, Readable: true, ActiveRules: active}
}
