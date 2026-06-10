package telemetry

import "github.com/google/uuid"

// Event is one PostHog capture event. Properties keys are set ONLY by the
// constructors below — never by serializing caller-supplied maps — so no
// path/command/repo payload can leak. This file IS the field allowlist.
type Event struct {
	Event      string                 `json:"event"`
	Properties map[string]interface{} `json:"properties"`
}

func base(distinctID, version string) map[string]interface{} {
	return map[string]interface{}{
		"distinct_id":       distinctID,
		"$insert_id":        uuid.NewString(), // PostHog dedupes replays on this
		"agentjail_version": version,
	}
}

// NewEnvEvent: environment basics, emitted at daemon start.
func NewEnvEvent(distinctID, version, goos, goarch, installMethod string) Event {
	p := base(distinctID, version)
	p["os"] = goos
	p["arch"] = goarch
	if installMethod != "" {
		p["install_method"] = installMethod // "curl" | "brew" | "" (omitted)
	}
	return Event{Event: "session_start", Properties: p}
}

// NewFeatureEvent: a CLI command was run. command is an enum; agents are enums.
func NewFeatureEvent(distinctID, version, command string, agents []string) Event {
	p := base(distinctID, version)
	p["command"] = command
	if len(agents) > 0 {
		p["agents"] = agents
	}
	return Event{Event: "feature_used", Properties: p}
}

// NewDecisionRollup: aggregated decision counts for one window. ruleCounts keys
// are enum rule IDs (e.g. "command_policy/rm_rf") — never the matched payload.
// ruleActionCounts keys are "action|ruleID" pairs (e.g. "deny|command_policy/rm_rf").
// Existing action_counts and rule_counts fields are preserved for backward compat.
func NewDecisionRollup(distinctID, version string, actionCounts, ruleCounts map[string]int, dropped int) Event {
	p := base(distinctID, version)
	p["action_counts"] = actionCounts
	p["rule_counts"] = ruleCounts
	if dropped > 0 {
		p["spool_dropped"] = dropped
	}
	return Event{Event: "decision_rollup", Properties: p}
}

// NewDecisionRollupWithDetails is NewDecisionRollup extended with combined
// rule×action counts and per-tool / per-agent counts. Callers that have a full
// DecisionWindow should prefer this constructor. Optional fields are omitted
// when empty (backward compat with existing action_counts / rule_counts).
func NewDecisionRollupWithDetails(distinctID, version string, w DecisionWindow, dropped int) Event {
	p := base(distinctID, version)
	p["action_counts"] = w.ActionCounts
	p["rule_counts"] = w.RuleCounts
	if len(w.RuleActionCounts) > 0 {
		p["rule_action_counts"] = w.RuleActionCounts
	}
	if len(w.ToolCounts) > 0 {
		p["tool_counts"] = w.ToolCounts
	}
	if len(w.AgentCounts) > 0 {
		p["agent_counts"] = w.AgentCounts
	}
	if dropped > 0 {
		p["spool_dropped"] = dropped
	}
	return Event{Event: "decision_rollup", Properties: p}
}

// NewPerfRollup: aggregated daemon performance for one window.
func NewPerfRollup(distinctID, version string, p50ms, p95ms float64, restarts int) Event {
	p := base(distinctID, version)
	p["eval_p50_ms"] = p50ms
	p["eval_p95_ms"] = p95ms
	p["restarts"] = restarts
	return Event{Event: "perf_rollup", Properties: p}
}

// NewPolicyConfigEvent: a snapshot of the user's policy configuration, emitted by
// the daemon at startup and on reload. disabledRules is the user's disabled-rules
// list verbatim (it may include custom rule IDs); custom_rule_count is how many
// custom rules are loaded.
func NewPolicyConfigEvent(distinctID, version string, customRuleCount int, disabledRules []string) Event {
	p := base(distinctID, version)
	p["custom_rule_count"] = customRuleCount
	p["disabled_rules"] = disabledRules
	return Event{Event: "policy_config", Properties: p}
}

// NewFeedbackEvent: a user-initiated feedback message. message and contact are
// supplied by the user explicitly; os is environment basics. contact is omitted
// when empty.
func NewFeedbackEvent(distinctID, version, goos, message, contact string) Event {
	p := base(distinctID, version)
	p["message"] = message
	p["os"] = goos
	if contact != "" {
		p["contact"] = contact
	}
	return Event{Event: "feedback", Properties: p}
}

// NewInstallEvent: fired immediately after a successful agentjail install.
// installMethod is an enum: "curl" | "brew" | "" (unknown). agents is the
// list of agent enum IDs that were wired (e.g. ["claude-code", "cursor"]).
// agentsDetected is the count of agents found on the machine (may be larger
// than len(agents) when some were not selected).
func NewInstallEvent(distinctID, version, goos, goarch, installMethod string, agents []string, agentsDetected int) Event {
	p := base(distinctID, version)
	p["os"] = goos
	p["arch"] = goarch
	if installMethod != "" {
		p["install_method"] = installMethod // "curl" | "brew"
	}
	if len(agents) > 0 {
		p["agents"] = agents
	}
	p["agents_detected"] = agentsDetected
	return Event{Event: "install", Properties: p}
}

// NewUninstallEvent: fired immediately before agentjail teardown so churn is
// captured even when ~/.agentjail is removed moments later.
func NewUninstallEvent(distinctID, version, goos, goarch string) Event {
	p := base(distinctID, version)
	p["os"] = goos
	p["arch"] = goarch
	return Event{Event: "uninstall", Properties: p}
}

// NewFailOpenEvent: fired when the hook falls open due to a daemon fault.
// reason is an enum describing the failure category (never a raw payload):
// "dial-daemon" | "read-response" | "parse-response" | "read-stdin" | "parse-input" | "other".
func NewFailOpenEvent(distinctID, version, goos, reason string) Event {
	p := base(distinctID, version)
	p["os"] = goos
	p["reason"] = reason // enum; see failOpenMarker categories in agentjail-hook
	return Event{Event: "fail_open", Properties: p}
}

// NewHeartbeatEvent: emitted at most once per ~24h when a CLI command runs and
// the update-check throttle allows it. Captures version currency and OS.
// latestVersion is "" when the check failed or was not attempted.
func NewHeartbeatEvent(distinctID, currentVersion, latestVersion, goos string, updateAvailable bool) Event {
	p := base(distinctID, currentVersion)
	p["os"] = goos
	p["latest_version"] = latestVersion
	p["update_available"] = updateAvailable
	return Event{Event: "heartbeat", Properties: p}
}
