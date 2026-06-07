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
func NewDecisionRollup(distinctID, version string, actionCounts, ruleCounts map[string]int, dropped int) Event {
	p := base(distinctID, version)
	p["action_counts"] = actionCounts
	p["rule_counts"] = ruleCounts
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
