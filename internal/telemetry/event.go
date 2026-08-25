package telemetry

import "github.com/google/uuid"

var commit = "" // injected via -ldflags at release build time

// Event is one PostHog capture event. Properties keys are set ONLY by the
// constructors below — never by serializing caller-supplied maps — so no
// path/command/repo payload can leak. This file IS the field allowlist.
type Event struct {
	Event      string                 `json:"event"`
	Properties map[string]interface{} `json:"properties"`
	Set        map[string]interface{} `json:"$set,omitempty"`
	SetOnce    map[string]interface{} `json:"$set_once,omitempty"`
}

// MacOSSetupStage is a fixed step in the native app setup funnel.
type MacOSSetupStage string

const (
	MacOSSetupStarted      MacOSSetupStage = "started"
	MacOSSetupComponents   MacOSSetupStage = "components"
	MacOSSetupExtension    MacOSSetupStage = "extension"
	MacOSSetupApproval     MacOSSetupStage = "approval"
	MacOSSetupVerification MacOSSetupStage = "verification"
)

// MacOSSetupOutcome is a fixed result for one setup stage.
type MacOSSetupOutcome string

const (
	MacOSSetupOutcomeStarted   MacOSSetupOutcome = "started"
	MacOSSetupOutcomeSucceeded MacOSSetupOutcome = "succeeded"
	MacOSSetupOutcomeFailed    MacOSSetupOutcome = "failed"
	MacOSSetupOutcomeRequired  MacOSSetupOutcome = "required"
)

func (s MacOSSetupStage) valid() bool {
	switch s {
	case MacOSSetupStarted, MacOSSetupComponents, MacOSSetupExtension, MacOSSetupApproval, MacOSSetupVerification:
		return true
	default:
		return false
	}
}

func (o MacOSSetupOutcome) valid() bool {
	switch o {
	case MacOSSetupOutcomeStarted, MacOSSetupOutcomeSucceeded, MacOSSetupOutcomeFailed, MacOSSetupOutcomeRequired:
		return true
	default:
		return false
	}
}

func validMacOSSetupMeasurement(stage MacOSSetupStage, outcome MacOSSetupOutcome) bool {
	if !stage.valid() || !outcome.valid() {
		return false
	}
	switch stage {
	case MacOSSetupStarted:
		return outcome == MacOSSetupOutcomeStarted
	case MacOSSetupComponents, MacOSSetupExtension:
		return outcome == MacOSSetupOutcomeStarted || outcome == MacOSSetupOutcomeSucceeded || outcome == MacOSSetupOutcomeFailed
	case MacOSSetupApproval:
		return outcome == MacOSSetupOutcomeRequired
	case MacOSSetupVerification:
		return outcome == MacOSSetupOutcomeSucceeded || outcome == MacOSSetupOutcomeFailed
	default:
		return false
	}
}

func base(distinctID, version string) map[string]interface{} {
	if version == "" {
		if len(commit) >= 7 {
			version = "dev-" + commit[:7]
		} else if commit != "" {
			version = "dev-" + commit
		} else {
			version = "dev"
		}
	}
	return map[string]interface{}{
		"distinct_id":       distinctID,
		"$insert_id":        uuid.NewString(), // PostHog dedupes replays on this
		"agentjail_version": version,
	}
}

func personSet(version, goos, goarch string) map[string]interface{} {
	m := map[string]interface{}{"agentjail_version": version}
	if goos != "" {
		m["os"] = goos
	}
	if goarch != "" {
		m["arch"] = goarch
	}
	return m
}

// NewEnvEvent: environment basics, emitted at daemon start.
func NewEnvEvent(distinctID, version, goos, goarch, installMethod string) Event {
	p := base(distinctID, version)
	p["os"] = goos
	p["arch"] = goarch
	if installMethod != "" {
		p["install_method"] = installMethod // "app" | "curl" | "brew" | "" (omitted)
	}
	ev := Event{Event: "session_start", Properties: p, Set: personSet(version, goos, goarch)}
	if installMethod != "" {
		ev.SetOnce = map[string]interface{}{"install_method": installMethod}
	}
	return ev
}

// NewFeatureEvent: a CLI command was run. command is an enum; agents are enums.
func NewFeatureEvent(distinctID, version, command string, agents []string) Event {
	p := base(distinctID, version)
	p["command"] = command
	if len(agents) > 0 {
		p["agents"] = agents
	}
	return Event{Event: "feature_used", Properties: p, Set: map[string]interface{}{"agentjail_version": version}}
}

// NewMacOSSetupEvent records only the fixed setup funnel step and result.
// See ADR 0141-unified-macos-app.
func NewMacOSSetupEvent(distinctID, version string, stage MacOSSetupStage, outcome MacOSSetupOutcome) (Event, bool) {
	if !validMacOSSetupMeasurement(stage, outcome) {
		return Event{}, false
	}
	p := base(distinctID, version)
	p["stage"] = string(stage)
	p["outcome"] = string(outcome)
	return Event{Event: "macos_setup", Properties: p, Set: map[string]interface{}{"agentjail_version": version}}, true
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
	return Event{Event: "decision_rollup", Properties: p, Set: map[string]interface{}{"agentjail_version": version}}
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
	return Event{Event: "decision_rollup", Properties: p, Set: map[string]interface{}{"agentjail_version": version}}
}

// NewPerfRollup: aggregated daemon performance for one window.
func NewPerfRollup(distinctID, version string, p50ms, p95ms float64, restarts int) Event {
	p := base(distinctID, version)
	p["eval_p50_ms"] = p50ms
	p["eval_p95_ms"] = p95ms
	p["restarts"] = restarts
	return Event{Event: "perf_rollup", Properties: p, Set: map[string]interface{}{"agentjail_version": version}}
}

// NewPolicyConfigEvent: a snapshot of the user's policy configuration, emitted by
// the daemon at startup and on reload. disabledRules is the user's disabled-rules
// list verbatim (it may include custom rule IDs); custom_rule_count is how many
// custom rules are loaded.
func NewPolicyConfigEvent(distinctID, version string, customRuleCount int, disabledRules []string) Event {
	p := base(distinctID, version)
	p["custom_rule_count"] = customRuleCount
	p["disabled_rules"] = disabledRules
	return Event{Event: "policy_config", Properties: p, Set: map[string]interface{}{"agentjail_version": version}}
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
	return Event{Event: "feedback", Properties: p, Set: map[string]interface{}{"agentjail_version": version}}
}

// NewInstallEvent: fired immediately after a successful agentjail install.
// installMethod is an enum: "app" | "curl" | "brew" | "" (unknown). agents is the
// list of agent enum IDs that were wired (e.g. ["claude-code", "cursor"]).
// agentsDetected is the count of agents found on the machine (may be larger
// than len(agents) when some were not selected). isFreshInstall is true when
// ~/.agentjail/telemetry.json did not exist before this run (first-ever install
// vs. a binary/daemon refresh).
func NewInstallEvent(distinctID, version, goos, goarch, installMethod string, agents []string, agentsDetected int, isFreshInstall bool) Event {
	p := base(distinctID, version)
	p["os"] = goos
	p["arch"] = goarch
	if installMethod != "" {
		p["install_method"] = installMethod // "app" | "curl" | "brew"
	}
	if len(agents) > 0 {
		p["agents"] = agents
	}
	p["agents_detected"] = agentsDetected
	p["is_fresh_install"] = isFreshInstall
	ev := Event{Event: "install", Properties: p, Set: personSet(version, goos, goarch)}
	so := map[string]interface{}{"first_installed_version": version}
	if installMethod != "" {
		so["install_method"] = installMethod
	}
	ev.SetOnce = so
	return ev
}

// NewUninstallEvent: fired immediately before agentjail teardown so churn is
// captured even when ~/.agentjail is removed moments later. agents is the list
// of agent enum IDs that were unhooked: a single entry (e.g. ["claude-code"])
// for a `--for <agent>` single-agent removal, or empty/nil for a full teardown.
// Its presence distinguishes a partial unhook from a full uninstall.
func NewUninstallEvent(distinctID, version, goos, goarch string, agents []string) Event {
	p := base(distinctID, version)
	p["os"] = goos
	p["arch"] = goarch
	if len(agents) > 0 {
		p["agents"] = agents
	}
	return Event{Event: "uninstall", Properties: p, Set: personSet(version, goos, goarch)}
}

// NewFailOpenEvent: fired when the hook falls open due to a daemon fault.
// reason is an enum describing the failure category (never a raw payload):
// "dial-daemon" | "read-response" | "parse-response" | "read-stdin" | "parse-input" | "other".
func NewFailOpenEvent(distinctID, version, goos, reason string) Event {
	p := base(distinctID, version)
	p["os"] = goos
	p["reason"] = reason // enum; see failOpenMarker categories in agentjail-hook
	return Event{Event: "fail_open", Properties: p, Set: map[string]interface{}{"agentjail_version": version}}
}

// NewHeartbeatEvent: emitted at most once per ~24h when a CLI command runs and
// the update-check throttle allows it. Captures version currency and OS.
// latestVersion is "" when the check failed or was not attempted.
// source is "cli" or "daemon" — which component emitted the event.
func NewHeartbeatEvent(distinctID, currentVersion, latestVersion, goos, source string, updateAvailable bool) Event {
	p := base(distinctID, currentVersion)
	p["os"] = goos
	p["latest_version"] = latestVersion
	p["update_available"] = updateAvailable
	p["source"] = source
	return Event{Event: "heartbeat", Properties: p, Set: map[string]interface{}{"agentjail_version": currentVersion, "os": goos}}
}

// NewUpdateEvent: fired immediately after a successful `agentjail update`.
// from_version and to_version are semver enum strings (e.g. "v1.2.3").
// os and arch are runtime.GOOS / runtime.GOARCH enums.
func NewUpdateEvent(distinctID, fromVersion, toVersion, goos, goarch string) Event {
	p := base(distinctID, fromVersion)
	p["from_version"] = fromVersion
	p["to_version"] = toVersion
	p["os"] = goos
	p["arch"] = goarch
	return Event{Event: "update", Properties: p, Set: personSet(toVersion, goos, goarch)}
}
