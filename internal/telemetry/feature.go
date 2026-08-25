package telemetry

// RecordFeature is the short-lived-CLI entry point: load consent, and if enabled,
// append a single feature_used event to the spool. It NEVER touches the network —
// the daemon flushes the spool later. Best-effort: all errors are swallowed so
// telemetry can never break a CLI command.
func RecordFeature(p Paths, getenv func(string) string, version, command string, agents []string) {
	c, err := LoadConsent(p)
	if err != nil {
		return
	}
	if on, _ := Resolve(c, getenv); !on {
		return
	}
	_ = NewSpool(p, spoolMaxEvents, spoolMaxBytes).Append(NewFeatureEvent(c.AnonymousID, version, command, agents))
}

// RecordMacOSSetup spools one bounded native-app setup event when telemetry is enabled.
func RecordMacOSSetup(p Paths, getenv func(string) string, version string, stage MacOSSetupStage, outcome MacOSSetupOutcome) bool {
	c, err := LoadConsent(p)
	if err != nil {
		return false
	}
	if on, _ := Resolve(c, getenv); !on {
		return false
	}
	event, ok := NewMacOSSetupEvent(c.AnonymousID, version, stage, outcome)
	if !ok {
		return false
	}
	return NewSpool(p, spoolMaxEvents, spoolMaxBytes).Append(event) == nil
}
