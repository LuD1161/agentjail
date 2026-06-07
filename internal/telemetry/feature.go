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
