package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/store"
	"github.com/LuD1161/agentjail/internal/wire"
)

// The Protection section answers the question the rest of doctor cannot:
// "was enforcement actually running?" — not "is it running right now".
// See ADR 0082-doctor-attests-enforcement.
const (
	// enforcementGapMargin is how far the newest shield activation may lead
	// the newest decision before it reads as a gap. A shielded session that
	// runs tool calls records decisions within seconds, so an hour of shield
	// activity with nothing recorded is not a quiet session.
	enforcementGapMargin = time.Hour
	// protectionLookback bounds how far back a signal is considered current.
	// Older than this and the machine is simply idle, not broken.
	protectionLookback = 7 * 24 * time.Hour
)

// protectionSignals is the observable evidence about whether enforcement ran.
// Kept as plain data so the checks below are pure and testable without a DB.
type protectionSignals struct {
	LastDecision    time.Time // newest decisions row; zero if none
	LastShield      time.Time // newest shield.activated; zero if none
	DaemonDownSince time.Time // fail-open sentinel mtime; zero if absent
	Dropped         int64     // decisions.dropped total in the lookback window
}

// enforcementGapCheck reports the divergence that identifies this bug class:
// the shield kept activating while the daemon recorded nothing. The shield
// writes to the store on its own path, so it stays healthy precisely when
// policy enforcement is off — which makes it useless as a health metric and
// ideal as a cross-check against decisions.
func enforcementGapCheck(sig protectionSignals, now time.Time) doctorCheck {
	if sig.LastShield.IsZero() || now.Sub(sig.LastShield) > protectionLookback {
		return doctorCheck{
			label:  "Enforcement",
			status: "skip",
			detail: "no recent shield activity to cross-check",
		}
	}
	if sig.LastDecision.IsZero() {
		return doctorCheck{
			label:  "Enforcement",
			status: "fail",
			detail: fmt.Sprintf("shield ran (last %s) but NO decision was ever recorded — policy enforcement is not reaching the daemon. Check: agentjail doctor / restart: agentjail daemon restart",
				humanAgo(now, sig.LastShield)),
		}
	}
	if gap := sig.LastShield.Sub(sig.LastDecision); gap > enforcementGapMargin {
		return doctorCheck{
			label:  "Enforcement",
			status: "fail",
			detail: fmt.Sprintf("shield ran %s but the last decision is %s — %s of shielded work went unrecorded, so policy was likely NOT enforced. Restart: agentjail daemon restart",
				humanAgo(now, sig.LastShield), humanAgo(now, sig.LastDecision), roundDur(gap)),
		}
	}
	return doctorCheck{
		label:  "Enforcement",
		status: "ok",
		detail: fmt.Sprintf("decisions current (last %s)", humanAgo(now, sig.LastDecision)),
	}
}

// daemonDowntimeCheck turns the fail-open sentinel into a duration. The hook
// writes it the first time it cannot reach the daemon and the daemon clears it
// on startup, so a surviving sentinel dates the start of the current outage.
func daemonDowntimeCheck(sig protectionSignals, now time.Time) doctorCheck {
	if sig.DaemonDownSince.IsZero() {
		return doctorCheck{
			label:  "Fail-open history",
			status: "ok",
			detail: "no unresolved fail-open window",
		}
	}
	return doctorCheck{
		label:  "Fail-open history",
		status: "warn",
		detail: fmt.Sprintf("the hook failed open at %s (%s ago) and the daemon has not started since — everything after that ran unenforced. Restart: agentjail daemon restart",
			sig.DaemonDownSince.Format(time.RFC3339), roundDur(now.Sub(sig.DaemonDownSince))),
	}
}

// droppedDecisionsCheck surfaces decisions the writer could not persist. A
// nonzero count means the decisions table under-reports and is not a complete
// record for that window (ADR 0072).
func droppedDecisionsCheck(sig protectionSignals) doctorCheck {
	if sig.Dropped == 0 {
		return doctorCheck{
			label:  "Decision recording",
			status: "ok",
			detail: "no dropped decisions",
		}
	}
	return doctorCheck{
		label:  "Decision recording",
		status: "warn",
		detail: fmt.Sprintf("%d decision(s) dropped — enforcement was applied but the record is incomplete", sig.Dropped),
	}
}

// humanAgo renders a timestamp as a relative age.
func humanAgo(now, then time.Time) string {
	if then.IsZero() {
		return "never"
	}
	return roundDur(now.Sub(then)) + " ago"
}

// roundDur renders a duration at a resolution a human wants to read.
func roundDur(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return d.Round(time.Minute).String()
	case d < 48*time.Hour:
		return d.Round(time.Hour).String()
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// readProtectionSignals gathers the evidence read-only. Any failure yields a
// zero signal rather than an error: doctor must still report everything else
// when the DB is absent (a fresh install) or unreadable.
func readProtectionSignals(home string) protectionSignals {
	var sig protectionSignals

	if fi, err := os.Stat(wire.FailOpenWarnedSentinelPath()); err == nil {
		sig.DaemonDownSince = fi.ModTime()
	}

	dbPath := filepath.Join(home, ".agentjail", "agentjail.db")
	if _, err := os.Stat(dbPath); err != nil {
		return sig
	}
	st, err := store.OpenReadOnly(dbPath)
	if err != nil {
		return sig
	}
	defer st.Close() //nolint:errcheck

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if rows, err := st.ListDecisions(ctx, store.Filter{Limit: 1, OrderDesc: true}); err == nil && len(rows) > 0 {
		sig.LastDecision = rows[0].Ts
	}
	if rows, err := st.ListAuditLog(ctx, store.AuditLogFilter{
		EventType: audit.ShieldActivated, Limit: 1,
	}); err == nil && len(rows) > 0 {
		sig.LastShield = rows[0].Ts
	}
	if rows, err := st.ListAuditLog(ctx, store.AuditLogFilter{
		EventType: audit.DecisionsDropped, Limit: 50,
	}); err == nil {
		cutoff := time.Now().Add(-protectionLookback)
		for _, r := range rows {
			if !r.Ts.IsZero() && r.Ts.After(cutoff) {
				sig.Dropped += droppedCountFromDetail(r.Detail)
			}
		}
	}
	return sig
}

// checkProtection is the doctor section wiring.
func checkProtection(home string) []doctorCheck {
	sig := readProtectionSignals(home)
	now := time.Now()
	return []doctorCheck{
		enforcementGapCheck(sig, now),
		daemonDowntimeCheck(sig, now),
		droppedDecisionsCheck(sig),
	}
}

// droppedCountFromDetail reads the count out of a decisions.dropped Detail
// blob ({"count":"12"}). Returns 0 if absent or malformed — a diagnostic must
// never fail the whole section over one unreadable row.
func droppedCountFromDetail(detail string) int64 {
	if detail == "" {
		return 0
	}
	var d map[string]string
	if err := json.Unmarshal([]byte(detail), &d); err != nil {
		return 0
	}
	n, err := strconv.ParseInt(d["count"], 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}
