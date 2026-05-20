package eslogger

import "time"

// Source identifies which capture track produced a NormEvent.
type Source string

const (
	SourceES Source = "es" // macOS Endpoint Security via eslogger(1)
	SourceAW Source = "aw" // agentjail events.jsonl (PATH shim / runtime hook)
)

// NormEvent is the minimal normalized projection of an exec event used by
// the join. We only carry what was catalogued as load-bearing:
//
//   time, pid, ppid, exec.path, exec.argv
//
// Keeping the schema small bounds the per-event memory cost of the join
// state. Anything richer (cdhash, audit_token, signing_id, env) stays in
// the raw line and is re-fetched only when emitting a delta record.
type NormEvent struct {
	Source   Source    `json:"source"`
	Time     time.Time `json:"time"`
	PID      int       `json:"pid"`
	PPID     int       `json:"ppid"`
	ExecPath string    `json:"exec_path"`
	Argv     []string  `json:"argv,omitempty"`

	// Raw is the original JSON line. We keep a reference so a delta can
	// be re-emitted with the full payload for downstream auditing,
	// without re-parsing. It is not used by the join itself.
	Raw []byte `json:"-"`
}

// Delta is what the diff emits. A "es_only" delta is an ES exec event
// that did not match any agentjail exec event inside the join window.
type Delta struct {
	Kind     string    `json:"kind"` // "es_only" today; reserved: "aw_only", "mismatch"
	Time     time.Time `json:"time"`
	PID      int       `json:"pid"`
	PPID     int       `json:"ppid"`
	ExecPath string    `json:"exec_path"`
	Argv     []string  `json:"argv,omitempty"`
	Reason   string    `json:"reason"`
}
