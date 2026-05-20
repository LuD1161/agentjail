package eslogger

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// ParseESLine projects one eslogger JSON-Lines record into a NormEvent.
//
// The eslogger output is documented as unstable ("eslogger is
// _NOT_ API in any sense"). We therefore:
//
//   - match by field presence, not by numeric event_type — only
//     records with a top-level event.exec object are projected to a
//     NormEvent (the join key for tamper evidence is exec)
//   - tolerate missing fields silently; an event with no usable target
//     pid is dropped with (nil, false) — the parser does not stop the
//     stream
//   - keep the raw line on the NormEvent so a delta can be re-emitted
//     with the full ES payload
//
// Returns (event, true) on a usable exec record, (nil, false) otherwise.
// A genuine JSON parse error returns an error; the caller decides whether
// to skip the line or fail.
func ParseESLine(line []byte) (*NormEvent, bool, error) {
	if len(line) == 0 {
		return nil, false, nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(line, &raw); err != nil {
		return nil, false, fmt.Errorf("eslogger: parse line: %w", err)
	}
	evRaw, ok := raw["event"]
	if !ok {
		return nil, false, nil
	}
	var evMap map[string]json.RawMessage
	if err := json.Unmarshal(evRaw, &evMap); err != nil {
		return nil, false, nil
	}
	execRaw, ok := evMap["exec"]
	if !ok {
		// fork / exit / other — not part of the diff today
		return nil, false, nil
	}

	var exec struct {
		Target struct {
			AuditToken struct {
				PID int `json:"pid"`
			} `json:"audit_token"`
			PPID       int `json:"ppid"`
			Executable struct {
				Path string `json:"path"`
			} `json:"executable"`
		} `json:"target"`
		Args []string `json:"args"`
	}
	if err := json.Unmarshal(execRaw, &exec); err != nil {
		return nil, false, nil
	}
	if exec.Target.Executable.Path == "" {
		return nil, false, nil
	}

	var t time.Time
	if tRaw, ok := raw["time"]; ok {
		var s string
		if json.Unmarshal(tRaw, &s) == nil && s != "" {
			// eslogger uses RFC3339 with nanosecond precision; the
			// stdlib parser handles both that and plain RFC3339.
			if parsed, err := time.Parse(time.RFC3339Nano, s); err == nil {
				t = parsed
			} else if parsed, err := time.Parse(time.RFC3339, s); err == nil {
				t = parsed
			}
		}
	}

	// We need the new process' pid (post-exec). The ppid is the actor.
	if exec.Target.AuditToken.PID == 0 {
		return nil, false, nil
	}

	// keep a private copy of the line so a re-slice by the bufio scanner
	// does not corrupt the retained Raw field.
	rawCopy := make([]byte, len(line))
	copy(rawCopy, line)

	return &NormEvent{
		Source:   SourceES,
		Time:     t,
		PID:      exec.Target.AuditToken.PID,
		PPID:     exec.Target.PPID,
		ExecPath: exec.Target.Executable.Path,
		Argv:     exec.Args,
		Raw:      rawCopy,
	}, true, nil
}

// StreamES reads an eslogger JSON-Lines file, yielding NormEvents to fn.
// It allocates a bounded buffer (1 MiB) for the scanner so a single
// pathological line cannot OOM the process. Malformed lines are counted
// in the returned stats but do not abort the stream — the caller wants
// "ES saw X" coverage even if some events are unparseable.
func StreamES(r io.Reader, fn func(*NormEvent) error) (Stats, error) {
	return streamLines(r, SourceES, ParseESLine, fn)
}

// Stats reports parser outcomes for one stream.
type Stats struct {
	Lines     int // total lines read
	Parsed    int // lines that yielded a NormEvent
	Skipped   int // valid JSON but not a usable exec record
	Malformed int // JSON parse errors
}

// streamLines is shared by the ES and AW stream readers.
func streamLines(
	r io.Reader,
	src Source,
	parse func([]byte) (*NormEvent, bool, error),
	fn func(*NormEvent) error,
) (Stats, error) {
	var st Stats
	sc := bufio.NewScanner(r)
	const maxLine = 1 << 20 // 1 MiB; eslogger records are ~1-3 KiB
	sc.Buffer(make([]byte, 0, 64<<10), maxLine)
	for sc.Scan() {
		st.Lines++
		ev, ok, err := parse(sc.Bytes())
		if err != nil {
			st.Malformed++
			continue
		}
		if !ok {
			st.Skipped++
			continue
		}
		ev.Source = src
		st.Parsed++
		if err := fn(ev); err != nil {
			return st, err
		}
	}
	if err := sc.Err(); err != nil {
		return st, fmt.Errorf("%s: scan: %w", src, err)
	}
	return st, nil
}
