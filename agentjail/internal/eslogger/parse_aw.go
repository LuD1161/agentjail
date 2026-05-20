package eslogger

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// ParseAWLine projects one agentjail events.jsonl record into a NormEvent.
//
// The shape we target is what internal/telemetry.Event writes to disk:
//
//	{
//	  "time_unix_nano": 1716480000000000000,
//	  "body":           "exec/shim",        // hook/op; "exec/*" is what we care about
//	  "attributes": {
//	    "process.pid":        50001,
//	    "process.parent_pid": 50000,
//	    "argv":               ["/bin/ls","-la"],
//	    "real_program":       "/bin/ls",
//	    ...
//	  }
//	}
//
// We match by body prefix "exec/" (covers exec/shim, exec/spawn from the
// runtime hook, and any future exec/* hook). Non-exec rows are skipped.
func ParseAWLine(line []byte) (*NormEvent, bool, error) {
	if len(line) == 0 {
		return nil, false, nil
	}
	var rec struct {
		TimeUnixNano int64          `json:"time_unix_nano"`
		Body         string         `json:"body"`
		Attributes   map[string]any `json:"attributes"`
	}
	if err := json.Unmarshal(line, &rec); err != nil {
		return nil, false, fmt.Errorf("agentjail: parse line: %w", err)
	}
	if !hasExecPrefix(rec.Body) {
		return nil, false, nil
	}

	pid, _ := asInt(rec.Attributes["process.pid"])
	ppid, _ := asInt(rec.Attributes["process.parent_pid"])
	argv := asStringSlice(rec.Attributes["argv"])
	// Prefer real_program (resolved absolute path) when the shim wrote it,
	// falling back to argv[0]. The shim always sets real_program; the
	// runtime hook may only have argv.
	execPath, _ := rec.Attributes["real_program"].(string)
	if execPath == "" && len(argv) > 0 {
		execPath = argv[0]
	}
	if execPath == "" {
		return nil, false, nil
	}

	var t time.Time
	if rec.TimeUnixNano > 0 {
		t = time.Unix(0, rec.TimeUnixNano).UTC()
	}

	rawCopy := make([]byte, len(line))
	copy(rawCopy, line)

	return &NormEvent{
		Source:   SourceAW,
		Time:     t,
		PID:      pid,
		PPID:     ppid,
		ExecPath: execPath,
		Argv:     argv,
		Raw:      rawCopy,
	}, true, nil
}

// StreamAW reads an agentjail events.jsonl file, yielding NormEvents.
func StreamAW(r io.Reader, fn func(*NormEvent) error) (Stats, error) {
	return streamLines(r, SourceAW, ParseAWLine, fn)
}

func hasExecPrefix(body string) bool {
	const p = "exec/"
	return len(body) >= len(p) && body[:len(p)] == p
}

func asInt(v any) (int, bool) {
	switch x := v.(type) {
	case float64:
		return int(x), true
	case int:
		return x, true
	case int64:
		return int(x), true
	case json.Number:
		i, err := x.Int64()
		if err != nil {
			return 0, false
		}
		return int(i), true
	}
	return 0, false
}

func asStringSlice(v any) []string {
	xs, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
