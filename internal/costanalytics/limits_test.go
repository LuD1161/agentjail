package costanalytics

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

type countingReadSeeker struct {
	reader *strings.Reader
	read   int
}

func (r *countingReadSeeker) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.read += n
	return n, err
}

func (r *countingReadSeeker) Seek(offset int64, whence int) (int64, error) {
	return r.reader.Seek(offset, whence)
}

var _ io.ReadSeeker = (*countingReadSeeker)(nil)

func TestParsePeriodBounds(t *testing.T) {
	tests := []struct {
		value string
		want  time.Duration
		ok    bool
	}{
		{value: "90d", want: 90 * 24 * time.Hour, ok: true},
		{value: "2160h", want: 90 * 24 * time.Hour, ok: true},
		{value: "91d"},
		{value: "2161h"},
		{value: "999999999999999999999d"},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			got, err := ParsePeriod(test.value)
			if (err == nil) != test.ok {
				t.Fatalf("ParsePeriod(%q) error = %v", test.value, err)
			}
			if got != test.want {
				t.Fatalf("ParsePeriod(%q) = %s, want %s", test.value, got, test.want)
			}
		})
	}
}

func TestAppendSessionCostsCapsResults(t *testing.T) {
	existing := make([]SessionCost, maxSessionCosts-1)
	got, err := appendSessionCosts(existing, []SessionCost{{}, {}})
	if err == nil || len(got) != maxSessionCosts {
		t.Fatalf("got len=%d err=%v, want capped result and error", len(got), err)
	}
}

func TestTranscriptScannerSkipsOversizedLineAndContinues(t *testing.T) {
	input := "first\n" + strings.Repeat("x", maxTranscriptLineBytes+2) + "\nlast\n"
	scanner := newTranscriptScanner(strings.NewReader(input))

	var lines []string
	for scanner.Scan() {
		if len(scanner.Bytes()) > 0 {
			lines = append(lines, string(scanner.Bytes()))
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(lines, ","); got != "first,last" {
		t.Fatalf("lines = %q, want oversized record skipped and later record read", got)
	}
}

func TestTranscriptScannerKeepsLegacyFinalRecordWithoutNewline(t *testing.T) {
	scanner := newTranscriptScanner(strings.NewReader("final"))
	if !scanner.Scan() || string(scanner.Bytes()) != "final" {
		t.Fatalf("final record = %q", scanner.Bytes())
	}
	if scanner.Scan() || scanner.Err() != nil {
		t.Fatalf("scanner ended with err=%v", scanner.Err())
	}
}

func TestJSONLCursorCheckpointsOnlyCompleteRecords(t *testing.T) {
	input := strings.NewReader("first\npartial")
	cursor, err := NewJSONLCursor(input, JSONLCursorState{})
	if err != nil {
		t.Fatal(err)
	}
	if !cursor.Scan() || string(cursor.Record().Bytes) != "first" || cursor.Record().Offset != 0 {
		t.Fatalf("first record = %+v", cursor.Record())
	}
	if cursor.Scan() {
		t.Fatalf("incomplete record was returned: %+v", cursor.Record())
	}
	if err := cursor.Err(); err != nil {
		t.Fatal(err)
	}
	if got := cursor.State(); got.Offset != int64(len("first\n")) || got.DiscardingOversized {
		t.Fatalf("state = %+v, want checkpoint before partial record", got)
	}

	resumed, err := NewJSONLCursor(strings.NewReader("first\npartial-rest\n"), cursor.State())
	if err != nil {
		t.Fatal(err)
	}
	if !resumed.Scan() || string(resumed.Record().Bytes) != "partial-rest" {
		t.Fatalf("resumed record = %+v", resumed.Record())
	}
	if got := resumed.Scan(); got || resumed.Err() != nil {
		t.Fatalf("resumed cursor ended with scan=%v err=%v", got, resumed.Err())
	}
}

func TestJSONLCursorResumesOversizedRecordDiscard(t *testing.T) {
	first := strings.Repeat("x", maxTranscriptLineBytes+1)
	cursor, err := NewJSONLCursor(strings.NewReader(first), JSONLCursorState{})
	if err != nil {
		t.Fatal(err)
	}
	if got := cursor.Scan(); got || cursor.Err() != nil {
		t.Fatalf("oversized partial record scan=%v err=%v", got, cursor.Err())
	}
	state := cursor.State()
	if state.Offset != int64(len(first)) || !state.DiscardingOversized {
		t.Fatalf("state = %+v, want discard checkpoint at EOF", state)
	}

	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	var restored JSONLCursorState
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	full := first + "tail\nvalid\n"
	resumed, err := NewJSONLCursor(strings.NewReader(full), restored)
	if err != nil {
		t.Fatal(err)
	}
	if !resumed.Scan() || string(resumed.Record().Bytes) != "valid" {
		t.Fatalf("resumed record = %+v", resumed.Record())
	}
	if got := resumed.State(); got.Offset != int64(len(full)) || got.DiscardingOversized {
		t.Fatalf("resumed state = %+v", got)
	}
}

func TestJSONLCursorResumeReadsOnlyAppendedSuffix(t *testing.T) {
	prefix := strings.Repeat("old-record\n", 100_000)
	suffix := "new-record\n"
	reader := &countingReadSeeker{reader: strings.NewReader(prefix + suffix)}
	cursor, err := NewJSONLCursor(reader, JSONLCursorState{Offset: int64(len(prefix))})
	if err != nil {
		t.Fatal(err)
	}
	if !cursor.Scan() || string(cursor.Record().Bytes) != "new-record" {
		t.Fatalf("record = %+v", cursor.Record())
	}
	if reader.read != len(suffix) {
		t.Fatalf("read %d bytes, want appended suffix only (%d)", reader.read, len(suffix))
	}
}
