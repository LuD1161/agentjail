package costindex

import (
	"bytes"
	"testing"
)

func TestNewParserStateJSONBoundsAndValidates(t *testing.T) {
	if state, err := NewParserStateJSON(nil); err != nil || state != "{}" {
		t.Fatalf("empty state = %q, %v", state, err)
	}
	if _, err := NewParserStateJSON([]byte(`{"offset":12}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := NewParserStateJSON([]byte(`{"offset":`)); err == nil {
		t.Fatal("invalid JSON accepted")
	}
	if _, err := NewParserStateJSON(bytes.Repeat([]byte{'x'}, maxParserStateBytes+1)); err == nil {
		t.Fatal("oversized parser state accepted")
	}
}
