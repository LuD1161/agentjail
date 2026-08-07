package localui

import "testing"

func TestDefaultURLDerivesFromAddr(t *testing.T) {
	if got, want := DefaultURL, "http://"+DefaultAddr; got != want {
		t.Fatalf("DefaultURL = %q, want %q", got, want)
	}
}
