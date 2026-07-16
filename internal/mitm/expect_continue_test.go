package mitm

import (
	"net/http"
	"testing"
)

// http.ReadRequest hands back the Expect header untouched; nothing answered it,
// so draining the body blocked on bytes the client was still waiting to be
// invited to send. Every large upload hung. AGE-226.
func TestHasExpectContinue(t *testing.T) {
	for _, tc := range []struct {
		name   string
		proto  string
		major  int
		minor  int
		header string
		want   bool
	}{
		{name: "absent", proto: "HTTP/1.1", major: 1, minor: 1, header: "", want: false},
		{name: "present", proto: "HTTP/1.1", major: 1, minor: 1, header: "100-continue", want: true},
		{name: "case-insensitive", proto: "HTTP/1.1", major: 1, minor: 1, header: "100-Continue", want: true},
		{name: "padded", proto: "HTTP/1.1", major: 1, minor: 1, header: " 100-continue ", want: true},
		{name: "in a list", proto: "HTTP/1.1", major: 1, minor: 1, header: "foo, 100-continue", want: true},
		{name: "other expectation", proto: "HTTP/1.1", major: 1, minor: 1, header: "other", want: false},
		// HTTP/1.0 has no interim responses: answering one would desync the
		// connection rather than unblock it.
		{name: "http/1.0 ignores it", proto: "HTTP/1.0", major: 1, minor: 0, header: "100-continue", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &http.Request{
				Proto:      tc.proto,
				ProtoMajor: tc.major,
				ProtoMinor: tc.minor,
				Header:     http.Header{},
			}
			if tc.header != "" {
				req.Header.Set("Expect", tc.header)
			}
			if got := hasExpectContinue(req); got != tc.want {
				t.Errorf("hasExpectContinue(Expect: %q, %s) = %v, want %v", tc.header, tc.proto, got, tc.want)
			}
		})
	}
}
