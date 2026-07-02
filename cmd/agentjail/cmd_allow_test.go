package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
)

// fakeSentinelProxy is an httptest.Server that plays the role of the
// netproxy data-plane proxy the sandboxed agent's HTTP_PROXY/HTTPS_PROXY
// points at. runAllowHost is only expected to talk to it via the standard
// proxy-env resolution (http.ProxyFromEnvironment) -- never a hardcoded
// address -- matching the plan's Codex note.
//
// net/http caches http.ProxyFromEnvironment's env-var resolution ONCE per
// process (sync.Once), so every test in this file MUST share a single
// server and only vary its canned response -- a second httptest.Server with
// a different env-set-after-first-call would be silently ignored.
type fakeSentinelProxy struct {
	mu      sync.Mutex
	status  int
	body    []byte
	lastReq *http.Request
	calls   int
}

var (
	sharedSentinelProxy     *fakeSentinelProxy
	sharedSentinelProxyOnce sync.Once
)

// getSharedSentinelProxy lazily starts the one-and-only fake sentinel proxy
// for the process and points HTTP(S)_PROXY at it. Safe to call from every
// test in this file; the server outlives all of them (process exit cleans
// it up) since http.ProxyFromEnvironment's cache would outlive a per-test
// t.Cleanup anyway.
func getSharedSentinelProxy(t *testing.T) *fakeSentinelProxy {
	t.Helper()
	sharedSentinelProxyOnce.Do(func() {
		f := &fakeSentinelProxy{}
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			f.calls++
			f.lastReq = r
			status, body := f.status, f.body
			f.mu.Unlock()
			w.WriteHeader(status)
			_, _ = w.Write(body)
		}))
		_ = os.Setenv("HTTP_PROXY", ts.URL)
		_ = os.Setenv("http_proxy", ts.URL)
		_ = os.Setenv("HTTPS_PROXY", ts.URL)
		_ = os.Setenv("https_proxy", ts.URL)
		_ = os.Setenv("NO_PROXY", "")
		_ = os.Setenv("no_proxy", "")
		sharedSentinelProxy = f
	})
	return sharedSentinelProxy
}

func (f *fakeSentinelProxy) set(status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = status
	f.body = []byte(body)
}

func (f *fakeSentinelProxy) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestRunAllowHost_PendingOnAccepted(t *testing.T) {
	fake := getSharedSentinelProxy(t)
	fake.set(http.StatusAccepted, `{"grant_id":"g-123","host":"api.example.com","ttl_ms":3600000}`)

	stdout, stderr, code := captureOutput(t, func() int {
		return runAllowHost("api.example.com", "1h", "need it for tests")
	})

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "pending human approval") {
		t.Errorf("stdout missing pending message: %q", stdout)
	}
	if !strings.Contains(stdout, "g-123") {
		t.Errorf("stdout missing grant_id: %q", stdout)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.calls == 0 {
		t.Fatal("sentinel proxy was never called")
	}
	if fake.lastReq == nil {
		t.Fatal("no request captured")
	}
	if got := fake.lastReq.Method; got != http.MethodGet {
		t.Errorf("method = %q, want GET", got)
	}
	if got := fake.lastReq.URL.Host; got != "grant.agentjail.local" {
		t.Errorf("request authority = %q, want grant.agentjail.local", got)
	}
	if got := fake.lastReq.URL.Path; got != "/allow" {
		t.Errorf("request path = %q, want /allow", got)
	}
	q := fake.lastReq.URL.Query()
	if got := q.Get("host"); got != "api.example.com" {
		t.Errorf("host query param = %q, want api.example.com", got)
	}
	if got := q.Get("ttl"); got != "1h" {
		t.Errorf("ttl query param = %q, want 1h", got)
	}
	if got := q.Get("reason"); got != "need it for tests" {
		t.Errorf("reason query param = %q, want %q", got, "need it for tests")
	}
}

func TestRunAllowHost_ServerRefusal(t *testing.T) {
	fake := getSharedSentinelProxy(t)

	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"bad_host", http.StatusBadRequest, "invalid host"},
		{"unknown_token", http.StatusProxyAuthRequired, "unknown token"},
		{"over_cap", http.StatusTooManyRequests, "pending cap exceeded"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake.set(tc.status, tc.body)
			_, stderr, code := captureOutput(t, func() int {
				return runAllowHost("api.example.com", "1h", "")
			})
			if code == 0 {
				t.Fatalf("exit code = 0, want non-zero for status %d", tc.status)
			}
			if !strings.Contains(stderr, tc.body) {
				t.Errorf("stderr missing server message %q: %q", tc.body, stderr)
			}
		})
	}
}

func TestRunAllowHost_LocalValidationFailsBeforeNetwork(t *testing.T) {
	fake := getSharedSentinelProxy(t)
	fake.set(http.StatusAccepted, `{}`)

	before := fake.callCount()
	_, stderr, code := captureOutput(t, func() int {
		return runAllowHost("not-a-valid-bare-hostname", "1h", "")
	})
	if code == 0 {
		t.Fatal("exit code = 0, want non-zero for a host that fails hostgrant.Validate")
	}
	if stderr == "" {
		t.Error("expected a validation error message on stderr")
	}
	if fake.callCount() != before {
		t.Errorf("sentinel proxy was called (%d times) even though local validation should have failed first", fake.callCount()-before)
	}
}

func TestRunAllowHost_InvalidTTL(t *testing.T) {
	fake := getSharedSentinelProxy(t)
	fake.set(http.StatusAccepted, `{}`)

	before := fake.callCount()
	_, stderr, code := captureOutput(t, func() int {
		return runAllowHost("api.example.com", "not-a-duration", "")
	})
	if code == 0 {
		t.Fatal("exit code = 0, want non-zero for an invalid --ttl")
	}
	if !strings.Contains(stderr, "ttl") {
		t.Errorf("stderr should mention ttl: %q", stderr)
	}
	if fake.callCount() != before {
		t.Errorf("sentinel proxy was called even though --ttl should have failed validation first")
	}
}

func TestRunAllowHost_ReasonTooLong(t *testing.T) {
	fake := getSharedSentinelProxy(t)
	fake.set(http.StatusAccepted, `{}`)

	before := fake.callCount()
	longReason := strings.Repeat("x", 257)
	_, stderr, code := captureOutput(t, func() int {
		return runAllowHost("api.example.com", "1h", longReason)
	})
	if code == 0 {
		t.Fatal("exit code = 0, want non-zero for an over-long --reason")
	}
	if stderr == "" {
		t.Error("expected an error message on stderr")
	}
	if fake.callCount() != before {
		t.Errorf("sentinel proxy was called even though --reason should have failed validation first")
	}
}

// TestSentinelURLIsWellFormed guards against a typo in the sentinel URL
// constant regressing the whole request path.
func TestSentinelURLIsWellFormed(t *testing.T) {
	u, err := url.Parse(sentinelAllowURL)
	if err != nil {
		t.Fatalf("sentinelAllowURL does not parse: %v", err)
	}
	if u.Host != "grant.agentjail.local" || u.Path != "/allow" || u.Scheme != "http" {
		t.Errorf("sentinelAllowURL = %q, want http://grant.agentjail.local/allow", sentinelAllowURL)
	}
}
