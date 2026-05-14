package v1

import (
	"bytes"
	"encoding/json"
	"testing"
)

// TestResponseEncodingParity locks the v1 Response shape to the bytes the
// per-session daemon writes today. The fixtures below are the exact JSON
// lines the daemon's writeSyncResponse path emits for the four code-path
// kinds documented in commit 264eadd:
//
//   - explicit deny with a rule_id (the "no-rm-rf" path in
//     internal/daemon/daemon_test.go)
//   - ping liveness probe (Action=allow, Reason="ping")
//   - policy-disabled allow (Action=allow, Reason="policy disabled")
//   - eval-error allow (Action=allow, Reason="eval_error")
//
// We assert TWO directions:
//
//  1. Marshal(v1.Response{...}) produces the EXACT same bytes the daemon
//     produces today (modulo Go's stable struct-field ordering — both the
//     daemon and this package list the fields in the same order).
//  2. Unmarshal(daemon_bytes) into v1.Response round-trips lossless.
//
// If this test breaks, the v1 wire shape has drifted. Do NOT loosen the
// fixtures — fix the producer, or write a new versioned package.
func TestResponseEncodingParity(t *testing.T) {
	cases := []struct {
		name    string
		resp    Response
		wantRaw string
	}{
		{
			name: "deny_with_rule_id",
			resp: Response{
				ReqID:  "abc",
				Action: ActionDeny,
				RuleID: "no-rm-rf",
			},
			wantRaw: `{"req_id":"abc","action":"deny","rule_id":"no-rm-rf"}`,
		},
		{
			name: "ping_liveness",
			resp: Response{
				ReqID:  "ping-1",
				Action: ActionAllow,
				Reason: "ping",
			},
			wantRaw: `{"req_id":"ping-1","action":"allow","reason":"ping"}`,
		},
		{
			name: "policy_disabled_allow",
			resp: Response{
				ReqID:  "req-7",
				Action: ActionAllow,
				Reason: "policy disabled",
			},
			wantRaw: `{"req_id":"req-7","action":"allow","reason":"policy disabled"}`,
		},
		{
			name: "eval_error_allow",
			resp: Response{
				ReqID:  "req-9",
				Action: ActionAllow,
				Reason: "eval_error",
			},
			wantRaw: `{"req_id":"req-9","action":"allow","reason":"eval_error"}`,
		},
		{
			name: "allow_no_rule",
			resp: Response{
				ReqID:  "req-11",
				Action: ActionAllow,
				Reason: "no_rule",
			},
			wantRaw: `{"req_id":"req-11","action":"allow","reason":"no_rule"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := json.Marshal(&tc.resp)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if !bytes.Equal(got, []byte(tc.wantRaw)) {
				t.Errorf("marshal mismatch\n got: %s\nwant: %s", got, tc.wantRaw)
			}

			var back Response
			if err := json.Unmarshal([]byte(tc.wantRaw), &back); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if back != tc.resp {
				t.Errorf("round-trip drift\n got: %+v\nwant: %+v", back, tc.resp)
			}
		})
	}
}

// TestRequestEncodingParity locks the v1 Request shape against the bytes
// the existing PEPs send today. The two fixtures cover the two modes:
//
//   - fire-and-forget audit frame (no ReqID)
//   - sync RPC frame (ReqID set; otherwise identical attrs)
//
// Field ordering matches Go's struct-tag ordering: hook, op, pid, ppid,
// track, attrs, req_id. This is the order the daemon's Frame type uses;
// keeping the two in lockstep is the whole point of byte parity.
func TestRequestEncodingParity(t *testing.T) {
	asyncRaw := `{"hook":"exec","pid":42,"track":"native","attrs":{"program":"rm"}}`
	syncRaw := `{"hook":"exec","pid":42,"track":"native","attrs":{"program":"rm"},"req_id":"abc"}`

	for _, tc := range []struct {
		name string
		raw  string
		want Request
	}{
		{
			name: "async_audit_frame",
			raw:  asyncRaw,
			want: Request{
				Hook:       "exec",
				PID:        42,
				Track:      "native",
				Attributes: map[string]any{"program": "rm"},
			},
		},
		{
			name: "sync_rpc_frame",
			raw:  syncRaw,
			want: Request{
				Hook:       "exec",
				PID:        42,
				Track:      "native",
				Attributes: map[string]any{"program": "rm"},
				ReqID:      "abc",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := json.Marshal(&tc.want)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if !bytes.Equal(got, []byte(tc.raw)) {
				t.Errorf("marshal mismatch\n got: %s\nwant: %s", got, tc.raw)
			}

			var back Request
			if err := json.Unmarshal([]byte(tc.raw), &back); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			// map[string]any equality via re-marshal for stable compare.
			gotBack, _ := json.Marshal(&back)
			wantBack, _ := json.Marshal(&tc.want)
			if !bytes.Equal(gotBack, wantBack) {
				t.Errorf("round-trip drift\n got: %s\nwant: %s", gotBack, wantBack)
			}
		})
	}
}

// TestActionEnumClosed pins the v1 verdict set. Adding a new value here
// requires bumping the package version (v2/) per the freeze rule.
func TestActionEnumClosed(t *testing.T) {
	want := map[Action]string{
		ActionAllow: "allow",
		ActionDeny:  "deny",
		ActionAsk:   "ask",
	}
	for a, s := range want {
		if string(a) != s {
			t.Errorf("Action %q != %q", a, s)
		}
		b, err := json.Marshal(a)
		if err != nil {
			t.Fatalf("marshal %q: %v", a, err)
		}
		if string(b) != `"`+s+`"` {
			t.Errorf("Action %q marshal: got %s, want %q", a, b, s)
		}
	}
	if len(want) != 3 {
		t.Fatalf("v1 Action enum size changed (got %d, want 3) — that is a v2 break", len(want))
	}
}
