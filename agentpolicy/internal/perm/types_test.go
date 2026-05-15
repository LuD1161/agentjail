package perm

import (
	"encoding/json"
	"testing"
)

// TestActionConstants pins the on-the-wire spelling. These strings appear
// in audit events and in the experimental rego rules; changing one without
// updating both is a compatibility break.
func TestActionConstants(t *testing.T) {
	cases := []struct {
		got  Action
		want string
	}{
		{ActionExec, "exec"},
		{ActionRead, "read"},
		{ActionWrite, "write"},
		{ActionFetch, "fetch"},
		{ActionMCPCall, "mcp_call"},
		{ActionCredUse, "cred_use"},
	}
	for _, c := range cases {
		if string(c.got) != c.want {
			t.Errorf("Action %q != %q", c.got, c.want)
		}
	}
}

// TestRequestRoundTrip ensures the JSON shape is stable end-to-end so
// frame ingest, OPA input, and audit emission all read the same field
// names without per-site translation.
func TestRequestRoundTrip(t *testing.T) {
	req := CheckResourcesRequest{
		RequestID: "req-1",
		Principal: Principal{
			ID:    "claude-code:01J6F",
			Roles: []string{"interactive"},
			Attr:  map[string]any{"user": "testuser"},
		},
		Resource: Resource{
			ID:   "subprocess:rm",
			Kind: "subprocess",
			Attr: map[string]any{"program": "rm"},
		},
		Action:  ActionExec,
		Context: Context{Home: "/Users/testuser", CwdRepo: "/Users/testuser/Repos/agentjail"},
	}
	b, err := json.Marshal(&req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back CheckResourcesRequest
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.RequestID != req.RequestID {
		t.Errorf("request id: %q != %q", back.RequestID, req.RequestID)
	}
	if back.Principal.ID != req.Principal.ID {
		t.Errorf("principal id: %q != %q", back.Principal.ID, req.Principal.ID)
	}
	if back.Action != req.Action {
		t.Errorf("action: %q != %q", back.Action, req.Action)
	}
	if back.Context.Home != req.Context.Home {
		t.Errorf("context.home: %q != %q", back.Context.Home, req.Context.Home)
	}
}

// TestZeroValuesOmit pins the omitempty behavior. Zero-valued requests
// must not pollute the OPA input with empty roles / attrs / context.
func TestZeroValuesOmit(t *testing.T) {
	b, err := json.Marshal(&CheckResourcesRequest{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := raw["request_id"]; ok {
		t.Errorf("request_id should be omitted when empty: %s", string(b))
	}
	// principal + resource + action always serialize (they are required
	// to identify a request) even when zero-valued.
	if _, ok := raw["principal"]; !ok {
		t.Errorf("principal should always serialize: %s", string(b))
	}
	if _, ok := raw["resource"]; !ok {
		t.Errorf("resource should always serialize: %s", string(b))
	}
}
