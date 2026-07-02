package proxyctl

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNewTokenUniqueAndSized(t *testing.T) {
	seen := make(map[Token]struct{})
	for range 1000 {
		tok, err := NewToken()
		if err != nil {
			t.Fatalf("NewToken: %v", err)
		}
		if tok == "" {
			t.Fatal("NewToken returned empty token")
		}
		// base64url(no pad) of 32 bytes = 43 chars; must contain no ':' so it
		// is safe as the Basic-auth username on the data plane.
		if len(tok) != 43 {
			t.Errorf("token length = %d; want 43 (base64url of %d bytes)", len(tok), TokenBytes)
		}
		if strings.ContainsAny(string(tok), ":/+= ") {
			t.Errorf("token %q contains an unsafe char for Basic-auth username", tok)
		}
		if _, dup := seen[tok]; dup {
			t.Fatalf("NewToken produced a duplicate: %q", tok)
		}
		seen[tok] = struct{}{}
	}
}

func TestFingerprintCompatible(t *testing.T) {
	f := Fingerprint{BinaryVersion: "0.4.0", ProtocolVersion: CurrentProtocolVersion}
	if !f.Compatible(CurrentProtocolVersion) {
		t.Error("same protocol version must be compatible")
	}
	if f.Compatible(CurrentProtocolVersion + 1) {
		t.Error("different protocol version must be incompatible")
	}
	// Binary drift with matching protocol stays compatible (do not restart a
	// proxy serving live sessions for a binary bump).
	f2 := Fingerprint{BinaryVersion: "9.9.9", ProtocolVersion: CurrentProtocolVersion}
	if !f2.Compatible(CurrentProtocolVersion) {
		t.Error("binary drift with matching protocol must stay compatible")
	}
}

func TestRequestResponseJSONRoundTrip(t *testing.T) {
	req := Request{
		Type:       ReqRegister,
		Token:      "abc123",
		Policy:     &SessionPolicy{AllowedHosts: []string{"api.github.com", "*.claude.ai"}},
		LeaseTTLMs: 3600000,
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Request
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Type != ReqRegister || got.Token != "abc123" || got.Policy == nil ||
		len(got.Policy.AllowedHosts) != 2 || got.LeaseTTLMs != 3600000 {
		t.Errorf("round-trip mismatch: %+v", got)
	}

	// Fingerprint request omits token/policy in the wire form.
	fp := Request{Type: ReqFingerprint}
	fb, _ := json.Marshal(fp)
	if strings.Contains(string(fb), "token") || strings.Contains(string(fb), "policy") {
		t.Errorf("fingerprint request should omit token/policy, got %s", fb)
	}

	resp := Response{OK: true, Fingerprint: &Fingerprint{BinaryVersion: "0.4.0", ProtocolVersion: CurrentProtocolVersion}}
	rb, _ := json.Marshal(resp)
	var gotResp Response
	if err := json.Unmarshal(rb, &gotResp); err != nil {
		t.Fatalf("resp unmarshal: %v", err)
	}
	if !gotResp.OK || gotResp.Fingerprint == nil || gotResp.Fingerprint.ProtocolVersion != CurrentProtocolVersion {
		t.Errorf("resp round-trip mismatch: %+v", gotResp)
	}
}

func TestControlSocketPathShape(t *testing.T) {
	p := ControlSocketPath()
	if !strings.HasSuffix(p, "/.agentjail/run/netproxy-ctl.sock") &&
		!strings.HasSuffix(p, "/agentjail-run/netproxy-ctl.sock") {
		t.Errorf("ControlSocketPath = %q; want it under ~/.agentjail/run or the /tmp fallback", p)
	}
	// The control socket must NOT be the daemon socket path.
	if strings.HasSuffix(p, "daemon.sock") {
		t.Errorf("control socket collides with daemon socket: %q", p)
	}
}
