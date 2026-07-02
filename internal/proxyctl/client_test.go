package proxyctl

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeControlServer serves one control request per connection using handler,
// on a short-path unix socket, until the returned stop is called.
func fakeControlServer(t *testing.T, handler func(Request) Response) (string, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ajpc")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	sock := filepath.Join(dir, "ctl.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var req Request
				if json.NewDecoder(c).Decode(&req) != nil {
					return
				}
				_ = json.NewEncoder(c).Encode(handler(req))
			}(conn)
		}
	}()
	return sock, func() { ln.Close(); os.RemoveAll(dir) }
}

func TestQueryFingerprint(t *testing.T) {
	sock, stop := fakeControlServer(t, func(req Request) Response {
		if req.Type != ReqFingerprint {
			return Response{OK: false, Error: "unexpected"}
		}
		return Response{OK: true, Fingerprint: &Fingerprint{BinaryVersion: "9.9", ProtocolVersion: CurrentProtocolVersion}}
	})
	defer stop()

	fp, err := QueryFingerprint(sock, time.Second)
	if err != nil {
		t.Fatalf("QueryFingerprint: %v", err)
	}
	if !fp.Compatible(CurrentProtocolVersion) {
		t.Errorf("fingerprint not compatible: %+v", fp)
	}
}

func TestQueryFingerprintNoServer(t *testing.T) {
	// A path with nothing listening must return a dial error, not hang.
	if _, err := QueryFingerprint("/tmp/definitely-not-a-socket-ajpc.sock", 200*time.Millisecond); err == nil {
		t.Error("expected dial error when no proxy is serving the socket")
	}
}

func TestRegister(t *testing.T) {
	var got Request
	sock, stop := fakeControlServer(t, func(req Request) Response {
		got = req
		if req.Type != ReqRegister || req.Token == "" || req.Policy == nil {
			return Response{OK: false, Error: "bad register"}
		}
		return Response{OK: true}
	})
	defer stop()

	err := Register(sock, Token("tok-1"), "sess-1", "/home/agent/proj", SessionPolicy{AllowedHosts: []string{"a.com", "b.com"}}, time.Hour, time.Second)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if got.Token != "tok-1" || got.Policy == nil || len(got.Policy.AllowedHosts) != 2 {
		t.Errorf("server saw wrong register payload: %+v", got)
	}
	if got.SessionID != "sess-1" || got.Cwd != "/home/agent/proj" {
		t.Errorf("server saw wrong session identity: %+v", got)
	}
	if got.LeaseTTLMs != time.Hour.Milliseconds() {
		t.Errorf("lease ttl = %d ms; want %d", got.LeaseTTLMs, time.Hour.Milliseconds())
	}
}

func TestRegisterRefused(t *testing.T) {
	sock, stop := fakeControlServer(t, func(Request) Response {
		return Response{OK: false, Error: "nope"}
	})
	defer stop()

	if err := Register(sock, Token("t"), "sess", "/cwd", SessionPolicy{}, time.Hour, time.Second); err == nil {
		t.Error("expected error when the proxy refuses the register")
	}
}

func TestGrantList(t *testing.T) {
	want := []GrantInfo{
		{GrantID: "g1", Host: "example.com", TTLMs: 3600000, Cwd: "/home/agent/proj", Reason: "need npm registry"},
		{GrantID: "g2", Host: "api.foo.dev", TTLMs: 1800000},
	}
	sock, stop := fakeControlServer(t, func(req Request) Response {
		if req.Type != ReqGrantList {
			return Response{OK: false, Error: "unexpected"}
		}
		if req.Token != "" || req.SessionID != "" {
			return Response{OK: false, Error: "grant_list must not carry a token or session id"}
		}
		return Response{OK: true, Grants: want}
	})
	defer stop()

	got, err := GrantList(sock, time.Second)
	if err != nil {
		t.Fatalf("GrantList: %v", err)
	}
	if len(got) != 2 || got[0].GrantID != "g1" || got[1].Host != "api.foo.dev" {
		t.Errorf("GrantList = %+v; want %+v", got, want)
	}
}

func TestGrantListRefused(t *testing.T) {
	sock, stop := fakeControlServer(t, func(Request) Response {
		return Response{OK: false, Error: "audit unavailable"}
	})
	defer stop()

	if _, err := GrantList(sock, time.Second); err == nil {
		t.Error("expected error when the proxy refuses grant_list")
	}
}

func TestGrantApprove(t *testing.T) {
	var got Request
	sock, stop := fakeControlServer(t, func(req Request) Response {
		got = req
		if req.Type != ReqGrantApprove || req.GrantID == "" {
			return Response{OK: false, Error: "bad approve"}
		}
		if req.Token != "" {
			return Response{OK: false, Error: "grant_approve must not carry a token"}
		}
		return Response{OK: true}
	})
	defer stop()

	if err := GrantApprove(sock, "g1", time.Second); err != nil {
		t.Fatalf("GrantApprove: %v", err)
	}
	if got.GrantID != "g1" {
		t.Errorf("server saw grant id %q; want g1", got.GrantID)
	}
}

func TestGrantApproveRefused(t *testing.T) {
	sock, stop := fakeControlServer(t, func(Request) Response {
		return Response{OK: false, Error: "unknown grant id"}
	})
	defer stop()

	if err := GrantApprove(sock, "missing", time.Second); err == nil {
		t.Error("expected error when the proxy refuses grant_approve")
	}
}

func TestGrantDeny(t *testing.T) {
	var got Request
	sock, stop := fakeControlServer(t, func(req Request) Response {
		got = req
		if req.Type != ReqGrantDeny || req.GrantID == "" {
			return Response{OK: false, Error: "bad deny"}
		}
		return Response{OK: true}
	})
	defer stop()

	if err := GrantDeny(sock, "g2", time.Second); err != nil {
		t.Fatalf("GrantDeny: %v", err)
	}
	if got.GrantID != "g2" {
		t.Errorf("server saw grant id %q; want g2", got.GrantID)
	}
}

func TestGrantDenyRefused(t *testing.T) {
	sock, stop := fakeControlServer(t, func(Request) Response {
		return Response{OK: false, Error: "unknown grant id"}
	})
	defer stop()

	if err := GrantDeny(sock, "missing", time.Second); err == nil {
		t.Error("expected error when the proxy refuses grant_deny")
	}
}
