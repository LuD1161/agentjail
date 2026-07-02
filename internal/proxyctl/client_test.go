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

	err := Register(sock, Token("tok-1"), SessionPolicy{AllowedHosts: []string{"a.com", "b.com"}}, time.Hour, time.Second)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if got.Token != "tok-1" || got.Policy == nil || len(got.Policy.AllowedHosts) != 2 {
		t.Errorf("server saw wrong register payload: %+v", got)
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

	if err := Register(sock, Token("t"), SessionPolicy{}, time.Hour, time.Second); err == nil {
		t.Error("expected error when the proxy refuses the register")
	}
}
