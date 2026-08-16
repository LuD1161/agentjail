package daemonapp

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/grantctl"
)

type frameAuditEmitter struct {
	calls atomic.Int32
}

func (e *frameAuditEmitter) Emit(context.Context, audit.Event) error {
	e.calls.Add(1)
	return nil
}

func startControlFrameServer(t *testing.T, registry *grantctl.Registry, emitter audit.Emitter, reload func(context.Context) error) string {
	t.Helper()
	sock := filepath.Join(shortTempDir(t), "frame.sock")
	server, err := newGrantServer(sock, testCtlToken, registry, emitter, true, nil, reload)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go server.serveCtl(ctx)
	return sock
}

func encodeControlRequestFrame(t *testing.T, request grantctl.Request) []byte {
	t.Helper()
	var frame bytes.Buffer
	if err := grantctl.WriteRequestFrame(&frame, request); err != nil {
		t.Fatal(err)
	}
	return frame.Bytes()
}

func writeRawControlFrame(t *testing.T, conn net.Conn, frame []byte) {
	t.Helper()
	for len(frame) > 0 {
		n, err := conn.Write(frame)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Fatal("zero-byte control frame write")
		}
		frame = frame[n:]
	}
}

func rawControlFrameRoundTrip(t *testing.T, sock string, frame []byte, closeWrite bool) grantctl.Response {
	t.Helper()
	conn, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	writeRawControlFrame(t, conn, frame)
	if closeWrite {
		unixConn, ok := conn.(*net.UnixConn)
		if !ok {
			t.Fatalf("control connection = %T, want *net.UnixConn", conn)
		}
		if err := unixConn.CloseWrite(); err != nil {
			t.Fatal(err)
		}
	}
	response, err := grantctl.ReadResponseFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func requireMalformedControlFrame(t *testing.T, response grantctl.Response) {
	t.Helper()
	if response.OK || response.Error != "malformed grant control request" {
		t.Fatalf("malformed frame response = %+v", response)
	}
}

func TestControlRequestFrameFailuresDoNotDispatch(t *testing.T) {
	t.Run("trailing value cannot deny", func(t *testing.T) {
		registry := grantctl.NewRegistry()
		now := time.Now()
		grant, err := registry.RequestGrant("s1", "/project", "api.example.test", 1000, "reason", now)
		if err != nil {
			t.Fatal(err)
		}
		sock := startControlFrameServer(t, registry, &frameAuditEmitter{}, nil)
		frame := []byte(fmt.Sprintf("{\"type\":\"grant_deny\",\"ctl_token\":%q,\"grant_id\":%q} {}\n", testCtlToken, grant.GrantID))

		requireMalformedControlFrame(t, rawControlFrameRoundTrip(t, sock, frame, false))
		pending := registry.ListPending(now)
		if len(pending) != 1 || pending[0].GrantID != grant.GrantID {
			t.Fatalf("trailing value reached deny dispatch: %+v", pending)
		}
	})

	t.Run("missing delimiter cannot reload", func(t *testing.T) {
		var reloads atomic.Int32
		emitter := &frameAuditEmitter{}
		sock := startControlFrameServer(t, grantctl.NewRegistry(), emitter, func(context.Context) error {
			reloads.Add(1)
			return nil
		})
		frame := []byte(fmt.Sprintf("{\"type\":\"daemon_reload\",\"ctl_token\":%q}", testCtlToken))

		requireMalformedControlFrame(t, rawControlFrameRoundTrip(t, sock, frame, true))
		if reloads.Load() != 0 || emitter.calls.Load() != 0 {
			t.Fatalf("missing delimiter dispatched reload=%d audit=%d", reloads.Load(), emitter.calls.Load())
		}
	})

	t.Run("oversize cannot audit", func(t *testing.T) {
		emitter := &frameAuditEmitter{}
		var reloads atomic.Int32
		sock := startControlFrameServer(t, grantctl.NewRegistry(), emitter, func(context.Context) error {
			reloads.Add(1)
			return nil
		})
		prefix := []byte(fmt.Sprintf("{\"type\":\"update_audit\",\"ctl_token\":%q,\"update_status\":\"completed\",\"update_version\":\"v1\",\"update_os\":\"darwin\"}", testCtlToken))
		frame := append(prefix, bytes.Repeat([]byte{' '}, grantctl.MaxControlMsgBytes-len(prefix))...)
		frame = append(frame, '\n')

		requireMalformedControlFrame(t, rawControlFrameRoundTrip(t, sock, frame, false))
		if emitter.calls.Load() != 0 || reloads.Load() != 0 {
			t.Fatalf("oversize frame dispatched audit=%d reload=%d", emitter.calls.Load(), reloads.Load())
		}
	})

	t.Run("malformed JSON cannot dispatch", func(t *testing.T) {
		var reloads atomic.Int32
		emitter := &frameAuditEmitter{}
		sock := startControlFrameServer(t, grantctl.NewRegistry(), emitter, func(context.Context) error {
			reloads.Add(1)
			return nil
		})

		requireMalformedControlFrame(t, rawControlFrameRoundTrip(t, sock, []byte("{\n"), false))
		if reloads.Load() != 0 || emitter.calls.Load() != 0 {
			t.Fatalf("malformed JSON dispatched reload=%d audit=%d", reloads.Load(), emitter.calls.Load())
		}
	})
}

func TestControlRequestFrameAdditiveFieldsAndTypedDispatch(t *testing.T) {
	var reloads atomic.Int32
	emitter := &frameAuditEmitter{}
	sock := startControlFrameServer(t, grantctl.NewRegistry(), emitter, func(context.Context) error {
		reloads.Add(1)
		return nil
	})

	additive := []byte(fmt.Sprintf("{\"type\":\"daemon_reload\",\"ctl_token\":%q,\"future_envelope\":true}\n", testCtlToken))
	if response := rawControlFrameRoundTrip(t, sock, additive, false); !response.OK {
		t.Fatalf("additive request field was rejected: %+v", response)
	}
	if reloads.Load() != 1 {
		t.Fatalf("additive request dispatched reload %d times", reloads.Load())
	}

	unknownType := []byte(fmt.Sprintf("{\"type\":\"future_operation\",\"ctl_token\":%q,\"future_envelope\":true}\n", testCtlToken))
	response := rawControlFrameRoundTrip(t, sock, unknownType, false)
	if response.OK || !strings.Contains(response.Error, "unsupported grant control request") {
		t.Fatalf("unknown typed operation response = %+v", response)
	}
	if reloads.Load() != 1 || emitter.calls.Load() != 0 {
		t.Fatalf("unknown operation dispatched reload=%d audit=%d", reloads.Load(), emitter.calls.Load())
	}
}

func TestControlRequestFrameDispatchesOnlyFirstFrame(t *testing.T) {
	var reloads atomic.Int32
	emitter := &frameAuditEmitter{}
	sock := startControlFrameServer(t, grantctl.NewRegistry(), emitter, func(context.Context) error {
		reloads.Add(1)
		return nil
	})

	first := encodeControlRequestFrame(t, grantctl.Request{Type: grantctl.ReqDaemonReload, CtlToken: testCtlToken})
	second := encodeControlRequestFrame(t, grantctl.Request{
		Type:          grantctl.ReqUpdateAudit,
		CtlToken:      testCtlToken,
		UpdateStatus:  grantctl.UpdateAuditCompleted,
		UpdateVersion: "v1",
		UpdateOS:      "darwin",
	})
	conn, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	writeRawControlFrame(t, conn, append(first, second...))
	response, err := grantctl.ReadResponseFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !response.OK {
		t.Fatalf("first frame response = %+v", response)
	}
	var extra [1]byte
	if n, err := conn.Read(extra[:]); n != 0 || err == nil {
		t.Fatalf("connection remained open for a second frame: n=%d err=%v", n, err)
	} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatalf("connection timed out instead of closing after one frame: %v", err)
	}
	if reloads.Load() != 1 || emitter.calls.Load() != 0 {
		t.Fatalf("two frames dispatched reload=%d audit=%d", reloads.Load(), emitter.calls.Load())
	}
}

func TestControlResponseFrameOversizeBecomesOneRefusal(t *testing.T) {
	registry := grantctl.NewRegistry()
	created := time.Now()
	const marker = "original-oversized-list-marker"
	for i := range grantctl.MaxPendingGlobal {
		session := fmt.Sprintf("session-%d", i/grantctl.MaxPendingPerSession)
		host := fmt.Sprintf("host-%03d.example.test", i)
		cwd := "/" + strings.Repeat(marker, 80)
		if _, err := registry.RequestGrant(session, cwd, host, 1000, strings.Repeat("r", grantctl.MaxReasonLen), created); err != nil {
			t.Fatalf("seed grant %d: %v", i, err)
		}
	}
	sock := startControlFrameServer(t, registry, &frameAuditEmitter{}, nil)
	request := encodeControlRequestFrame(t, grantctl.Request{Type: grantctl.ReqGrantList, CtlToken: testCtlToken})
	response := rawControlFrameRoundTrip(t, sock, request, false)
	if response.OK || response.Error != "control response exceeds maximum frame size" || response.Grants != nil {
		t.Fatalf("oversized list response = %+v", response)
	}
}
