package daemonapp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/grantctl"
)

type reviewSnapshotProjectorFunc func(time.Time) grantctl.ReviewSnapshotV1

func (f reviewSnapshotProjectorFunc) ReviewSnapshot(now time.Time) grantctl.ReviewSnapshotV1 {
	return f(now)
}

type reviewAuditEmitter struct {
	calls atomic.Int32
}

func (e *reviewAuditEmitter) Emit(context.Context, audit.Event) error {
	e.calls.Add(1)
	return nil
}

func startReviewControlServer(t *testing.T, registry *grantctl.Registry, projector reviewSnapshotProjector, emitter audit.Emitter, reload func(context.Context) error) string {
	t.Helper()
	if registry == nil {
		registry = grantctl.NewRegistry()
	}
	if emitter == nil {
		emitter = audit.NopEmitter{}
	}

	sock := filepath.Join(shortTempDir(t), "review.sock")
	server, err := newGrantServer(sock, testCtlToken, registry, emitter, true, nil, reload)
	if err != nil {
		t.Fatal(err)
	}
	if projector != nil {
		server.reviews = projector
	}
	t.Cleanup(server.close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go server.serveCtl(ctx)
	return sock
}

func reviewControlRoundTrip(t *testing.T, sock string, request grantctl.Request) grantctl.Response {
	t.Helper()
	conn, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if err := grantctl.WriteRequestFrame(conn, request); err != nil {
		t.Fatal(err)
	}
	response, err := grantctl.ReadResponseFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func emptyReviewSnapshot(now time.Time) grantctl.ReviewSnapshotV1 {
	return grantctl.ReviewSnapshotV1{
		ProtocolVersion:   grantctl.ReviewProtocolVersion,
		GeneratedAtUnixMs: grantctl.UnixMilliseconds(now.UnixMilli()),
		Reviews:           []grantctl.ReviewInfo{},
	}
}

func TestReviewSnapshotResponseProjectsBoundAndUnbound(t *testing.T) {
	now := time.UnixMilli(1_786_816_800_123)
	registry := grantctl.NewRegistry()
	bound, err := registry.RequestGrant("bound-session", "/reported/not-authoritative", "api.example.test", 60_000, "bound reason", now.Add(-2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	registry.SetBoundCWD(bound.GrantID, "/Users/demo/verified-project")
	unbound, err := registry.RequestGrant("unbound-session", "/reported/darwin-cwd", "packages.example.test", 60_000, "unbound reason", now.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}

	response := reviewSnapshotResponse(registry, grantctl.ReviewProtocolVersion, now)
	if !response.OK || response.ReviewSnapshot == nil {
		t.Fatalf("review response = %+v", response)
	}
	snapshot := response.ReviewSnapshot
	if snapshot.ProtocolVersion != grantctl.ReviewProtocolVersion || snapshot.GeneratedAtUnixMs != grantctl.UnixMilliseconds(now.UnixMilli()) {
		t.Fatalf("snapshot metadata = %+v", snapshot)
	}
	if snapshot.TotalPending != 2 || snapshot.Truncated || len(snapshot.Reviews) != 2 {
		t.Fatalf("snapshot cardinality = %+v", snapshot)
	}

	byID := make(map[grantctl.ReviewID]grantctl.ReviewInfo, len(snapshot.Reviews))
	for _, review := range snapshot.Reviews {
		byID[review.ReviewID] = review
	}
	boundReview := byID[grantctl.ReviewID(bound.GrantID)]
	if boundReview.ProjectPath != "/Users/demo/verified-project" || boundReview.ContextState != grantctl.ReviewContextStateVerified || !boundReview.CanApprove || !boundReview.CanDeny {
		t.Fatalf("bound review = %+v", boundReview)
	}
	unboundReview := byID[grantctl.ReviewID(unbound.GrantID)]
	if unboundReview.ProjectPath != "" || unboundReview.ContextState != grantctl.ReviewContextStateUnbound || unboundReview.CanApprove || !unboundReview.CanDeny {
		t.Fatalf("unbound review = %+v", unboundReview)
	}
}

func TestReviewSnapshotAuthenticationAndVersionGatePrecedeProjection(t *testing.T) {
	tests := []struct {
		name    string
		request grantctl.Request
		wantErr string
	}{
		{
			name: "missing token",
			request: grantctl.Request{
				Type:            grantctl.ReqReviewSnapshot,
				ProtocolVersion: grantctl.ReviewProtocolVersion,
			},
			wantErr: "unauthorized",
		},
		{
			name: "invalid token",
			request: grantctl.Request{
				Type:            grantctl.ReqReviewSnapshot,
				CtlToken:        "sensitive-wrong-token",
				ProtocolVersion: grantctl.ReviewProtocolVersion,
			},
			wantErr: "unauthorized",
		},
		{
			name: "missing version",
			request: grantctl.Request{
				Type:     grantctl.ReqReviewSnapshot,
				CtlToken: testCtlToken,
			},
			wantErr: "review_snapshot requires protocol_version",
		},
		{
			name: "future version",
			request: grantctl.Request{
				Type:            grantctl.ReqReviewSnapshot,
				CtlToken:        testCtlToken,
				ProtocolVersion: grantctl.ReviewProtocolVersion + 1,
			},
			wantErr: "unsupported review protocol version 2",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			projector := reviewSnapshotProjectorFunc(func(now time.Time) grantctl.ReviewSnapshotV1 {
				calls.Add(1)
				return emptyReviewSnapshot(now)
			})
			sock := startReviewControlServer(t, nil, projector, nil, nil)
			response := reviewControlRoundTrip(t, sock, test.request)
			if response.OK || response.Error != test.wantErr {
				t.Fatalf("response = %+v, want error %q", response, test.wantErr)
			}
			if calls.Load() != 0 {
				t.Fatalf("projection called %d times", calls.Load())
			}
			if len(response.Error) > 96 || strings.Contains(response.Error, "sensitive-wrong-token") {
				t.Fatalf("unbounded or sensitive refusal: %q", response.Error)
			}
		})
	}
}

func TestReviewSnapshotEndpointUsesOneServerTimestamp(t *testing.T) {
	var calls atomic.Int32
	var projectedAtUnixMilli atomic.Int64
	projector := reviewSnapshotProjectorFunc(func(now time.Time) grantctl.ReviewSnapshotV1 {
		calls.Add(1)
		projectedAtUnixMilli.Store(now.UnixMilli())
		return emptyReviewSnapshot(now)
	})
	sock := startReviewControlServer(t, nil, projector, nil, nil)

	snapshot, err := grantctl.ReviewSnapshot(sock, testCtlToken, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("projection calls = %d, want 1", calls.Load())
	}
	if snapshot.GeneratedAtUnixMs != grantctl.UnixMilliseconds(projectedAtUnixMilli.Load()) {
		t.Fatalf("generated_at_unix_ms = %d, projector received %d", snapshot.GeneratedAtUnixMs, projectedAtUnixMilli.Load())
	}
}

func TestReviewSnapshotEndpointMatchesCanonicalFixtureWithoutAudit(t *testing.T) {
	want, err := os.ReadFile(filepath.Join("..", "grantctl", "testdata", "review_snapshot_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var canonical grantctl.Response
	if err := json.Unmarshal(want, &canonical); err != nil {
		t.Fatal(err)
	}
	if canonical.ReviewSnapshot == nil {
		t.Fatal("canonical fixture is missing review_snapshot")
	}

	var calls atomic.Int32
	projector := reviewSnapshotProjectorFunc(func(time.Time) grantctl.ReviewSnapshotV1 {
		calls.Add(1)
		return *canonical.ReviewSnapshot
	})
	emitter := &reviewAuditEmitter{}
	sock := startReviewControlServer(t, nil, projector, emitter, nil)
	conn, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if err := grantctl.WriteRequestFrame(conn, grantctl.Request{
		Type:            grantctl.ReqReviewSnapshot,
		CtlToken:        testCtlToken,
		ProtocolVersion: grantctl.ReviewProtocolVersion,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("endpoint fixture drifted\n got: %s\nwant: %s", got, want)
	}
	if calls.Load() != 1 || emitter.calls.Load() != 0 {
		t.Fatalf("projection calls=%d audit calls=%d", calls.Load(), emitter.calls.Load())
	}
}

func TestReviewSnapshotInvalidFramesNeverProject(t *testing.T) {
	prefix := fmt.Sprintf("{\"type\":\"review_snapshot\",\"ctl_token\":%q,\"protocol_version\":1}", testCtlToken)
	oversize := append([]byte(prefix), bytes.Repeat([]byte{' '}, grantctl.MaxControlMsgBytes-len(prefix))...)
	oversize = append(oversize, '\n')

	tests := []struct {
		name  string
		frame []byte
	}{
		{name: "malformed JSON", frame: []byte("{\n")},
		{name: "invalid version type", frame: []byte(fmt.Sprintf("{\"type\":\"review_snapshot\",\"ctl_token\":%q,\"protocol_version\":\"one\"}\n", testCtlToken))},
		{name: "trailing value", frame: []byte(prefix + " {}\n")},
		{name: "oversize", frame: oversize},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			projector := reviewSnapshotProjectorFunc(func(now time.Time) grantctl.ReviewSnapshotV1 {
				calls.Add(1)
				return emptyReviewSnapshot(now)
			})
			sock := startReviewControlServer(t, nil, projector, nil, nil)
			response := rawControlFrameRoundTrip(t, sock, test.frame, false)
			if response.OK || response.Error != "malformed grant control request" {
				t.Fatalf("response = %+v", response)
			}
			if calls.Load() != 0 {
				t.Fatalf("invalid frame projected %d times", calls.Load())
			}
		})
	}
}

func TestReviewSnapshotAcceptsAdditiveFieldsAndDispatchesOnlyFirstFrame(t *testing.T) {
	var calls atomic.Int32
	projector := reviewSnapshotProjectorFunc(func(now time.Time) grantctl.ReviewSnapshotV1 {
		calls.Add(1)
		return emptyReviewSnapshot(now)
	})
	sock := startReviewControlServer(t, nil, projector, nil, nil)
	first := []byte(fmt.Sprintf("{\"type\":\"review_snapshot\",\"ctl_token\":%q,\"protocol_version\":1,\"future_envelope\":true}\n", testCtlToken))
	second := encodeControlRequestFrame(t, grantctl.Request{
		Type:            grantctl.ReqReviewSnapshot,
		CtlToken:        testCtlToken,
		ProtocolVersion: grantctl.ReviewProtocolVersion,
	})

	response := rawControlFrameRoundTrip(t, sock, append(first, second...), false)
	if !response.OK || response.ReviewSnapshot == nil {
		t.Fatalf("additive first-frame response = %+v", response)
	}
	if calls.Load() != 1 {
		t.Fatalf("two frames projected %d times, want 1", calls.Load())
	}
}

func TestReviewSnapshotClientDistinguishesEmptyQueueFromUnavailable(t *testing.T) {
	sock := startReviewControlServer(t, grantctl.NewRegistry(), nil, nil, nil)
	snapshot, err := grantctl.ReviewSnapshot(sock, testCtlToken, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.TotalPending != 0 || snapshot.Truncated || snapshot.Reviews == nil || len(snapshot.Reviews) != 0 {
		t.Fatalf("empty snapshot = %+v", snapshot)
	}

	missingSock := filepath.Join(shortTempDir(t), "unavailable.sock")
	if _, err := grantctl.ReviewSnapshot(missingSock, testCtlToken, 20*time.Millisecond); err == nil {
		t.Fatal("unavailable daemon returned an empty queue")
	}
}

func TestReviewSnapshotEndpointCapsAndSortsDeterministically(t *testing.T) {
	registry := grantctl.NewRegistry()
	created := time.Now().Add(-time.Minute)
	for i := 0; i < 5; i++ {
		host := fmt.Sprintf("host-%d.example.test", i)
		grant, err := registry.RequestGrant("session", "/reported", host, 60_000, "reason", created.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		registry.SetBoundCWD(grant.GrantID, fmt.Sprintf("/Users/demo/project-%d", i))
	}
	sock := startReviewControlServer(t, registry, nil, nil, nil)

	snapshot, err := grantctl.ReviewSnapshot(sock, testCtlToken, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.TotalPending != 5 || !snapshot.Truncated || len(snapshot.Reviews) != grantctl.MaxReviewSnapshotItems {
		t.Fatalf("capped snapshot = %+v", snapshot)
	}
	wantHosts := []string{"host-4.example.test", "host-3.example.test", "host-2.example.test"}
	for i, want := range wantHosts {
		if snapshot.Reviews[i].Host != want {
			t.Fatalf("review[%d].host = %q, want %q", i, snapshot.Reviews[i].Host, want)
		}
	}
}

func TestReviewSnapshotEndpointReturnsDarwinShapedUnboundAsDenyOnly(t *testing.T) {
	registry := grantctl.NewRegistry()
	grant, err := registry.RequestGrant("darwin-session", "/agent/reported/darwin/project", "packages.example.test", 60_000, "resolve packages", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sock := startReviewControlServer(t, registry, nil, nil, nil)

	snapshot, err := grantctl.ReviewSnapshot(sock, testCtlToken, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Reviews) != 1 || snapshot.Reviews[0].ReviewID != grantctl.ReviewID(grant.GrantID) {
		t.Fatalf("unbound snapshot = %+v", snapshot)
	}
	review := snapshot.Reviews[0]
	if review.ContextState != grantctl.ReviewContextStateUnbound || review.ProjectPath != "" || review.CanApprove || !review.CanDeny {
		t.Fatalf("unbound actionability = %+v", review)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("/agent/reported/darwin/project")) || bytes.Contains(encoded, []byte("darwin-session")) {
		t.Fatalf("snapshot leaked self-reported context: %s", encoded)
	}
}

func TestReviewSnapshotConcurrentWithApproveAndDeny(t *testing.T) {
	home := shortTempDir(t)
	t.Setenv("HOME", home)
	project := filepath.Join(home, "project")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	registry := grantctl.NewRegistry()
	created := time.Now()
	approveGrant, err := registry.RequestGrant("approve-session", project, "approve.example.test", 60_000, "approve", created)
	if err != nil {
		t.Fatal(err)
	}
	registry.SetBoundCWD(approveGrant.GrantID, project)
	denyGrant, err := registry.RequestGrant("deny-session", project, "deny.example.test", 60_000, "deny", created.Add(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	registry.SetBoundCWD(denyGrant.GrantID, project)
	sock := startReviewControlServer(t, registry, nil, audit.NopEmitter{}, nil)

	start := make(chan struct{})
	errCh := make(chan error, 10)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 8; j++ {
				if _, err := grantctl.ReviewSnapshot(sock, testCtlToken, 3*time.Second); err != nil {
					errCh <- fmt.Errorf("snapshot: %w", err)
					return
				}
			}
		}()
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		if err := grantctl.GrantApprove(sock, testCtlToken, approveGrant.GrantID, 3*time.Second); err != nil {
			errCh <- fmt.Errorf("approve: %w", err)
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		if err := grantctl.GrantDeny(sock, testCtlToken, denyGrant.GrantID, 3*time.Second); err != nil {
			errCh <- fmt.Errorf("deny: %w", err)
		}
	}()
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
	if pending := registry.ListPending(time.Now()); len(pending) != 0 {
		t.Fatalf("pending after concurrent mutations = %+v", pending)
	}
}

func TestReviewSnapshotEndpointPreservesLegacyControlVerbs(t *testing.T) {
	home := shortTempDir(t)
	t.Setenv("HOME", home)
	project := filepath.Join(home, "legacy-project")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	registry := grantctl.NewRegistry()
	created := time.Now()
	approveGrant, err := registry.RequestGrant("legacy-approve", project, "approve-legacy.example.test", 60_000, "approve", created)
	if err != nil {
		t.Fatal(err)
	}
	registry.SetBoundCWD(approveGrant.GrantID, project)
	denyGrant, err := registry.RequestGrant("legacy-deny", project, "deny-legacy.example.test", 60_000, "deny", created.Add(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	registry.SetBoundCWD(denyGrant.GrantID, project)
	var reloads atomic.Int32
	sock := startReviewControlServer(t, registry, nil, audit.NopEmitter{}, func(context.Context) error {
		reloads.Add(1)
		return nil
	})

	grants, err := grantctl.GrantList(sock, testCtlToken, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 2 {
		t.Fatalf("legacy grant list = %+v", grants)
	}
	if err := grantctl.GrantApprove(sock, testCtlToken, approveGrant.GrantID, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := grantctl.GrantDeny(sock, testCtlToken, denyGrant.GrantID, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := grantctl.DaemonReload(sock, testCtlToken, time.Second); err != nil {
		t.Fatal(err)
	}
	if reloads.Load() != 1 {
		t.Fatalf("reload calls = %d, want 1", reloads.Load())
	}
	if pending := registry.ListPending(time.Now()); len(pending) != 0 {
		t.Fatalf("legacy mutations left pending grants: %+v", pending)
	}
}
