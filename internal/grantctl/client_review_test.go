package grantctl

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

func startReviewTestServer(t *testing.T, response []byte) (string, <-chan Request) {
	t.Helper()
	sock := shortSock(t, "review.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	received := make(chan Request, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		var request Request
		if decodeErr := json.NewDecoder(conn).Decode(&request); decodeErr != nil {
			return
		}
		received <- request
		_, _ = conn.Write(response)
	}()
	return sock, received
}

func encodedReviewTestResponse(t *testing.T, response Response) []byte {
	t.Helper()
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	return append(encoded, '\n')
}

func emptyReviewSnapshot(version ProtocolVersion) ReviewSnapshotV1 {
	return ReviewSnapshotV1{
		ProtocolVersion:   version,
		GeneratedAtUnixMs: 1_786_816_800_123,
		Reviews:           []ReviewInfo{},
	}
}

func TestReviewSnapshotClientSendsExplicitVersionAndDecodesValidResponse(t *testing.T) {
	want := canonicalReviewSnapshot()
	sock, received := startReviewTestServer(t, encodedReviewTestResponse(t, Response{
		OK:             true,
		ReviewSnapshot: &want,
	}))

	got, err := ReviewSnapshot(sock, "control-value", time.Second)
	if err != nil {
		t.Fatalf("ReviewSnapshot: %v", err)
	}
	if got.TotalPending != want.TotalPending || len(got.Reviews) != len(want.Reviews) {
		t.Fatalf("snapshot = %+v, want %+v", got, want)
	}
	request := <-received
	if request.Type != ReqReviewSnapshot || request.CtlToken != "control-value" || request.ProtocolVersion != ReviewProtocolVersion {
		t.Fatalf("request = %+v, want explicit authenticated v1 review request", request)
	}
}

func TestReviewSnapshotClientRejectsMissingVersion(t *testing.T) {
	sock, _ := startReviewTestServer(t, encodedReviewTestResponse(t, Response{OK: true}))
	if _, err := ReviewSnapshot(sock, "control-value", time.Second); err == nil {
		t.Fatal("expected missing review snapshot/version error")
	}
}

func TestReviewSnapshotClientRejectsUnsupportedVersion(t *testing.T) {
	snapshot := emptyReviewSnapshot(ReviewProtocolVersion + 1)
	sock, _ := startReviewTestServer(t, encodedReviewTestResponse(t, Response{OK: true, ReviewSnapshot: &snapshot}))
	if _, err := ReviewSnapshot(sock, "control-value", time.Second); err == nil {
		t.Fatal("expected unsupported review protocol error")
	}
}

func TestReviewSnapshotClientSurfacesRefusal(t *testing.T) {
	sock, _ := startReviewTestServer(t, encodedReviewTestResponse(t, Response{OK: false, Error: "unsupported protocol version"}))
	if _, err := ReviewSnapshot(sock, "control-value", time.Second); err == nil {
		t.Fatal("expected daemon refusal")
	}
}

func TestReviewSnapshotClientRejectsMalformedJSON(t *testing.T) {
	sock, _ := startReviewTestServer(t, []byte("{not-json}\n"))
	if _, err := ReviewSnapshot(sock, "control-value", time.Second); err == nil {
		t.Fatal("expected malformed response error")
	}
}

func TestReviewSnapshotClientToleratesUnknownAdditiveFields(t *testing.T) {
	response := []byte(`{"ok":true,"future_envelope":"ignored","review_snapshot":{"protocol_version":1,"generated_at_unix_ms":1786816800123,"total_pending":0,"truncated":false,"reviews":[],"future_snapshot":true}}` + "\n")
	sock, _ := startReviewTestServer(t, response)
	got, err := ReviewSnapshot(sock, "control-value", time.Second)
	if err != nil {
		t.Fatalf("unknown additive fields must be tolerated: %v", err)
	}
	if got.TotalPending != 0 || len(got.Reviews) != 0 {
		t.Fatalf("unexpected empty snapshot: %+v", got)
	}
}

func TestReviewSnapshotClientRejectsInvalidV1Enum(t *testing.T) {
	snapshot := canonicalReviewSnapshot()
	snapshot.Reviews[0].Kind = ReviewKind("unknown")
	sock, _ := startReviewTestServer(t, encodedReviewTestResponse(t, Response{OK: true, ReviewSnapshot: &snapshot}))
	if _, err := ReviewSnapshot(sock, "control-value", time.Second); err == nil {
		t.Fatal("expected invalid v1 enum error")
	}
}
