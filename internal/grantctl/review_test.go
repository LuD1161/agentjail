package grantctl

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func seedPendingReview(r *Registry, pg pendingGrant) {
	r.mu.Lock()
	defer r.mu.Unlock()
	copy := pg
	r.grants[copy.GrantID] = &copy
}

func TestReviewSnapshotProjectsVerifiedBindingNotReportedCWD(t *testing.T) {
	now := time.UnixMilli(1_786_816_800_123)
	r := NewRegistry()
	seedPendingReview(r, pendingGrant{
		GrantID:   "review-verified",
		Host:      "api.example.test",
		Reason:    "preview deploy",
		SessionID: "session-private",
		CWD:       "/agent/reported/not-authoritative",
		BoundCWD:  "/Users/demo/Projects/verified",
		Created:   now.Add(-time.Minute),
		Expires:   now.Add(time.Hour),
	})

	snapshot := r.ReviewSnapshot(now)
	if snapshot.ProtocolVersion != ReviewProtocolVersion || snapshot.GeneratedAtUnixMs != UnixMilliseconds(now.UnixMilli()) {
		t.Fatalf("unexpected snapshot metadata: %+v", snapshot)
	}
	if snapshot.TotalPending != 1 || snapshot.Truncated || len(snapshot.Reviews) != 1 {
		t.Fatalf("unexpected snapshot cardinality: %+v", snapshot)
	}
	review := snapshot.Reviews[0]
	if review.ProjectPath != "/Users/demo/Projects/verified" {
		t.Fatalf("project_path = %q, want verified binding", review.ProjectPath)
	}
	if review.ContextState != ReviewContextStateVerified || !review.CanApprove || !review.CanDeny {
		t.Fatalf("verified review actionability = %+v", review)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("/agent/reported/not-authoritative")) || bytes.Contains(encoded, []byte("session-private")) {
		t.Fatalf("snapshot leaked self-reported context: %s", encoded)
	}
}

func TestReviewSnapshotUnboundIsDenyOnly(t *testing.T) {
	now := time.UnixMilli(1_786_816_800_123)
	r := NewRegistry()
	seedPendingReview(r, pendingGrant{
		GrantID: "review-unbound",
		Host:    "packages.example.test",
		CWD:     "/agent/reported/not-authoritative",
		Created: now.Add(-time.Minute),
		Expires: now.Add(time.Hour),
	})

	review := r.ReviewSnapshot(now).Reviews[0]
	if review.ContextState != ReviewContextStateUnbound || review.ProjectPath != "" {
		t.Fatalf("unbound review context = %+v", review)
	}
	if review.CanApprove || !review.CanDeny {
		t.Fatalf("unbound review must be deny-only: %+v", review)
	}
}

func TestReviewSnapshotOmitsUnrepresentableAuthority(t *testing.T) {
	now := time.UnixMilli(1_786_816_800_123)
	tests := []struct {
		name            string
		host            string
		path            string
		wantHost        string
		wantProjectPath string
	}{
		{
			name:            "host over byte limit",
			host:            strings.Repeat("h", MaxReviewHostBytes+1),
			path:            "/Users/demo/project",
			wantProjectPath: "/Users/demo/project",
		},
		{
			name:     "project path over byte limit",
			host:     "api.example.test",
			path:     "/" + strings.Repeat("p", MaxReviewProjectPathBytes),
			wantHost: "api.example.test",
		},
		{
			name:            "invalid utf8 host",
			host:            string([]byte{'h', 0xff}),
			path:            "/Users/demo/project",
			wantProjectPath: "/Users/demo/project",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := NewRegistry()
			seedPendingReview(r, pendingGrant{
				GrantID:  "review-unrepresentable",
				Host:     test.host,
				BoundCWD: test.path,
				Created:  now.Add(-time.Minute),
				Expires:  now.Add(time.Hour),
			})

			review := r.ReviewSnapshot(now).Reviews[0]
			if review.ContextState != ReviewContextStateUnrepresentable || review.CanApprove || !review.CanDeny {
				t.Fatalf("unrepresentable review must be deny-only: %+v", review)
			}
			if review.Host != test.wantHost || review.ProjectPath != test.wantProjectPath {
				t.Fatalf("authority fields were truncated or changed: %+v", review)
			}
		})
	}
}

func TestReviewSnapshotTruncatesReasonAtUTF8Boundary(t *testing.T) {
	now := time.UnixMilli(1_786_816_800_123)
	r := NewRegistry()
	seedPendingReview(r, pendingGrant{
		GrantID:  "review-reason",
		Host:     "api.example.test",
		BoundCWD: "/Users/demo/project",
		Reason:   strings.Repeat("a", MaxReviewReasonBytes-1) + "é",
		Created:  now.Add(-time.Minute),
		Expires:  now.Add(time.Hour),
	})

	review := r.ReviewSnapshot(now).Reviews[0]
	if !review.ReasonTruncated || len(review.Reason) != MaxReviewReasonBytes-1 || !utf8.ValidString(review.Reason) {
		t.Fatalf("reason was not safely truncated: bytes=%d valid=%v truncated=%v", len(review.Reason), utf8.ValidString(review.Reason), review.ReasonTruncated)
	}
}

func TestReviewSnapshotExcludesClaimedAndExpiredBeforeReap(t *testing.T) {
	now := time.UnixMilli(1_786_816_800_123)
	r := NewRegistry()
	seedPendingReview(r, pendingGrant{
		GrantID:  "expired-at-now",
		Host:     "expired.example.test",
		BoundCWD: "/Users/demo/expired",
		Created:  now.Add(-PendingGrantTTL),
		Expires:  now,
	})
	seedPendingReview(r, pendingGrant{
		GrantID:  "claimed",
		Host:     "claimed.example.test",
		BoundCWD: "/Users/demo/claimed",
		Created:  now.Add(-time.Minute),
		Expires:  now.Add(time.Hour),
		claimed:  true,
	})
	seedPendingReview(r, pendingGrant{
		GrantID:  "live",
		Host:     "live.example.test",
		BoundCWD: "/Users/demo/live",
		Created:  now.Add(-time.Second),
		Expires:  now.Add(time.Hour),
	})

	snapshot := r.ReviewSnapshot(now)
	if snapshot.TotalPending != 1 || len(snapshot.Reviews) != 1 || snapshot.Reviews[0].ReviewID != "live" {
		t.Fatalf("snapshot included claimed or expired review: %+v", snapshot)
	}
	if got := r.ListPending(now); len(got) != 1 || got[0].GrantID != "live" {
		t.Fatalf("time-aware list included expired state before reap: %+v", got)
	}
}

func TestReviewSnapshotSortsAndCapsDeterministically(t *testing.T) {
	now := time.UnixMilli(1_786_816_800_123)
	r := NewRegistry()
	for _, item := range []struct {
		id      string
		created time.Time
	}{
		{id: "old", created: now.Add(-3 * time.Minute)},
		{id: "tie-b", created: now.Add(-time.Minute)},
		{id: "tie-a", created: now.Add(-time.Minute)},
		{id: "newest", created: now.Add(-time.Second)},
		{id: "middle", created: now.Add(-2 * time.Minute)},
	} {
		seedPendingReview(r, pendingGrant{
			GrantID:  item.id,
			Host:     item.id + ".example.test",
			BoundCWD: "/Users/demo/" + item.id,
			Created:  item.created,
			Expires:  now.Add(time.Hour),
		})
	}

	snapshot := r.ReviewSnapshot(now)
	if snapshot.TotalPending != 5 || !snapshot.Truncated || len(snapshot.Reviews) != MaxReviewSnapshotItems {
		t.Fatalf("unexpected capped snapshot: %+v", snapshot)
	}
	want := []ReviewID{"newest", "tie-a", "tie-b"}
	for i := range want {
		if snapshot.Reviews[i].ReviewID != want[i] {
			t.Fatalf("review order[%d] = %q, want %q", i, snapshot.Reviews[i].ReviewID, want[i])
		}
	}
}

func canonicalReviewSnapshot() ReviewSnapshotV1 {
	return ReviewSnapshotV1{
		ProtocolVersion:   ReviewProtocolVersion,
		GeneratedAtUnixMs: 1_786_816_800_123,
		TotalPending:      3,
		Truncated:         false,
		Reviews: []ReviewInfo{
			{
				ReviewID:        "review-verified-001",
				Kind:            ReviewKindProjectHost,
				Host:            "api.example.test",
				ProjectPath:     "/Users/demo/Projects/alpha",
				Reason:          "Publish preview metadata",
				ReasonTruncated: false,
				ContextState:    ReviewContextStateVerified,
				CreatedAtUnixMs: 1_786_816_799_000,
				ExpiresAtUnixMs: 1_786_820_399_000,
				ApprovalScope:   ReviewScopeFutureProjectSessions,
				CanApprove:      true,
				CanDeny:         true,
			},
			{
				ReviewID:        "review-unbound-002",
				Kind:            ReviewKindProjectHost,
				Host:            "packages.example.test",
				Reason:          "Resolve dependencies",
				ReasonTruncated: false,
				ContextState:    ReviewContextStateUnbound,
				CreatedAtUnixMs: 1_786_816_798_000,
				ExpiresAtUnixMs: 1_786_820_398_000,
				ApprovalScope:   ReviewScopeFutureProjectSessions,
				CanApprove:      false,
				CanDeny:         true,
			},
			{
				ReviewID:        "review-unrepresentable-003",
				Kind:            ReviewKindProjectHost,
				ProjectPath:     "/Users/demo/Projects/gamma",
				Reason:          "Host exceeded projection limit",
				ReasonTruncated: false,
				ContextState:    ReviewContextStateUnrepresentable,
				CreatedAtUnixMs: 1_786_816_797_000,
				ExpiresAtUnixMs: 1_786_820_397_000,
				ApprovalScope:   ReviewScopeFutureProjectSessions,
				CanApprove:      false,
				CanDeny:         true,
			},
		},
	}
}

func TestReviewSnapshotGolden(t *testing.T) {
	want, err := os.ReadFile("testdata/review_snapshot_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	response := Response{OK: true, ReviewSnapshot: ptrReviewSnapshot(canonicalReviewSnapshot())}
	got, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if !bytes.Equal(got, want) {
		t.Fatalf("review snapshot fixture drifted\n got: %s\nwant: %s", got, want)
	}

	decoder := json.NewDecoder(bytes.NewReader(want))
	decoder.DisallowUnknownFields()
	var decoded Response
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatalf("decode canonical fixture: %v", err)
	}
	if !reflect.DeepEqual(decoded, response) {
		t.Fatalf("decoded fixture = %+v, want %+v", decoded, response)
	}
}

func ptrReviewSnapshot(snapshot ReviewSnapshotV1) *ReviewSnapshotV1 {
	return &snapshot
}

func TestReviewSnapshotWorstCaseEncodingFitsControlFrame(t *testing.T) {
	now := time.UnixMilli(1_786_816_800_123)
	r := NewRegistry()
	for i := 0; i < MaxReviewSnapshotItems; i++ {
		seedPendingReview(r, pendingGrant{
			GrantID:  "worst-" + itoa(i),
			Host:     strings.Repeat("\x1f", MaxReviewHostBytes),
			BoundCWD: strings.Repeat("\x1f", MaxReviewProjectPathBytes),
			Reason:   strings.Repeat("\x1f", MaxReviewReasonBytes),
			Created:  now.Add(-time.Duration(i) * time.Second),
			Expires:  now.Add(time.Hour),
		})
	}
	snapshot := r.ReviewSnapshot(now)
	for _, review := range snapshot.Reviews {
		if len(review.Host) != MaxReviewHostBytes || len(review.ProjectPath) != MaxReviewProjectPathBytes || len(review.Reason) != MaxReviewReasonBytes {
			t.Fatalf("worst-case authority/prose was not retained at its limit: host=%d path=%d reason=%d", len(review.Host), len(review.ProjectPath), len(review.Reason))
		}
		if review.ContextState != ReviewContextStateVerified || !review.CanApprove {
			t.Fatalf("at-limit review unexpectedly became unactionable: %+v", review)
		}
	}
	var frame bytes.Buffer
	if err := json.NewEncoder(&frame).Encode(Response{OK: true, ReviewSnapshot: &snapshot}); err != nil {
		t.Fatal(err)
	}
	if frame.Len() >= MaxControlMsgBytes {
		t.Fatalf("worst-case frame = %d bytes, must be below %d", frame.Len(), MaxControlMsgBytes)
	}
	if frame.Bytes()[frame.Len()-1] != '\n' || bytes.Contains(frame.Bytes()[:frame.Len()-1], []byte{'\n'}) {
		t.Fatal("encoded response must have exactly one terminal raw newline")
	}
}

func TestReviewResponseTypesExcludeSensitiveFields(t *testing.T) {
	forbidden := []string{"token", "challenge", "command", "tool_input"}
	for _, typ := range []reflect.Type{
		reflect.TypeOf(Response{}),
		reflect.TypeOf(ReviewSnapshotV1{}),
		reflect.TypeOf(ReviewInfo{}),
	} {
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			candidate := strings.ToLower(field.Name + " " + field.Tag.Get("json"))
			for _, term := range forbidden {
				if strings.Contains(candidate, term) {
					t.Fatalf("%s.%s exposes forbidden field/tag term %q", typ.Name(), field.Name, term)
				}
			}
		}
	}
}

func TestReviewEnumsHaveNoValidZeroValue(t *testing.T) {
	if ReviewKind("") == ReviewKindProjectHost {
		t.Fatal("zero ReviewKind must not be project_host")
	}
	if ReviewScope("") == ReviewScopeFutureProjectSessions {
		t.Fatal("zero ReviewScope must not be future_project_sessions")
	}
	if ReviewContextState("") == ReviewContextStateVerified || ReviewContextState("") == ReviewContextStateUnbound || ReviewContextState("") == ReviewContextStateUnrepresentable {
		t.Fatal("zero ReviewContextState must not be valid")
	}
	if ProtocolVersion(0) == ReviewProtocolVersion {
		t.Fatal("zero protocol version must not alias v1")
	}
}

func TestReviewWireAdditiveForLegacyGrantMessages(t *testing.T) {
	request, err := json.Marshal(Request{Type: ReqGrantList, CtlToken: "legacy-control-value"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(request), `{"type":"grant_list","ctl_token":"legacy-control-value"}`; got != want {
		t.Fatalf("legacy request changed: got %s, want %s", got, want)
	}
	response, err := json.Marshal(Response{OK: true})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(response), `{"ok":true}`; got != want {
		t.Fatalf("legacy response changed: got %s, want %s", got, want)
	}
}
