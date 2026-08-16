package grantctl

import (
	"sync"
	"testing"
	"time"
)

func TestRequestGrant_Basic(t *testing.T) {
	r := NewRegistry()
	now := time.Now()

	info, err := r.RequestGrant("sess-1", "/home/agent", "example.com", 60000, "need api access", now)
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	if info.GrantID == "" {
		t.Fatal("expected non-empty GrantID")
	}
	if info.Host != "example.com" || info.SessionID != "sess-1" || info.CWD != "/home/agent" || info.Reason != "need api access" || info.TTLMs != 60000 {
		t.Fatalf("unexpected GrantInfo: %+v", info)
	}

	pending := r.ListPending(now)
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending grant, got %d", len(pending))
	}
}

func TestRequestGrant_DuplicateCoalesces(t *testing.T) {
	r := NewRegistry()
	now := time.Now()

	first, err := r.RequestGrant("sess-1", "/home/agent", "example.com", 60000, "reason-1", now)
	if err != nil {
		t.Fatalf("RequestGrant (first): %v", err)
	}

	later := now.Add(time.Minute)
	second, err := r.RequestGrant("sess-1", "/home/agent", "example.com", 120000, "reason-2", later)
	if err != nil {
		t.Fatalf("RequestGrant (second): %v", err)
	}

	if first.GrantID != second.GrantID {
		t.Fatalf("expected coalesced GrantID, got %q and %q", first.GrantID, second.GrantID)
	}
	if second.TTLMs != 120000 || second.Reason != "reason-2" {
		t.Fatalf("expected updated TTL/reason, got %+v", second)
	}

	pending := r.ListPending(later)
	if len(pending) != 1 {
		t.Fatalf("expected coalesced request to remain a single pending grant, got %d", len(pending))
	}
}

func TestRequestGrant_PerSessionCap(t *testing.T) {
	r := NewRegistry()
	now := time.Now()

	for i := range MaxPendingPerSession {
		host := hostForIndex(i)
		if _, err := r.RequestGrant("sess-1", "/cwd", host, 1000, "r", now); err != nil {
			t.Fatalf("RequestGrant %d: %v", i, err)
		}
	}

	_, err := r.RequestGrant("sess-1", "/cwd", "overflow.example.com", 1000, "r", now)
	if err != ErrPerSessionCapExceeded {
		t.Fatalf("expected ErrPerSessionCapExceeded, got %v", err)
	}

	// A different session is unaffected by sess-1's cap.
	if _, err := r.RequestGrant("sess-2", "/cwd", "ok.example.com", 1000, "r", now); err != nil {
		t.Fatalf("RequestGrant for sess-2 should succeed: %v", err)
	}
}

func TestRequestGrant_GlobalCap(t *testing.T) {
	r := NewRegistry()
	now := time.Now()

	// Spread requests across many sessions so the per-session cap never
	// triggers, only the global cap.
	perSession := MaxPendingPerSession
	sessions := (MaxPendingGlobal / perSession) + 1
	created := 0
	for s := 0; s < sessions && created < MaxPendingGlobal; s++ {
		sessID := hostForIndex(s) // reuse as a unique string generator
		for i := 0; i < perSession && created < MaxPendingGlobal; i++ {
			host := hostForIndex(created)
			if _, err := r.RequestGrant(sessID, "/cwd", host, 1000, "r", now); err != nil {
				t.Fatalf("RequestGrant (created=%d): %v", created, err)
			}
			created++
		}
	}

	if got := r.countPendingGlobal(now); got != MaxPendingGlobal {
		t.Fatalf("expected %d pending grants filed, got %d", MaxPendingGlobal, got)
	}

	_, err := r.RequestGrant("sess-overflow", "/cwd", "overflow.example.com", 1000, "r", now)
	if err != ErrGlobalCapExceeded {
		t.Fatalf("expected ErrGlobalCapExceeded, got %v", err)
	}
}

func hostForIndex(i int) string {
	return "host-" + itoa(i) + ".example.com"
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

func TestListPending(t *testing.T) {
	r := NewRegistry()
	now := time.Now()

	if _, err := r.RequestGrant("sess-1", "/cwd-a", "a.example.com", 1000, "ra", now); err != nil {
		t.Fatalf("RequestGrant sess-1: %v", err)
	}
	if _, err := r.RequestGrant("sess-2", "/cwd-b", "b.example.com", 2000, "rb", now); err != nil {
		t.Fatalf("RequestGrant sess-2: %v", err)
	}

	pending := r.ListPending(now)
	if len(pending) != 2 {
		t.Fatalf("expected 2 pending grants, got %d", len(pending))
	}

	seen := map[string]bool{}
	for _, p := range pending {
		seen[p.SessionID] = true
	}
	if !seen["sess-1"] || !seen["sess-2"] {
		t.Fatalf("expected both sessions represented, got %+v", pending)
	}
}

func TestClaimGrant_CommitRemoves(t *testing.T) {
	r := NewRegistry()
	now := time.Now()

	info, err := r.RequestGrant("sess-1", "/cwd", "example.com", 1000, "r", now)
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}

	claimed, commit, _, err := r.ClaimGrant(info.GrantID, now)
	if err != nil {
		t.Fatalf("ClaimGrant: %v", err)
	}
	if claimed.GrantID != info.GrantID || claimed.Host != "example.com" {
		t.Fatalf("unexpected claimed snapshot: %+v", claimed)
	}

	// Claimed grants are invisible to ListPending/FindGrant.
	if len(r.ListPending(now)) != 0 {
		t.Fatalf("expected claimed grant hidden from ListPending")
	}
	if _, ok := r.FindGrant(info.GrantID, now); ok {
		t.Fatalf("expected claimed grant hidden from FindGrant")
	}

	commit()

	if len(r.ListPending(now)) != 0 {
		t.Fatalf("expected grant removed after commit")
	}
	if _, ok := r.FindGrant(info.GrantID, now); ok {
		t.Fatalf("expected grant not found after commit")
	}
}

func TestClaimGrant_RollbackRestores(t *testing.T) {
	r := NewRegistry()
	now := time.Now()

	info, err := r.RequestGrant("sess-1", "/cwd", "example.com", 1000, "r", now)
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}

	_, _, rollback, err := r.ClaimGrant(info.GrantID, now)
	if err != nil {
		t.Fatalf("ClaimGrant: %v", err)
	}

	rollback()

	pending := r.ListPending(now)
	if len(pending) != 1 {
		t.Fatalf("expected grant restored to pending after rollback, got %d", len(pending))
	}
	found, ok := r.FindGrant(info.GrantID, now)
	if !ok {
		t.Fatalf("expected FindGrant to find restored grant")
	}
	if found.GrantID != info.GrantID {
		t.Fatalf("unexpected restored grant: %+v", found)
	}

	// The grant should be reclaimable again after rollback.
	if _, _, _, err := r.ClaimGrant(info.GrantID, now); err != nil {
		t.Fatalf("expected grant reclaimable after rollback, got %v", err)
	}
}

func TestClaimGrant_DoubleClaimRejected(t *testing.T) {
	r := NewRegistry()
	now := time.Now()

	info, err := r.RequestGrant("sess-1", "/cwd", "example.com", 1000, "r", now)
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}

	_, _, _, err = r.ClaimGrant(info.GrantID, now)
	if err != nil {
		t.Fatalf("first ClaimGrant: %v", err)
	}

	_, _, _, err = r.ClaimGrant(info.GrantID, now)
	if err != ErrGrantAlreadyClaimed {
		t.Fatalf("expected ErrGrantAlreadyClaimed on double claim, got %v", err)
	}
}

func TestClaimGrant_NotFound(t *testing.T) {
	r := NewRegistry()
	now := time.Now()

	_, _, _, err := r.ClaimGrant("does-not-exist", now)
	if err != ErrGrantNotFound {
		t.Fatalf("expected ErrGrantNotFound, got %v", err)
	}
}

func TestSetBoundCWD(t *testing.T) {
	r := NewRegistry()
	now := time.Now()

	info, err := r.RequestGrant("sess-1", "/cwd", "example.com", 1000, "r", now)
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}

	// Unbound: ClaimGrant should reflect an empty BoundCWD before SetBoundCWD.
	claimed, _, rollback, err := r.ClaimGrant(info.GrantID, now)
	if err != nil {
		t.Fatalf("ClaimGrant: %v", err)
	}
	if claimed.BoundCWD != "" {
		t.Fatalf("expected empty BoundCWD before SetBoundCWD, got %q", claimed.BoundCWD)
	}
	rollback()

	r.SetBoundCWD(info.GrantID, "/resolved/pid/cwd")

	claimed2, commit, _, err := r.ClaimGrant(info.GrantID, now)
	if err != nil {
		t.Fatalf("ClaimGrant (after bind): %v", err)
	}
	if claimed2.BoundCWD != "/resolved/pid/cwd" {
		t.Fatalf("expected BoundCWD set, got %q", claimed2.BoundCWD)
	}
	commit()
}

func TestSetBoundCWD_UnknownGrantIsNoOp(t *testing.T) {
	r := NewRegistry()
	// Must not panic on unknown grant ID.
	r.SetBoundCWD("does-not-exist", "/some/cwd")
}

func TestDenyGrant(t *testing.T) {
	r := NewRegistry()
	now := time.Now()

	info, err := r.RequestGrant("sess-1", "/cwd", "example.com", 1000, "r", now)
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}

	if err := r.DenyGrant(info.GrantID, now); err != nil {
		t.Fatalf("DenyGrant: %v", err)
	}

	if len(r.ListPending(now)) != 0 {
		t.Fatalf("expected grant removed after deny")
	}
	if _, ok := r.FindGrant(info.GrantID, now); ok {
		t.Fatalf("expected FindGrant to fail after deny")
	}

	// A new request for the same session+host should succeed (not blocked
	// by a stale coalesce index entry).
	if _, err := r.RequestGrant("sess-1", "/cwd", "example.com", 1000, "r2", now); err != nil {
		t.Fatalf("RequestGrant after deny: %v", err)
	}
}

func TestDenyGrant_NotFound(t *testing.T) {
	r := NewRegistry()
	now := time.Now()

	if err := r.DenyGrant("does-not-exist", now); err != ErrGrantNotFound {
		t.Fatalf("expected ErrGrantNotFound, got %v", err)
	}
}

func TestReap_ExpiredPending(t *testing.T) {
	r := NewRegistry()
	now := time.Now()

	info, err := r.RequestGrant("sess-1", "/cwd", "example.com", 1000, "r", now)
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}

	past := now.Add(PendingGrantTTL + time.Minute)
	result := r.Reap(past)

	if len(result.Reaped) != 1 || result.Reaped[0] != info.GrantID {
		t.Fatalf("expected grant %q reaped, got %+v", info.GrantID, result)
	}
	if len(r.ListPending(past)) != 0 {
		t.Fatalf("expected pending queue empty after reap")
	}
	if len(r.bySessionHost) != 0 {
		t.Fatalf("reap left stale coalescing index: %+v", r.bySessionHost)
	}
	replacement, err := r.RequestGrant("sess-1", "/cwd", "example.com", 1000, "replacement", past)
	if err != nil {
		t.Fatalf("RequestGrant after reap: %v", err)
	}
	if replacement.GrantID == info.GrantID {
		t.Fatal("request after reap reused expired grant ID")
	}
}

func TestReap_NonExpiredKept(t *testing.T) {
	r := NewRegistry()
	now := time.Now()

	if _, err := r.RequestGrant("sess-1", "/cwd", "example.com", 1000, "r", now); err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}

	soon := now.Add(time.Minute)
	result := r.Reap(soon)

	if len(result.Reaped) != 0 {
		t.Fatalf("expected nothing reaped, got %+v", result)
	}
	if len(r.ListPending(soon)) != 1 {
		t.Fatalf("expected grant to remain pending")
	}
}

func TestReap_ClaimedGrantNeverReaped(t *testing.T) {
	r := NewRegistry()
	now := time.Now()

	info, err := r.RequestGrant("sess-1", "/cwd", "example.com", 1000, "r", now)
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}

	_, _, rollback, err := r.ClaimGrant(info.GrantID, now)
	if err != nil {
		t.Fatalf("ClaimGrant: %v", err)
	}

	past := now.Add(PendingGrantTTL + time.Minute)
	result := r.Reap(past)
	if len(result.Reaped) != 0 {
		t.Fatalf("expected claimed grant not reaped, got %+v", result)
	}

	rollback()
}

func TestClaimGrant_ExpiryBoundary(t *testing.T) {
	created := time.Unix(1_700_000_000, 0)
	expires := created.Add(PendingGrantTTL)
	tests := []struct {
		name    string
		now     time.Time
		wantErr error
	}{
		{name: "one nanosecond before", now: expires.Add(-time.Nanosecond)},
		{name: "at expiry", now: expires, wantErr: ErrGrantExpired},
		{name: "after expiry", now: expires.Add(time.Nanosecond), wantErr: ErrGrantExpired},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := NewRegistry()
			info, err := r.RequestGrant("sess", "/cwd", "api.example.test", 1000, "reason", created)
			if err != nil {
				t.Fatal(err)
			}

			claimed, commit, rollback, err := r.ClaimGrant(info.GrantID, test.now)
			if err != test.wantErr {
				t.Fatalf("ClaimGrant error = %v, want %v", err, test.wantErr)
			}
			if test.wantErr == nil {
				if claimed.GrantID != info.GrantID || commit == nil || rollback == nil {
					t.Fatalf("live claim returned incomplete transaction: %+v", claimed)
				}
				commit()
			} else {
				if claimed != (ClaimedGrant{}) || commit != nil || rollback != nil {
					t.Fatalf("expired claim returned authority or closures: %+v", claimed)
				}
			}
			if len(r.grants) != 0 || len(r.bySessionHost) != 0 {
				t.Fatalf("claim left stale indexes: grants=%d index=%d", len(r.grants), len(r.bySessionHost))
			}
		})
	}
}

func TestDenyGrant_ExpiryBoundary(t *testing.T) {
	created := time.Unix(1_700_000_000, 0)
	expires := created.Add(PendingGrantTTL)
	tests := []struct {
		name    string
		now     time.Time
		wantErr error
	}{
		{name: "one nanosecond before", now: expires.Add(-time.Nanosecond)},
		{name: "at expiry", now: expires, wantErr: ErrGrantExpired},
		{name: "after expiry", now: expires.Add(time.Nanosecond), wantErr: ErrGrantExpired},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := NewRegistry()
			info, err := r.RequestGrant("sess", "/cwd", "api.example.test", 1000, "reason", created)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.DenyGrant(info.GrantID, test.now); err != test.wantErr {
				t.Fatalf("DenyGrant error = %v, want %v", err, test.wantErr)
			}
			if len(r.grants) != 0 || len(r.bySessionHost) != 0 {
				t.Fatalf("deny left stale indexes: grants=%d index=%d", len(r.grants), len(r.bySessionHost))
			}
		})
	}
}

func TestGrantReads_ExpiryBoundary(t *testing.T) {
	created := time.Unix(1_700_000_000, 0)
	expires := created.Add(PendingGrantTTL)
	tests := []struct {
		name     string
		now      time.Time
		wantLive bool
	}{
		{name: "one nanosecond before", now: expires.Add(-time.Nanosecond), wantLive: true},
		{name: "at expiry", now: expires},
		{name: "after expiry", now: expires.Add(time.Nanosecond)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := NewRegistry()
			info, err := r.RequestGrant("sess", "/cwd", "api.example.test", 1000, "reason", created)
			if err != nil {
				t.Fatal(err)
			}
			listed := r.ListPending(test.now)
			_, found := r.FindGrant(info.GrantID, test.now)
			snapshot := r.ReviewSnapshot(test.now)
			if gotLive := len(listed) == 1; gotLive != test.wantLive {
				t.Fatalf("ListPending live = %v, want %v", gotLive, test.wantLive)
			}
			if found != test.wantLive {
				t.Fatalf("FindGrant live = %v, want %v", found, test.wantLive)
			}
			if gotLive := snapshot.TotalPending == 1 && len(snapshot.Reviews) == 1; gotLive != test.wantLive {
				t.Fatalf("ReviewSnapshot live = %v, want %v: %+v", gotLive, test.wantLive, snapshot)
			}
		})
	}
}

func TestRequestGrant_ExpiredDuplicateMintsFreshID(t *testing.T) {
	created := time.Unix(1_700_000_000, 0)
	expires := created.Add(PendingGrantTTL)
	r := NewRegistry()
	first, err := r.RequestGrant("sess", "/old", "api.example.test", 1000, "old", created)
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.RequestGrant("sess", "/new", "api.example.test", 2000, "new", expires)
	if err != nil {
		t.Fatal(err)
	}
	if second.GrantID == first.GrantID {
		t.Fatal("expired duplicate renewed the stale stable ID")
	}
	pending := r.ListPending(expires)
	if len(pending) != 1 || pending[0].GrantID != second.GrantID || pending[0].CWD != "/new" {
		t.Fatalf("fresh duplicate state = %+v", pending)
	}
	key := sessionHostKey{sessionID: "sess", host: "api.example.test"}
	if r.bySessionHost[key] != second.GrantID || len(r.grants) != 1 {
		t.Fatalf("fresh duplicate index is inconsistent: grants=%d indexed=%q", len(r.grants), r.bySessionHost[key])
	}
}

func TestRequestGrant_ExpiredEntriesDoNotConsumeCaps(t *testing.T) {
	created := time.Unix(1_700_000_000, 0)
	expires := created.Add(PendingGrantTTL)

	t.Run("per session", func(t *testing.T) {
		r := NewRegistry()
		for i := range MaxPendingPerSession {
			if _, err := r.RequestGrant("sess", "/cwd", hostForIndex(i), 1000, "reason", created); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := r.RequestGrant("sess", "/cwd", "fresh.example.test", 1000, "reason", expires); err != nil {
			t.Fatalf("expired per-session entries consumed cap: %v", err)
		}
		if got := r.countPendingForSession("sess", expires); got != 1 {
			t.Fatalf("live per-session count = %d, want 1", got)
		}
		if len(r.grants) != 1 || len(r.bySessionHost) != 1 {
			t.Fatalf("per-session cap cleanup left stale indexes: grants=%d index=%d", len(r.grants), len(r.bySessionHost))
		}
	})

	t.Run("global", func(t *testing.T) {
		r := NewRegistry()
		for i := range MaxPendingGlobal {
			session := "sess-" + itoa(i/MaxPendingPerSession)
			if _, err := r.RequestGrant(session, "/cwd", hostForIndex(i), 1000, "reason", created); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := r.RequestGrant("fresh-session", "/cwd", "fresh.example.test", 1000, "reason", expires); err != nil {
			t.Fatalf("expired global entries consumed cap: %v", err)
		}
		if got := r.countPendingGlobal(expires); got != 1 {
			t.Fatalf("live global count = %d, want 1", got)
		}
		if len(r.grants) != 1 || len(r.bySessionHost) != 1 {
			t.Fatalf("global cap cleanup left stale indexes: grants=%d index=%d", len(r.grants), len(r.bySessionHost))
		}
	})
}

func TestClaimGrant_ExpiryAfterLinearization(t *testing.T) {
	created := time.Unix(1_700_000_000, 0)
	expires := created.Add(PendingGrantTTL)

	t.Run("commit may finish after expiry", func(t *testing.T) {
		r := NewRegistry()
		info, err := r.RequestGrant("sess", "/cwd", "api.example.test", 1000, "reason", created)
		if err != nil {
			t.Fatal(err)
		}
		_, commit, _, err := r.ClaimGrant(info.GrantID, expires.Add(-time.Nanosecond))
		if err != nil {
			t.Fatal(err)
		}
		commit()
		if len(r.grants) != 0 || len(r.bySessionHost) != 0 {
			t.Fatal("committed claim left registry state")
		}
	})

	t.Run("rollback is removed by next timed operation", func(t *testing.T) {
		r := NewRegistry()
		info, err := r.RequestGrant("sess", "/cwd", "api.example.test", 1000, "reason", created)
		if err != nil {
			t.Fatal(err)
		}
		_, _, rollback, err := r.ClaimGrant(info.GrantID, expires.Add(-time.Nanosecond))
		if err != nil {
			t.Fatal(err)
		}
		rollback()
		if got := r.ListPending(expires); len(got) != 0 {
			t.Fatalf("expired rollback became visible: %+v", got)
		}
		if _, _, _, err := r.ClaimGrant(info.GrantID, expires); err != ErrGrantExpired {
			t.Fatalf("reclaim after expiry = %v, want ErrGrantExpired", err)
		}
		if len(r.grants) != 0 || len(r.bySessionHost) != 0 {
			t.Fatal("expired rollback left stale indexes")
		}
	})
}

func TestClaimGrant_ConcurrentBoundary(t *testing.T) {
	type claimResult struct {
		claimed  ClaimedGrant
		commit   func()
		rollback func()
		err      error
	}
	created := time.Unix(1_700_000_000, 0)
	expires := created.Add(PendingGrantTTL)
	run := func(t *testing.T, now time.Time) []claimResult {
		t.Helper()
		r := NewRegistry()
		info, err := r.RequestGrant("sess", "/cwd", "api.example.test", 1000, "reason", created)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		results := make(chan claimResult, 2)
		var wg sync.WaitGroup
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				claimed, commit, rollback, err := r.ClaimGrant(info.GrantID, now)
				results <- claimResult{claimed: claimed, commit: commit, rollback: rollback, err: err}
			}()
		}
		close(start)
		wg.Wait()
		close(results)
		out := make([]claimResult, 0, 2)
		for result := range results {
			out = append(out, result)
		}
		return out
	}

	t.Run("before expiry has one winner", func(t *testing.T) {
		results := run(t, expires.Add(-time.Nanosecond))
		successes, alreadyClaimed := 0, 0
		for _, result := range results {
			switch result.err {
			case nil:
				successes++
				result.commit()
			case ErrGrantAlreadyClaimed:
				alreadyClaimed++
			default:
				t.Fatalf("unexpected claim result: %v", result.err)
			}
		}
		if successes != 1 || alreadyClaimed != 1 {
			t.Fatalf("successes=%d already_claimed=%d", successes, alreadyClaimed)
		}
	})

	t.Run("at expiry returns no authority", func(t *testing.T) {
		results := run(t, expires)
		expired, notFound := 0, 0
		for _, result := range results {
			if result.claimed != (ClaimedGrant{}) || result.commit != nil || result.rollback != nil {
				t.Fatalf("expired concurrent claim returned authority: %+v", result.claimed)
			}
			switch result.err {
			case ErrGrantExpired:
				expired++
			case ErrGrantNotFound:
				notFound++
			default:
				t.Fatalf("unexpected claim result: %v", result.err)
			}
		}
		if expired != 1 || notFound != 1 {
			t.Fatalf("expired=%d not_found=%d", expired, notFound)
		}
	})
}

func TestDenyGrant_DoesNotRemoveInflightClaim(t *testing.T) {
	created := time.Unix(1_700_000_000, 0)
	r := NewRegistry()
	info, err := r.RequestGrant("sess", "/cwd", "api.example.test", 1000, "reason", created)
	if err != nil {
		t.Fatal(err)
	}
	_, _, rollback, err := r.ClaimGrant(info.GrantID, created)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.DenyGrant(info.GrantID, created); err != ErrGrantAlreadyClaimed {
		t.Fatalf("deny in-flight claim = %v, want ErrGrantAlreadyClaimed", err)
	}
	rollback()
	if pending := r.ListPending(created); len(pending) != 1 || pending[0].GrantID != info.GrantID {
		t.Fatalf("deny corrupted in-flight claim: %+v", pending)
	}
}
