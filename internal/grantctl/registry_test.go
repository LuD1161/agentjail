package grantctl

import (
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

	pending := r.ListPending()
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

	pending := r.ListPending()
	if len(pending) != 1 {
		t.Fatalf("expected coalesced request to remain a single pending grant, got %d", len(pending))
	}
}

func TestRequestGrant_PerSessionCap(t *testing.T) {
	r := NewRegistry()
	now := time.Now()

	for i := 0; i < MaxPendingPerSession; i++ {
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

	if got := r.countPendingGlobal(); got != MaxPendingGlobal {
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

	pending := r.ListPending()
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

	claimed, commit, _, err := r.ClaimGrant(info.GrantID)
	if err != nil {
		t.Fatalf("ClaimGrant: %v", err)
	}
	if claimed.GrantID != info.GrantID || claimed.Host != "example.com" {
		t.Fatalf("unexpected claimed snapshot: %+v", claimed)
	}

	// Claimed grants are invisible to ListPending/FindGrant.
	if len(r.ListPending()) != 0 {
		t.Fatalf("expected claimed grant hidden from ListPending")
	}
	if _, ok := r.FindGrant(info.GrantID); ok {
		t.Fatalf("expected claimed grant hidden from FindGrant")
	}

	commit()

	if len(r.ListPending()) != 0 {
		t.Fatalf("expected grant removed after commit")
	}
	if _, ok := r.FindGrant(info.GrantID); ok {
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

	_, _, rollback, err := r.ClaimGrant(info.GrantID)
	if err != nil {
		t.Fatalf("ClaimGrant: %v", err)
	}

	rollback()

	pending := r.ListPending()
	if len(pending) != 1 {
		t.Fatalf("expected grant restored to pending after rollback, got %d", len(pending))
	}
	found, ok := r.FindGrant(info.GrantID)
	if !ok {
		t.Fatalf("expected FindGrant to find restored grant")
	}
	if found.GrantID != info.GrantID {
		t.Fatalf("unexpected restored grant: %+v", found)
	}

	// The grant should be reclaimable again after rollback.
	if _, _, _, err := r.ClaimGrant(info.GrantID); err != nil {
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

	_, _, _, err = r.ClaimGrant(info.GrantID)
	if err != nil {
		t.Fatalf("first ClaimGrant: %v", err)
	}

	_, _, _, err = r.ClaimGrant(info.GrantID)
	if err != ErrGrantAlreadyClaimed {
		t.Fatalf("expected ErrGrantAlreadyClaimed on double claim, got %v", err)
	}
}

func TestClaimGrant_NotFound(t *testing.T) {
	r := NewRegistry()

	_, _, _, err := r.ClaimGrant("does-not-exist")
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
	claimed, _, rollback, err := r.ClaimGrant(info.GrantID)
	if err != nil {
		t.Fatalf("ClaimGrant: %v", err)
	}
	if claimed.BoundCWD != "" {
		t.Fatalf("expected empty BoundCWD before SetBoundCWD, got %q", claimed.BoundCWD)
	}
	rollback()

	r.SetBoundCWD(info.GrantID, "/resolved/pid/cwd")

	claimed2, commit, _, err := r.ClaimGrant(info.GrantID)
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

	if err := r.DenyGrant(info.GrantID); err != nil {
		t.Fatalf("DenyGrant: %v", err)
	}

	if len(r.ListPending()) != 0 {
		t.Fatalf("expected grant removed after deny")
	}
	if _, ok := r.FindGrant(info.GrantID); ok {
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

	if err := r.DenyGrant("does-not-exist"); err != ErrGrantNotFound {
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
	if len(r.ListPending()) != 0 {
		t.Fatalf("expected pending queue empty after reap")
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
	if len(r.ListPending()) != 1 {
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

	_, _, rollback, err := r.ClaimGrant(info.GrantID)
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
