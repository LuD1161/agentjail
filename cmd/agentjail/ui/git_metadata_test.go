package ui

import (
	"context"
	"fmt"
	localstore "github.com/LuD1161/agentjail/internal/store"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRepositoryCacheExpiryAndNegativeResults(t *testing.T) {
	now := time.Unix(1, 0)
	calls := 0
	cache := repositoryCache{
		now:    func() time.Time { return now },
		lookup: func(context.Context, string) repositoryInfo { calls++; return repositoryInfo{} },
	}
	for n := 0; n < 100; n++ {
		cache.get(context.Background(), "missing")
	}
	if calls != 1 {
		t.Fatalf("negative lookup calls = %d", calls)
	}
	now = now.Add(repositoryCacheTTL)
	cache.get(context.Background(), "missing")
	if calls != 2 {
		t.Fatalf("expired lookup calls = %d", calls)
	}
	for n := 0; n < maxRepositoryCacheEntries+1; n++ {
		cache.get(context.Background(), fmt.Sprint(n))
	}
	if len(cache.entries) > maxRepositoryCacheEntries {
		t.Fatalf("cache grew to %d", len(cache.entries))
	}
}

func TestRepositoryCacheCoalescesAndCancelsWaiters(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int64
	cache := repositoryCache{lookup: func(context.Context, string) repositoryInfo {
		calls.Add(1)
		close(entered)
		<-release
		return repositoryInfo{branch: "main"}
	}}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); cache.get(context.Background(), "repo") }()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := cache.get(ctx, "repo"); got.branch != "" {
		t.Fatalf("cancelled result = %v", got)
	}
	for n := 0; n < 20; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := cache.get(context.Background(), "repo"); got.branch != "main" {
				t.Errorf("result = %v", got)
			}
		}()
	}
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("coalesced lookup calls = %d", calls.Load())
	}
}

func TestRepositoryLookupHasDeadlineAndDoesNotCacheCallerCancellation(t *testing.T) {
	var calls int
	cache := repositoryCache{}
	ctx, cancel := context.WithCancel(context.Background())
	cache.lookup = func(ctx context.Context, _ string) repositoryInfo {
		calls++
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > repositoryLookupTimeout {
			t.Error("lookup has no bounded deadline")
		}
		cancel()
		<-ctx.Done()
		return repositoryInfo{}
	}
	cache.get(ctx, "repo")
	cache.lookup = func(context.Context, string) repositoryInfo { calls++; return repositoryInfo{branch: "main"} }
	if got := cache.get(context.Background(), "repo"); got.branch != "main" || calls != 2 {
		t.Fatalf("retry = %v, calls = %d", got, calls)
	}
}

func TestIngestionMetadataDoesNotHoldStateLock(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	store := NewStore()
	store.repositories.lookup = func(context.Context, string) repositoryInfo {
		close(entered)
		<-release
		return repositoryInfo{branch: "main"}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		store.Ingest([]byte(`{"msg":"eval","session_id":"one","cwd":"repo","action":"allow"}`))
	}()
	<-entered
	snapshot := make(chan struct{})
	go func() { store.Snapshot(); close(snapshot) }()
	select {
	case <-snapshot:
	case <-time.After(time.Second):
		close(release)
		<-done
		t.Fatal("metadata lookup blocked snapshot")
	}
	close(release)
	<-done
	if got := store.Snapshot(); len(got.Sessions) != 1 || got.Sessions[0].Branch != "main" {
		t.Fatalf("snapshot = %+v", got)
	}
}

func BenchmarkRepositoryMetadataCached(b *testing.B) {
	cache := repositoryCache{lookup: func(context.Context, string) repositoryInfo { return repositoryInfo{branch: "main"} }}
	cache.get(context.Background(), "repo")
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		cache.get(context.Background(), "repo")
	}
}

func TestSQLiteSnapshotCachesRepositoryPerDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")
	st, err := localstore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	for n := 0; n < 20; n++ {
		if err := st.RecordDecision(ctx, localstore.DecisionRecord{Ts: time.Now(), SessionID: fmt.Sprint(n), ToolName: "Read", Action: "allow", CWD: "shared-repo"}); err != nil {
			t.Fatal(err)
		}
	}
	server := NewServer("", "", path, false, NewStore(), "")
	defer func() {
		if server.dbConn != nil {
			server.dbConn.Close()
		}
	}()
	calls := 0
	server.repositories.lookup = func(context.Context, string) repositoryInfo {
		calls++
		return repositoryInfo{branch: "main", name: "shared"}
	}
	for n := 0; n < 2; n++ {
		snap, err := server.sqliteSnapshot(ctx, localstore.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		if len(snap.Sessions) != 20 {
			t.Fatalf("sessions = %d", len(snap.Sessions))
		}
	}
	if calls != 1 {
		t.Fatalf("metadata calls for shared CWD = %d", calls)
	}
}
