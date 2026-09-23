package policyeval

import (
	"context"
	"errors"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRepoRootNegativeCacheExpiresAfterGitInit(t *testing.T) {
	cwd := t.TempDir()
	now := time.Unix(100, 0)
	e := &evaluator{repoRootNow: func() time.Time { return now }}
	if root := e.resolveRepoRoot(context.Background(), cwd); root != "" {
		t.Fatalf("unexpected root %q", root)
	}
	if out, err := exec.Command("git", "init", "--quiet", cwd).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	if root := e.resolveRepoRoot(context.Background(), cwd); root != "" {
		t.Fatal("negative cache did not retain its bounded lifetime")
	}
	now = now.Add(repoRootNegativeTTL)
	if root := e.resolveRepoRoot(context.Background(), cwd); root != CanonicalizeCWD(cwd) {
		t.Fatalf("root=%q, want newly initialized repository", root)
	}
}

func TestRepoRootCacheExpiry(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		ttl  time.Duration
	}{{"positive", nil, repoRootTTL}, {"transient", errors.New("temporary lookup error"), repoRootNegativeTTL}} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Unix(100, 0)
			calls := 0
			e := &evaluator{repoRootNow: func() time.Time { return now }, findRepoRoot: func(context.Context, string) (string, error) {
				calls++
				if calls == 1 {
					return "/first", tc.err
				}
				return "/second", nil
			}}
			first := e.resolveRepoRoot(context.Background(), "cwd")
			if got := e.resolveRepoRoot(context.Background(), "cwd"); got != first || calls != 1 {
				t.Fatal("cache missed before expiry")
			}
			now = now.Add(tc.ttl)
			if got := e.resolveRepoRoot(context.Background(), "cwd"); got != "/second" || calls != 2 {
				t.Fatal("did not refresh expired result")
			}
		})
	}
}

func TestRepoRootDoesNotCacheCancellation(t *testing.T) {
	for _, lookupErr := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(lookupErr.Error(), func(t *testing.T) {
			calls := 0
			e := &evaluator{findRepoRoot: func(context.Context, string) (string, error) {
				calls++
				if calls == 1 {
					return "", lookupErr
				}
				return "/root", nil
			}}
			e.resolveRepoRoot(context.Background(), "cwd")
			if root := e.resolveRepoRoot(context.Background(), "cwd"); root != "/root" || calls != 2 {
				t.Fatal("cancellation was cached")
			}
		})
	}
}

func TestRepoRootPropagatesCancellation(t *testing.T) {
	started := make(chan struct{})
	e := &evaluator{findRepoRoot: func(ctx context.Context, _ string) (string, error) {
		close(started)
		<-ctx.Done()
		return "", ctx.Err()
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan string, 1)
	go func() { done <- e.resolveRepoRoot(ctx, "cwd") }()
	<-started
	cancel()
	if root := <-done; root != "" {
		t.Fatal("canceled lookup returned a root")
	}
	if len(e.repoRootCache) != 0 {
		t.Fatal("canceled lookup populated cache")
	}
}

func TestRepoRootConcurrentLookupsShareResult(t *testing.T) {
	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	e := &evaluator{findRepoRoot: func(context.Context, string) (string, error) {
		calls.Add(1)
		close(started)
		<-release
		return "/root", nil
	}}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if root := e.resolveRepoRoot(context.Background(), "cwd"); root != "/root" {
				t.Errorf("root=%q", root)
			}
		}()
	}
	<-started
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if root := e.resolveRepoRoot(cancelCtx, "cwd"); root != "" {
		t.Fatal("canceled waiter returned a root")
	}
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("lookups=%d, want one", calls.Load())
	}
}

func TestReloadClearsRepoRoots(t *testing.T) {
	e := newTrustTestEvaluator(t)
	calls := 0
	e.findRepoRoot = func(context.Context, string) (string, error) { calls++; return "/root", nil }
	e.resolveRepoRoot(context.Background(), "cwd")
	if err := e.Reload(context.Background(), e.modules, e.cfg); err != nil {
		t.Fatal(err)
	}
	e.resolveRepoRoot(context.Background(), "cwd")
	if calls != 2 {
		t.Fatal("reload retained repository discovery cache")
	}
}

func BenchmarkRepoRootWarm(b *testing.B) {
	e := &evaluator{findRepoRoot: func(context.Context, string) (string, error) { return "/root", nil }}
	e.resolveRepoRoot(context.Background(), "cwd")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.resolveRepoRoot(context.Background(), "cwd")
	}
}

// Done signals that a live waiter has joined an existing discovery flight.
type observedRepoContext struct {
	context.Context
	joined chan struct{}
	once   sync.Once
}

func (c *observedRepoContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.joined) })
	return c.Context.Done()
}

func TestRepoRootLiveWaiterRetriesCanceledLeader(t *testing.T) {
	var calls atomic.Int32
	started := make(chan struct{})
	e := &evaluator{findRepoRoot: func(ctx context.Context, _ string) (string, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-ctx.Done()
			return "", ctx.Err()
		}
		return "/project", nil
	}}
	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	defer cancelLeader()
	leaderDone := make(chan string, 1)
	go func() { leaderDone <- e.resolveRepoRoot(leaderCtx, "cwd") }()
	<-started
	waiterCtx := &observedRepoContext{Context: context.Background(), joined: make(chan struct{})}
	waiterDone := make(chan string, 1)
	go func() { waiterDone <- e.resolveRepoRoot(waiterCtx, "cwd") }()
	<-waiterCtx.joined
	cancelLeader()
	if root := <-leaderDone; root != "" {
		t.Fatalf("canceled leader root=%q", root)
	}
	if root := <-waiterDone; root != "/project" {
		t.Fatalf("live waiter root=%q, want independent retry", root)
	}
	if calls.Load() != 2 {
		t.Fatalf("lookups=%d, want two", calls.Load())
	}
	if root := e.resolveRepoRoot(context.Background(), "cwd"); root != "/project" || calls.Load() != 2 {
		t.Fatal("retry result was not cached")
	}
}

func TestRepoRootWaitersShareInternalTimeout(t *testing.T) {
	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	e := &evaluator{findRepoRoot: func(context.Context, string) (string, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return "", context.DeadlineExceeded
	}}
	leaderDone := make(chan string, 1)
	go func() { leaderDone <- e.resolveRepoRoot(context.Background(), "cwd") }()
	<-started
	const waiters = 8
	results := make(chan string, waiters)
	for i := 0; i < waiters; i++ {
		waiterCtx := &observedRepoContext{Context: context.Background(), joined: make(chan struct{})}
		go func() { results <- e.resolveRepoRoot(waiterCtx, "cwd") }()
		<-waiterCtx.joined
	}
	close(release)
	if root := <-leaderDone; root != "" {
		t.Fatalf("leader root=%q", root)
	}
	for i := 0; i < waiters; i++ {
		if root := <-results; root != "" {
			t.Fatalf("waiter root=%q", root)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("lookups=%d, want one shared internal timeout", calls.Load())
	}
	if len(e.repoRootCache) != 0 {
		t.Fatal("internal timeout was cached")
	}
}
