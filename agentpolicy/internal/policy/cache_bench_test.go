package policy

// cache_bench_test.go — benchmark the static/dynamic key split strategy
// against a naive full-input hash.
//
// Workload model:
//   50 unique commands (rm, git, cat, … pattern variants) × 100 sessions.
//   Each (command, session) pair issues 3 repeated calls.
//
// The split strategy: key on (ToolName + staticInputHash(in)), which strips
// session_id and per-session Cwd. All 100 sessions issuing the same command
// hash to the same CacheKey → ~100 cache hits per command after the first
// session warms the entry.
//
// The naive strategy: key on hashInput(in) which includes session_id (stored
// in Context["session_id"]) and Cwd. Every (command, session) pair is a
// distinct key → 5000 entries, each hit only on the 2nd and 3rd repetitions
// within the same session.
//
// Run: go test ./internal/policy/... -bench=. -benchtime=1s -v

import (
	"fmt"
	"testing"
)

// syntheticCommands returns n distinct Input values representing commands like
// "rm -rf", "git status", etc. — the static content is stable, but callers
// layer in a session_id via Context to simulate dynamic fields.
func syntheticCommands(n int) []Input {
	templates := []struct {
		hook    string
		program string
		flags   []string
		pos     []string
		action  string
		path    string
		host    string
		method  string
	}{
		{"exec", "rm", []string{"-r", "-f"}, []string{"/tmp/build"}, "", "", "", ""},
		{"exec", "git", []string{"status"}, nil, "", "", "", ""},
		{"exec", "git", []string{"diff"}, []string{"HEAD"}, "", "", "", ""},
		{"exec", "git", []string{"log", "--oneline", "-20"}, nil, "", "", "", ""},
		{"exec", "cat", nil, []string{"/etc/hosts"}, "", "", "", ""},
		{"file", "", nil, nil, "read", "/Users/alice/.ssh/id_rsa", "", ""},
		{"file", "", nil, nil, "write", "/tmp/output.txt", "", ""},
		{"file", "", nil, nil, "read", "/Users/alice/.aws/credentials", "", ""},
		{"http", "", nil, nil, "fetch", "", "api.anthropic.com", "POST"},
		{"http", "", nil, nil, "fetch", "", "api.github.com", "GET"},
	}

	cmds := make([]Input, n)
	for i := 0; i < n; i++ {
		t := templates[i%len(templates)]
		cmds[i] = Input{
			Hook:       t.hook,
			Program:    fmt.Sprintf("%s-%d", t.program, i/len(templates)),
			Flags:      t.flags,
			Positional: t.pos,
			Action:     t.action,
			Path:       t.path,
			Host:       t.host,
			Method:     t.method,
		}
	}
	return cmds
}

// injectSession returns a copy of in with session_id injected into Context
// and a per-session Cwd. These fields are the "dynamic" part that the split
// strategy strips when building the cache key.
func injectSession(in Input, sessionID string) Input {
	ctx := make(map[string]any, len(in.Context)+1)
	for k, v := range in.Context {
		ctx[k] = v
	}
	ctx["session_id"] = sessionID
	out := in
	out.Context = ctx
	out.Cwd = "/tmp/agent-" + sessionID + "/workdir"
	return out
}

// BenchmarkCacheWithStaticDynamicSplit measures the hit rate achieved by the
// Cache interface's CacheKey (ToolName + staticInputHash), which strips
// session-specific fields.
//
// Workload: 50 commands × 100 sessions × 3 repeats per (command, session).
// After the first session warms each command, subsequent sessions are hits.
// Expected hit rate: (sessions-1)/sessions × 100 % ≈ 99 %.
func BenchmarkCacheWithStaticDynamicSplit(b *testing.B) {
	const (
		numCommands = 50
		numSessions = 100
		repeats     = 3
	)
	commands := syntheticCommands(numCommands)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache := NewLRUCache(numCommands * 2) // generous — no LRU eviction needed
		hits, misses := 0, 0
		for sess := 0; sess < numSessions; sess++ {
			sid := fmt.Sprintf("sess-%04d", sess)
			for _, cmd := range commands {
				sessCmd := injectSession(cmd, sid)
				key := StaticKey(sessCmd)
				for rep := 0; rep < repeats; rep++ {
					if _, ok := cache.Get(key); ok {
						hits++
					} else {
						misses++
						cache.Set(key, Decision{Action: "allow"})
					}
				}
			}
		}
		st := cache.Stats()
		b.ReportMetric(float64(st.Hits)/float64(st.Hits+st.Misses)*100, "hit_pct")
		_ = hits
		_ = misses
	}
}

// BenchmarkCacheNaiveFullHash measures the hit rate when the full Input
// (including session_id in Context and Cwd) is hashed as the cache key.
//
// Workload: identical to the split benchmark.
// Expected hit rate: (repeats-1)/repeats × 100 % ≈ 66 % — only the 2nd and
// 3rd call within the SAME session hit. Cross-session repetitions are misses
// because the session_id changes the hash.
func BenchmarkCacheNaiveFullHash(b *testing.B) {
	const (
		numCommands = 50
		numSessions = 100
		repeats     = 3
	)
	commands := syntheticCommands(numCommands)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		inner := newLRU(numCommands * numSessions * 2) // large enough to avoid eviction
		hits, misses := 0, 0
		for sess := 0; sess < numSessions; sess++ {
			sid := fmt.Sprintf("sess-%04d", sess)
			for _, cmd := range commands {
				sessCmd := injectSession(cmd, sid)
				for rep := 0; rep < repeats; rep++ {
					k := hashInput(sessCmd) // naive: full hash including session_id + cwd
					if _, ok := inner.get(k); ok {
						hits++
					} else {
						misses++
						inner.put(k, Decision{Action: "allow"})
					}
				}
			}
		}
		total := hits + misses
		b.ReportMetric(float64(hits)/float64(total)*100, "hit_pct")
	}
}

// BenchmarkStaticKeyDerivation measures the overhead of computing StaticKey
// (including staticInputHash) for a single Input. This is the per-request
// cost added by the split strategy on top of the cache lookup.
func BenchmarkStaticKeyDerivation(b *testing.B) {
	in := Input{
		Hook:       "exec",
		Program:    "rm",
		Flags:      []string{"-r", "-f"},
		Positional: []string{"/Users/alice/project/build"},
		Context:    map[string]any{"session_id": "sess-0001"},
		Cwd:        "/tmp/agent-sess-0001/workdir",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = StaticKey(in)
	}
}

// BenchmarkHitRateImprovement is a non-benchmark correctness assertion run
// under testing.T to surface the hit-rate numbers in plain `go test` output.
// It mirrors BenchmarkCacheWithStaticDynamicSplit and BenchmarkCacheNaiveFullHash
// but reports via t.Logf so it appears with -v.
func BenchmarkHitRateImprovement(b *testing.B) {
	const (
		numCommands = 50
		numSessions = 100
		repeats     = 3
	)
	commands := syntheticCommands(numCommands)

	// Split cache
	splitCache := NewLRUCache(numCommands * 2)
	for sess := 0; sess < numSessions; sess++ {
		sid := fmt.Sprintf("sess-%04d", sess)
		for _, cmd := range commands {
			sessCmd := injectSession(cmd, sid)
			key := StaticKey(sessCmd)
			for rep := 0; rep < repeats; rep++ {
				if _, ok := splitCache.Get(key); !ok {
					splitCache.Set(key, Decision{Action: "allow"})
				}
			}
		}
	}
	splitStats := splitCache.Stats()

	// Naive cache
	naiveCache := newLRU(numCommands * numSessions * 2)
	var naiveHits, naiveMisses int64
	for sess := 0; sess < numSessions; sess++ {
		sid := fmt.Sprintf("sess-%04d", sess)
		for _, cmd := range commands {
			sessCmd := injectSession(cmd, sid)
			for rep := 0; rep < repeats; rep++ {
				k := hashInput(sessCmd)
				if _, ok := naiveCache.get(k); ok {
					naiveHits++
				} else {
					naiveMisses++
					naiveCache.put(k, Decision{Action: "allow"})
				}
			}
		}
	}

	splitHitPct := float64(splitStats.Hits) / float64(splitStats.Hits+splitStats.Misses) * 100
	naiveHitPct := float64(naiveHits) / float64(naiveHits+naiveMisses) * 100

	b.ReportMetric(splitHitPct, "split_hit_pct")
	b.ReportMetric(naiveHitPct, "naive_hit_pct")
	b.ReportMetric(float64(naiveMisses)/float64(splitStats.Misses), "miss_ratio_naive_over_split")
}
