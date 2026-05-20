package seccomp

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// TestBaselineCoveredByKnownNames asserts every name we put in
// Baseline is also in KnownNames. Without this, a typo in Baseline
// would silently get rejected as "unknown" at Apply() time on Linux —
// the test catches it on every developer workstation, no kernel
// required.
func TestBaselineCoveredByKnownNames(t *testing.T) {
	for _, name := range Baseline {
		if _, ok := KnownNames[name]; !ok {
			t.Errorf("Baseline contains %q but KnownNames does not; add it to known.go", name)
		}
	}
}

// TestBaselineNoSuspectDuplicates flags accidental duplicate entries
// (cheap diff catcher for future contributors).
func TestBaselineNoSuspectDuplicates(t *testing.T) {
	seen := make(map[string]int, len(Baseline))
	for _, n := range Baseline {
		seen[n]++
	}
	for name, count := range seen {
		if count > 1 {
			t.Errorf("Baseline contains %q %dx; pick a single entry", name, count)
		}
	}
}

// TestDefaultProfileIsSafe asserts Default() ships fail-closed.
func TestDefaultProfileIsSafe(t *testing.T) {
	p := Default()
	if p.DefaultAction != ActionKillProcess {
		t.Errorf("Default().DefaultAction = %v; want ActionKillProcess (fail-closed)", p.DefaultAction)
	}
	if p.Size() < 50 {
		t.Errorf("Default().Size() = %d; baseline shrunk unexpectedly", p.Size())
	}
}

// TestStraceValidate is the strace-vs-allowlist coverage check. It
// parses testdata/claude-strace.txt, extracts every syscall name, and
// fails if any observed syscall is missing from Baseline.
//
// This is the load-bearing allowlist coverage test ("Allowlist sized
// to what Claude/Codex/Aider actually need"). Run it on every commit:
//
//	go test ./agentjail/internal/seccomp/...
//
// To regenerate the fixture with a fresh trace, see the comment at the
// top of testdata/claude-strace.txt.
func TestStraceValidate(t *testing.T) {
	f, err := os.Open("testdata/claude-strace.txt")
	if err != nil {
		t.Fatalf("open trace fixture: %v", err)
	}
	defer f.Close()

	allow := make(map[string]struct{}, len(Baseline))
	for _, n := range Baseline {
		allow[n] = struct{}{}
	}

	// knownUnused = syscalls strace might emit that we intentionally
	// do not allow (none today; placeholder so future additions don't
	// silently sneak past).
	knownUnused := map[string]struct{}{
		// e.g. "ptrace": {}, // would belong here if we explicitly
		// decided ptrace stays denied even when observed in a trace.
	}

	scanner := bufio.NewScanner(f)
	// Some strace lines are very long once arg-blobs are inlined; raise
	// the scanner buffer from the default 64 KiB so we don't error out.
	scanner.Buffer(make([]byte, 0, 1<<16), 1<<20)
	missing := make(map[string]struct{})
	seen := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// strace format: "name(args...) = ret".
		paren := strings.IndexByte(line, '(')
		if paren <= 0 {
			continue
		}
		name := line[:paren]
		// strace may prefix multi-threaded output with "[pid 1234] ";
		// strip any leading bracket block.
		if strings.HasPrefix(name, "[") {
			if end := strings.Index(line, "] "); end > 0 {
				name = strings.TrimSpace(line[end+2 : paren])
			}
		}
		// Whitelist resumed/unfinished syscall fragments: strace emits
		// "<... read resumed>" on signal interruption — ignore those.
		if strings.HasPrefix(name, "<") {
			continue
		}
		seen++
		if _, ok := allow[name]; ok {
			continue
		}
		if _, ok := knownUnused[name]; ok {
			continue
		}
		missing[name] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan trace fixture: %v", err)
	}
	if seen == 0 {
		t.Fatal("strace fixture parsed 0 syscalls; did the file format change?")
	}
	if len(missing) > 0 {
		names := make([]string, 0, len(missing))
		for n := range missing {
			names = append(names, n)
		}
		t.Errorf("strace contained syscalls not in Baseline; add or document them: %v", names)
	}
}

// BenchmarkProfileBuild benchmarks the in-memory profile construction
// (no Apply syscall, so it runs on macOS). The cost should stay sub-
// millisecond — if it doesn't, KISS has been violated somewhere.
func BenchmarkProfileBuild(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = Default()
	}
}
