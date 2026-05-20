package proctree

import (
	"errors"
	"os"
	"testing"
)

// fakeTree builds a parentOf func from a child -> parent map. Anything
// not present in the map returns ErrUnsupported so tests don't silently
// fall through to /proc.
func fakeTree(t *testing.T, parents map[int]int) func(int) (int, error) {
	t.Helper()
	return func(pid int) (int, error) {
		p, ok := parents[pid]
		if !ok {
			return 0, errors.New("fakeTree: unknown pid")
		}
		return p, nil
	}
}

func TestIsDescendant_DirectChild(t *testing.T) {
	restore := withLookup(fakeTree(t, map[int]int{
		200: 100,
		100: 1,
	}))
	defer restore()
	if !IsDescendant(200, 100) {
		t.Fatalf("expected 200 to descend from 100")
	}
}

func TestIsDescendant_SelfIsDescendant(t *testing.T) {
	if !IsDescendant(42, 42) {
		t.Fatalf("a pid must be its own descendant (inclusive)")
	}
}

func TestIsDescendant_NotADescendant(t *testing.T) {
	restore := withLookup(fakeTree(t, map[int]int{
		200: 1, // 200 -> init, never sees 100
	}))
	defer restore()
	if IsDescendant(200, 100) {
		t.Fatalf("200 is not under 100")
	}
}

func TestIsDescendant_DepthCap(t *testing.T) {
	// Build a chain of MaxDepth+5 hops with the ancestor at the bottom;
	// IsDescendant must give up after MaxDepth and return false.
	chain := map[int]int{}
	for i := 1000; i <= 1000+MaxDepth+5; i++ {
		chain[i] = i + 1
	}
	ancestor := 1000 + MaxDepth + 6
	chain[ancestor] = 1 // top of chain rooted at init
	restore := withLookup(fakeTree(t, chain))
	defer restore()
	// The ancestor sits MaxDepth+6 hops above pid=1000 — past the cap.
	if IsDescendant(1000, ancestor) {
		t.Fatalf("expected depth cap to prevent reaching ancestor at >MaxDepth")
	}
}

func TestIsDescendant_Cycle(t *testing.T) {
	// 100 -> 200 -> 100 (ppid cycle after PID wrap).
	restore := withLookup(func(pid int) (int, error) {
		switch pid {
		case 100:
			return 200, nil
		case 200:
			return 100, nil
		}
		return 0, errors.New("unknown")
	})
	defer restore()
	if IsDescendant(100, 999) {
		t.Fatalf("cycle should return false, not loop")
	}
}

func TestIsDescendant_LookupError(t *testing.T) {
	restore := withLookup(func(pid int) (int, error) {
		return 0, errors.New("vanished")
	})
	defer restore()
	if IsDescendant(100, 1) {
		t.Fatalf("lookup error must fail-closed")
	}
}

func TestIsDescendant_NegativePID(t *testing.T) {
	if IsDescendant(-1, 1) || IsDescendant(1, -1) || IsDescendant(0, 1) {
		t.Fatalf("non-positive pids must return false")
	}
}

func TestParentOf_RootIsItself(t *testing.T) {
	p, err := ParentOf(1)
	if err != nil || p != 1 {
		t.Fatalf("ParentOf(1) = (%d, %v); want (1, nil)", p, err)
	}
}

func TestParentOf_RealProcess(t *testing.T) {
	// Self-test against the real OS to make sure the platform impl is
	// wired up. Skip on unsupported GOOSes (where parentOf returns
	// ErrUnsupported up-front).
	pid := os.Getpid()
	p, err := ParentOf(pid)
	if errors.Is(err, ErrUnsupported) {
		t.Skip("platform unsupported; cgo/path impl not present")
	}
	if err != nil {
		t.Fatalf("ParentOf(self) failed: %v", err)
	}
	if p <= 0 {
		t.Fatalf("expected positive ppid, got %d", p)
	}
}
