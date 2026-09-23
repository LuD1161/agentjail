package policyeval

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	repoRootTTL         = time.Minute
	repoRootNegativeTTL = time.Second
)

type repoRootEntry struct {
	root    string
	expires time.Time
}

type repoRootFlight struct {
	done      chan struct{}
	root      string
	callerErr error
}

func (e *evaluator) resolveRepoRoot(ctx context.Context, cwd string) string {
	if cwd == "" || ctx.Err() != nil {
		return ""
	}
	now := time.Now
	if e.repoRootNow != nil {
		now = e.repoRootNow
	}
	for {
		if ctx.Err() != nil {
			return ""
		}
		e.repoRootMu.Lock()
		if entry, ok := e.repoRootCache[cwd]; ok && now().Before(entry.expires) {
			e.repoRootMu.Unlock()
			return entry.root
		}
		if flight, ok := e.repoRootInFlight[cwd]; ok {
			e.repoRootMu.Unlock()
			select {
			case <-ctx.Done():
				return ""
			case <-flight.done:
				if flight.callerErr != nil {
					continue
				}
				return flight.root
			}
		}
		flight := &repoRootFlight{done: make(chan struct{})}
		if e.repoRootInFlight == nil {
			e.repoRootInFlight = make(map[string]*repoRootFlight)
		}
		e.repoRootInFlight[cwd] = flight
		generation := e.gen.Load()
		e.repoRootMu.Unlock()

		find := gitRepoRoot
		if e.findRepoRoot != nil {
			find = e.findRepoRoot
		}
		root, err := find(ctx, cwd)
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		ttl := repoRootTTL
		if err != nil || root == "" {
			root = ""
			ttl = repoRootNegativeTTL
		}
		e.repoRootMu.Lock()
		if ctx.Err() == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && generation == e.gen.Load() {
			if e.repoRootCache == nil {
				e.repoRootCache = make(map[string]repoRootEntry)
			}
			e.repoRootCache[cwd] = repoRootEntry{root: root, expires: now().Add(ttl)}
		}
		flight.root = root
		flight.callerErr = ctx.Err()
		delete(e.repoRootInFlight, cwd)
		close(flight.done)
		e.repoRootMu.Unlock()
		return root
	}
}

func gitRepoRoot(ctx context.Context, cwd string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	out, err := exec.CommandContext(ctx, "git", "-C", cwd, "rev-parse", "--show-toplevel").Output()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if err != nil {
		return "", err
	}
	root := strings.TrimSpace(string(out))
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	return root, nil
}
