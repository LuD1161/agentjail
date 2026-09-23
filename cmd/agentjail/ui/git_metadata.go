package ui

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	repositoryCacheTTL        = 30 * time.Second
	repositoryLookupTimeout   = 500 * time.Millisecond
	maxRepositoryCacheEntries = 256
)

type repositoryInfo struct{ branch, name string }
type repositoryEntry struct {
	info    repositoryInfo
	expires time.Time
	ready   chan struct{}
}

type repositoryCache struct {
	mu      sync.Mutex
	entries map[string]*repositoryEntry
	lookup  func(context.Context, string) repositoryInfo
	now     func() time.Time
}

// Metadata is optional; failed lookups are cached as empty fields.
func (c *repositoryCache) get(ctx context.Context, cwd string) repositoryInfo {
	if cwd == "" || ctx.Err() != nil {
		return repositoryInfo{}
	}
	c.mu.Lock()
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	if entry := c.entries[cwd]; entry != nil {
		if entry.ready != nil {
			ready := entry.ready
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return repositoryInfo{}
			case <-ready:
				return entry.info
			}
		}
		if now().Before(entry.expires) {
			info := entry.info
			c.mu.Unlock()
			return info
		}
		delete(c.entries, cwd)
	}
	if c.entries == nil {
		c.entries = make(map[string]*repositoryEntry)
	}
	if len(c.entries) >= maxRepositoryCacheEntries {
		var oldest string
		var expiry time.Time
		for path, entry := range c.entries {
			if entry.ready == nil && (oldest == "" || entry.expires.Before(expiry)) {
				oldest, expiry = path, entry.expires
			}
		}
		if oldest == "" {
			c.mu.Unlock()
			return repositoryInfo{}
		}
		delete(c.entries, oldest)
	}
	entry := &repositoryEntry{ready: make(chan struct{})}
	c.entries[cwd] = entry
	lookup := c.lookup
	if lookup == nil {
		lookup = readRepositoryInfo
	}
	c.mu.Unlock()

	lookupCtx, cancel := context.WithTimeout(ctx, repositoryLookupTimeout)
	info := lookup(lookupCtx, cwd)
	cancel()
	c.mu.Lock()
	entry.info, entry.expires = info, now().Add(repositoryCacheTTL)
	if ctx.Err() != nil {
		delete(c.entries, cwd)
	}
	close(entry.ready)
	entry.ready = nil
	c.mu.Unlock()
	return info
}

func readRepositoryInfo(ctx context.Context, cwd string) repositoryInfo {
	branch, err := exec.CommandContext(ctx, "git", "-C", cwd, "rev-parse", "--abbrev-ref", "HEAD").Output()
	if err != nil {
		return repositoryInfo{}
	}
	info := repositoryInfo{branch: strings.TrimSpace(string(branch))}
	common, err := exec.CommandContext(ctx, "git", "-C", cwd, "rev-parse", "--path-format=absolute", "--git-common-dir").Output()
	if err != nil {
		return info
	}
	info.name = filepath.Base(filepath.Dir(strings.TrimSpace(string(common))))
	return info
}
