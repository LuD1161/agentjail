package main

import (
	"context"
	"net"
	"sort"
	"sync"
	"time"
)

// dnsResolveConcurrency bounds how many hostnames are looked up in parallel.
// A batch of allowed hosts is typically small (a handful of essential hosts
// plus whatever the user has added), but a slow/unreachable DNS name must
// never be allowed to serialize the whole launch (see ADR 0034 -- this
// resolver is a tag-free shared contract; only the darwin backend currently
// calls it, since Landlock on Linux enforces network access by port, not by
// resolved IP).
const dnsResolveConcurrency = 8

// dnsPerLookupTimeout bounds a single net.LookupHost-equivalent call. A
// hostname that hangs (e.g. an unreachable or misconfigured resolver) is
// treated the same as a resolution failure: skipped, launch continues.
const dnsPerLookupTimeout = 2 * time.Second

// dnsBatchTimeout bounds the entire batch of lookups, regardless of how many
// hosts are in flight. This is the hard cap on how long host resolution can
// add to shield startup.
const dnsBatchTimeout = 5 * time.Second

// lookupHostFunc matches the shape of (*net.Resolver).LookupHost, factored
// out so tests can inject a fake resolver instead of hitting real DNS.
type lookupHostFunc func(ctx context.Context, host string) ([]string, error)

// resolveHostsToIPs resolves each host in hosts to its IP addresses,
// concurrently, with a per-lookup timeout and an overall batch deadline.
// Hosts that fail to resolve or time out are skipped -- this function never
// returns an error; a host contributing zero IPs is fail-open for that host
// only (the hostname itself still reaches netproxy's allowlist via a
// separate path; this resolver output is informational/best-effort, used to
// pre-populate IP literals in the generated sandbox profile).
//
// The returned slice is deduplicated and sorted, so profile generation stays
// deterministic across runs regardless of lookup completion order.
//
// onResolved, if non-nil, is called once per (host, ip) pair as it is
// discovered -- callers use this for logging without needing to duplicate
// the host->IP association after the fact. It may be called concurrently
// from multiple goroutines.
func resolveHostsToIPs(hosts []string, lookup lookupHostFunc, onResolved func(host, ip string)) []string {
	if len(hosts) == 0 || lookup == nil {
		return nil
	}

	batchCtx, cancel := context.WithTimeout(context.Background(), dnsBatchTimeout)
	defer cancel()

	sem := make(chan struct{}, dnsResolveConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := make(map[string]struct{})
	var ips []string

	for _, host := range hosts {
		host := host
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			lookupCtx, lookupCancel := context.WithTimeout(batchCtx, dnsPerLookupTimeout)
			defer lookupCancel()

			addrs, err := lookup(lookupCtx, host)
			if err != nil {
				return
			}

			mu.Lock()
			defer mu.Unlock()
			for _, addr := range addrs {
				ip := net.ParseIP(addr)
				if ip == nil || ip.IsLoopback() {
					continue
				}
				ipStr := ip.String()
				if _, dup := seen[ipStr]; dup {
					continue
				}
				seen[ipStr] = struct{}{}
				ips = append(ips, ipStr)
				if onResolved != nil {
					onResolved(host, ipStr)
				}
			}
		}()
	}

	// Wait for either all lookups to finish or the batch deadline -- whichever
	// comes first. Goroutines that are still running past the deadline will
	// have their lookupCtx canceled (derived from batchCtx) and exit shortly
	// after; we do not block the caller waiting for them.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-batchCtx.Done():
	}

	mu.Lock()
	defer mu.Unlock()
	sort.Strings(ips)
	return ips
}
