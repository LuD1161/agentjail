// Package dnsvip maps hostnames to virtual IPs (VIPs) inside a WireGuard
// network namespace so the gateway can attribute non-SNI connections (SSH,
// Postgres, Redis, MongoDB) back to the intended hostname.
package dnsvip

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
)

// IPv4 pool: 10.78.0.1 – 10.78.255.254  (skip .0 network, .255.255 broadcast)
// IPv6 pool: fd78::1   – fd78::ffff
const (
	ipv4PoolSize = 65534 // 256*256 - 2
	ipv6PoolSize = 65535 // 0x0001 – 0xffff
)

var (
	// ErrPoolExhausted is returned when no more VIPs are available.
	ErrPoolExhausted = errors.New("dnsvip: VIP pool exhausted")

	ipv4Base = net.IP{10, 78, 0, 0}  // network address (skipped)
	ipv6Base = net.ParseIP("fd78::") // prefix
)

// entry holds both address families for a single hostname.
type entry struct {
	v4 net.IP
	v6 net.IP
}

// Registry maps hostnames to virtual IPs and back.
type Registry struct {
	mu sync.RWMutex

	// Bidirectional maps.
	byHost map[string]*entry
	byV4   map[[4]byte]string
	byV6   map[[16]byte]string

	// Sequential counters (next offset to allocate). Offset 0 is skipped
	// (network address for v4, zero for v6).
	nextV4 uint32 // 1-based offset into the /16
	nextV6 uint32

	// Free-lists: offsets returned by Free that can be reused.
	freeV4 []uint32
	freeV6 []uint32
}

// NewRegistry creates an empty VIP registry.
func NewRegistry() *Registry {
	return &Registry{
		byHost: make(map[string]*entry),
		byV4:   make(map[[4]byte]string),
		byV6:   make(map[[16]byte]string),
		nextV4: 1, // first usable offset
		nextV6: 1,
	}
}

// offsetToV4 converts a 1-based offset to a 10.78.x.y address.
func offsetToV4(off uint32) net.IP {
	base := binary.BigEndian.Uint32(ipv4Base.To4())
	val := base + off
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, val)
	return ip
}

// offsetToV6 converts a 1-based offset to a fd78::x address.
func offsetToV6(off uint32) net.IP {
	ip := make(net.IP, 16)
	copy(ip, ipv6Base.To16())
	binary.BigEndian.PutUint16(ip[14:], uint16(off))
	return ip
}

func v4Key(ip net.IP) [4]byte {
	var k [4]byte
	copy(k[:], ip.To4())
	return k
}

func v6Key(ip net.IP) [16]byte {
	var k [16]byte
	copy(k[:], ip.To16())
	return k
}

// allocV4 returns the next available IPv4 offset.
func (r *Registry) allocV4() (uint32, error) {
	if len(r.freeV4) > 0 {
		off := r.freeV4[len(r.freeV4)-1]
		r.freeV4 = r.freeV4[:len(r.freeV4)-1]
		return off, nil
	}
	if r.nextV4 > uint32(ipv4PoolSize) {
		return 0, ErrPoolExhausted
	}
	off := r.nextV4
	r.nextV4++
	return off, nil
}

// allocV6 returns the next available IPv6 offset.
func (r *Registry) allocV6() (uint32, error) {
	if len(r.freeV6) > 0 {
		off := r.freeV6[len(r.freeV6)-1]
		r.freeV6 = r.freeV6[:len(r.freeV6)-1]
		return off, nil
	}
	if r.nextV6 > uint32(ipv6PoolSize) {
		return 0, ErrPoolExhausted
	}
	off := r.nextV6
	r.nextV6++
	return off, nil
}

// Allocate returns the IPv4 VIP for a hostname, allocating new addresses if the
// hostname has not been seen before.
func (r *Registry) Allocate(hostname string) (net.IP, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if e, ok := r.byHost[hostname]; ok {
		return dupIP(e.v4), nil
	}

	return r.allocBoth(hostname, false)
}

// AllocateV6 returns the IPv6 VIP for a hostname, allocating if needed.
func (r *Registry) AllocateV6(hostname string) (net.IP, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if e, ok := r.byHost[hostname]; ok {
		return dupIP(e.v6), nil
	}

	return r.allocBoth(hostname, true)
}

// allocBoth allocates both v4 and v6 addresses for a hostname.
// Must be called with r.mu held.
func (r *Registry) allocBoth(hostname string, returnV6 bool) (net.IP, error) {
	off4, err := r.allocV4()
	if err != nil {
		return nil, err
	}
	off6, err := r.allocV6()
	if err != nil {
		// Put v4 offset back.
		r.freeV4 = append(r.freeV4, off4)
		return nil, err
	}

	v4 := offsetToV4(off4)
	v6 := offsetToV6(off6)

	e := &entry{v4: v4, v6: v6}
	r.byHost[hostname] = e
	r.byV4[v4Key(v4)] = hostname
	r.byV6[v6Key(v6)] = hostname

	if returnV6 {
		return dupIP(v6), nil
	}
	return dupIP(v4), nil
}

// Lookup returns the hostname associated with a VIP (IPv4 or IPv6).
func (r *Registry) Lookup(vip net.IP) (hostname string, ok bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if v4 := vip.To4(); v4 != nil {
		hostname, ok = r.byV4[v4Key(v4)]
		return
	}
	hostname, ok = r.byV6[v6Key(vip)]
	return
}

// Free returns a hostname's VIPs to the pool for reuse.
func (r *Registry) Free(hostname string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	e, ok := r.byHost[hostname]
	if !ok {
		return
	}

	// Recover offsets from the IPs.
	v4val := binary.BigEndian.Uint32(e.v4.To4())
	baseVal := binary.BigEndian.Uint32(ipv4Base.To4())
	r.freeV4 = append(r.freeV4, v4val-baseVal)

	v6off := binary.BigEndian.Uint16(e.v6.To16()[14:])
	r.freeV6 = append(r.freeV6, uint32(v6off))

	delete(r.byV4, v4Key(e.v4))
	delete(r.byV6, v6Key(e.v6))
	delete(r.byHost, hostname)
}

// Stats returns allocation statistics for the IPv4 pool.
func (r *Registry) Stats() (allocated, available int) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	allocated = len(r.byHost)
	available = ipv4PoolSize - allocated
	return
}

func dupIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}
