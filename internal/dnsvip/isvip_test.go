package dnsvip

import (
	"net"
	"testing"
)

func TestIsVIP(t *testing.T) {
	r := NewRegistry()
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.78.0.0", true},     // network address, still in pool CIDR
		{"10.78.4.9", true},     // inside 10.78.0.0/16
		{"10.78.255.255", true}, // broadcast, still in CIDR
		{"10.79.0.1", false},    // adjacent /16, outside
		{"10.0.0.1", false},     // unrelated private
		{"93.184.216.34", false},
		{"fd78::1", true},    // inside fd78::/112
		{"fd78::ffff", true}, // top of the offset space
		{"fd78::1:0", false}, // one past the /112
		{"fd79::1", false},   // adjacent v6 prefix
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("bad test IP %q", c.ip)
		}
		if got := r.IsVIP(ip); got != c.want {
			t.Errorf("IsVIP(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
	if r.IsVIP(nil) {
		t.Error("IsVIP(nil) = true, want false")
	}
}

// An allocated VIP is reported by both IsVIP (CIDR) and Lookup (allocation).
func TestIsVIP_MatchesAllocated(t *testing.T) {
	r := NewRegistry()
	v4, err := r.Allocate("db.example.com")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if !r.IsVIP(v4) {
		t.Errorf("allocated VIP %s not reported by IsVIP", v4)
	}
	if _, ok := r.Lookup(v4); !ok {
		t.Errorf("allocated VIP %s not found by Lookup", v4)
	}
}
