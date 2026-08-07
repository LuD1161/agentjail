package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/wire"
)

// Guards the state -> badge mapping, including the AGE-212 state (shield up,
// daemon down) that ADR 0064-statusline-always-attests rendered as "secured".
func TestProtectionBadge(t *testing.T) {
	tests := []struct {
		name       string
		state      protection
		wantSubstr []string
		denySubstr []string
	}{
		{
			name:       "fully secured",
			state:      fullySecured,
			wantSubstr: []string{"secured by", "agentjail"},
			denySubstr: []string{"UNSECURED", "POLICY OFF"},
		},
		{
			name:       "shielded but daemon down",
			state:      shieldedPolicyDown,
			wantSubstr: []string{"POLICY OFF", "shield only", "agentjail"},
			denySubstr: []string{"secured by"},
		},
		{
			name:       "unshielded",
			state:      unshielded,
			wantSubstr: []string{"UNSECURED", "agentjail"},
			denySubstr: []string{"secured by", "POLICY OFF"},
		},
		{
			name:       "unknown state never claims secured",
			state:      protection(99),
			wantSubstr: []string{"UNSECURED"},
			denySubstr: []string{"secured by", "POLICY OFF"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.state.badge()
			if got == "" {
				t.Fatal("badge must never be empty")
			}
			for _, s := range tt.wantSubstr {
				if !strings.Contains(got, s) {
					t.Errorf("badge %q missing %q", got, s)
				}
			}
			for _, s := range tt.denySubstr {
				if strings.Contains(got, s) {
					t.Errorf("badge %q must not contain %q", got, s)
				}
			}
		})
	}
}

// Guards that liveness is consulted only when the shield is on, and that a dead
// daemon downgrades the state instead of being ignored.
func TestDetectProtection(t *testing.T) {
	tests := []struct {
		name       string
		shielded   bool
		daemonUp   bool
		want       protection
		wantProbed bool
	}{
		{"shield on, daemon up", true, true, fullySecured, true},
		{"shield on, daemon down (AGE-212)", true, false, shieldedPolicyDown, true},
		{"shield off, daemon up", false, true, unshielded, false},
		{"shield off, daemon down", false, false, unshielded, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probed := false
			got := detectProtection(tt.shielded, func() bool {
				probed = true
				return tt.daemonUp
			})
			if got != tt.want {
				t.Errorf("detectProtection(%v) = %v, want %v", tt.shielded, got, tt.want)
			}
			if probed != tt.wantProbed {
				t.Errorf("probed = %v, want %v", probed, tt.wantProbed)
			}
		})
	}
}

// Guards the three dial outcomes against a real socket: only a live listener
// counts. See ADR 0085-statusline-attests-daemon.
func TestDaemonAlive(t *testing.T) {
	dir := t.TempDir()

	// A healthy daemon: answers ControlOpPing.
	live := filepath.Join(dir, "live.sock")
	ln, err := net.Listen("unix", live)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var req wire.ControlRequest
				if err := json.NewDecoder(c).Decode(&req); err != nil {
					return
				}
				_ = json.NewEncoder(c).Encode(wire.ControlResponse{OK: true})
			}(c)
		}
	}()

	// A WEDGED daemon: listening, never accepts. The kernel completes the
	// AF_UNIX handshake into the accept backlog, so a bare connect() succeeds
	// and would badge this as secured — it enforces nothing.
	wedged := filepath.Join(dir, "wedged.sock")
	wedgedLn, err := net.Listen("unix", wedged)
	if err != nil {
		t.Fatalf("listen wedged: %v", err)
	}
	defer wedgedLn.Close()

	// A socket file with no listener behind it: what a crashed daemon leaves.
	stale := filepath.Join(dir, "stale.sock")
	staleLn, err := net.Listen("unix", stale)
	if err != nil {
		t.Fatalf("listen stale: %v", err)
	}
	if err := staleLn.Close(); err != nil {
		t.Fatalf("close stale: %v", err)
	}
	if _, err := os.Stat(stale); err != nil {
		f, err := os.Create(stale)
		if err != nil {
			t.Fatalf("recreate stale: %v", err)
		}
		f.Close()
	}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"daemon answers ping", live, true},
		{"daemon wedged: listening, never accepts", wedged, false},
		{"stale socket file, no listener", stale, false},
		{"missing socket", filepath.Join(dir, "absent.sock"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := daemonAlive(tt.path); got != tt.want {
				t.Errorf("daemonAlive(%s) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestShieldBadge_OnlyExactValueCounts(t *testing.T) {
	for _, v := range []string{"", "0", "true", "yes", "2"} {
		t.Run("value_"+v, func(t *testing.T) {
			t.Setenv("AGENTJAIL_SHIELDED", v)
			got := shieldBadge()
			if got == "" {
				t.Fatal("badge must never be empty")
			}
			if !strings.Contains(got, "UNSECURED") {
				t.Errorf("AGENTJAIL_SHIELDED=%q must not read as shielded, got %q", v, got)
			}
		})
	}
}

func TestRunChainedStatuslinePreservesShellCommand(t *testing.T) {
	got := runChainedStatusline(`read value; printf 'prefix:%s' "$value" | tr a-z A-Z`, []byte("quoted value\n"))
	if got != "PREFIX:QUOTED VALUE" {
		t.Fatalf("chained status line = %q", got)
	}
}

func TestRunChainedStatuslineFailureIsSilent(t *testing.T) {
	if got := runChainedStatusline("exit 7", nil); got != "" {
		t.Fatalf("failed chained status line returned %q", got)
	}
}

func TestLocalUILink(t *testing.T) {
	tests := []struct {
		name      string
		shielded  bool
		reachable bool
		wantLink  bool
	}{
		{name: "shielded and reachable", shielded: true, reachable: true, wantLink: true},
		{name: "shielded but unavailable", shielded: true},
		{name: "unshielded", reachable: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := localUILink(tt.shielded, func() bool { return tt.reachable })
			if (got != "") != tt.wantLink {
				t.Fatalf("link = %q, wantLink %v", got, tt.wantLink)
			}
			if tt.wantLink && (!strings.Contains(got, "📊 UI") || !strings.Contains(got, "127.0.0.1:9101")) {
				t.Fatalf("link = %q, missing label or address", got)
			}
		})
	}
}
