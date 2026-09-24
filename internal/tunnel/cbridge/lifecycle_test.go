package main

import (
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"net/netip"
	"testing"
	"time"
)

func TestWireGuardDeviceClosesWithoutPeerTraffic(t *testing.T) {
	for i := 0; i < 3; i++ {
		tun, err := newNetTUN(netip.MustParseAddr("10.78.0.2"), netip.Addr{}, 1420)
		if err != nil {
			t.Fatal(err)
		}
		dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
		done := make(chan struct{})
		go func() { dev.Close(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("device close stalled")
		}
	}
}
