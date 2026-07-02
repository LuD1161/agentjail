//go:build darwin

package main

import "fmt"

// tunnelSeatbeltRules returns SBPL rules that allow the agent to communicate
// with the local WireGuard gateway (UDP) and DNS-VIP server (UDP), while
// blocking all other outbound network access.
func tunnelSeatbeltRules(gatewayPort, dnsPort int) string {
	return fmt.Sprintf(`
;; Allow WireGuard gateway (UDP)
(allow network-outbound
  (remote udp (local ip "localhost:%d")))

;; Allow DNS-VIP server (UDP)
(allow network-outbound
  (remote udp (local ip "localhost:%d")))
`, gatewayPort, dnsPort)
}
