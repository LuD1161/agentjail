import NetworkExtension
import os.log

// C declarations for the Go static library functions (libagentjail_tunnel.a).
// The bridge header exposes the full libagentjail_tunnel.h; these are the three
// entry points the extension actually calls.
@_silgen_name("AgentjailTunnelStart")
func AgentjailTunnelStart() -> Int32

@_silgen_name("AgentjailTunnelStop")
func AgentjailTunnelStop()

@_silgen_name("AgentjailTunnelHandlePacket")
func AgentjailTunnelHandlePacket(_ data: UnsafePointer<UInt8>, _ length: Int32)

/// Reads one outbound packet that the Go gateway has forwarded back.
/// Returns the number of bytes written into `buf`, or -1 when there are no
/// packets ready (non-blocking).  The caller owns `buf`.
@_silgen_name("AgentjailTunnelReadPacket")
func AgentjailTunnelReadPacket(_ buf: UnsafeMutablePointer<UInt8>, _ maxLength: Int32) -> Int32

// MARK: - Provider

class PacketTunnelProvider: NEPacketTunnelProvider {

    private let log = OSLog(subsystem: "com.blinkerlm.agentjail.tunnel", category: "tunnel")

    /// Virtual tunnel IP range used by the agent jail network.
    /// The Go gateway listens on the "server" side (.1) and the system
    /// extension presents itself as the "client" side (.2).
    private static let tunnelServerAddress = "10.78.0.1"
    private static let tunnelClientAddress = "10.78.0.2"
    private static let tunnelSubnetMask    = "255.255.255.0"

    /// Maximum Transfer Unit forwarded through the virtual interface.
    private static let mtu = 1500

    // MARK: Start

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        os_log("startTunnel called", log: log, type: .info)

        // 1. Start the Go gateway.
        let rc = AgentjailTunnelStart()
        guard rc == 0 else {
            os_log("AgentjailTunnelStart failed: %d", log: log, type: .error, rc)
            completionHandler(TunnelError.startFailed(rc))
            return
        }
        os_log("Go gateway started (rc=%d)", log: log, type: .info, rc)

        // 2. Build tunnel network settings.
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: Self.tunnelServerAddress)
        settings.mtu = NSNumber(value: Self.mtu)

        // IPv4: route all traffic through the virtual interface.
        let ipv4 = NEIPv4Settings(addresses: [Self.tunnelClientAddress],
                                  subnetMasks: [Self.tunnelSubnetMask])
        ipv4.includedRoutes = [NEIPv4Route.default()]   // 0.0.0.0/0
        settings.ipv4Settings = ipv4

        // DNS: point everything at the Go DNS-VIP so queries can be inspected.
        let dns = NEDNSSettings(servers: [Self.tunnelServerAddress])
        dns.matchDomains = [""]   // empty string = catch-all (all domains)
        settings.dnsSettings = dns

        // 3. Activate the settings with the system.
        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                os_log("setTunnelNetworkSettings failed: %{public}@",
                       log: self.log, type: .error, error.localizedDescription)
                completionHandler(error)
                return
            }
            os_log("Tunnel network settings applied", log: self.log, type: .info)

            // 4. Begin bidirectional packet forwarding.
            self.startPacketForwarding()
            completionHandler(nil)
        }
    }

    // MARK: Stop

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        os_log("stopTunnel: reason=%d", log: log, type: .info, reason.rawValue)
        AgentjailTunnelStop()
        completionHandler()
    }

    // MARK: Packet forwarding

    /// Starts two concurrent loops:
    ///   - **inbound**:  read packets arriving from the OS (agent traffic) and
    ///     push them into the Go gateway via `AgentjailTunnelHandlePacket`.
    ///   - **outbound**: poll the Go gateway for processed/forwarded packets
    ///     and inject them back into the OS network stack via `packetFlow`.
    private func startPacketForwarding() {
        readFromPacketFlow()
        writeToPacketFlow()
    }

    /// Reads packets from the virtual interface and hands them to Go.
    private func readFromPacketFlow() {
        packetFlow.readPacketObjects { [weak self] packets in
            guard let self = self else { return }
            for packet in packets {
                let data = packet.data
                data.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
                    guard let base = ptr.baseAddress else { return }
                    AgentjailTunnelHandlePacket(
                        base.assumingMemoryBound(to: UInt8.self),
                        Int32(data.count)
                    )
                }
            }
            // Recurse: keep reading until the provider is stopped.
            self.readFromPacketFlow()
        }
    }

    /// Polls the Go gateway for outbound packets and writes them to the OS.
    ///
    /// This runs on a dedicated DispatchQueue so it does not block the main
    /// extension thread.  It sleeps briefly when there are no packets to avoid
    /// busy-spinning.
    private func writeToPacketFlow() {
        let q = DispatchQueue(label: "com.blinkerlm.agentjail.tunnel.write", qos: .userInitiated)
        let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: Self.mtu)

        q.async { [weak self] in
            guard let self = self else {
                buf.deallocate()
                return
            }
            while true {
                let n = AgentjailTunnelReadPacket(buf, Int32(Self.mtu))
                if n > 0 {
                    let data = Data(bytes: buf, count: Int(n))
                    // AF_INET (IPv4) = 2; supply protocol family so the OS
                    // knows how to interpret the raw IP packet.
                    self.packetFlow.writePackets([data], withProtocols: [AF_INET as NSNumber])
                } else {
                    // No packet ready — yield briefly to avoid 100% CPU.
                    usleep(500)
                }
            }
        }
    }
}

// MARK: - Errors

enum TunnelError: LocalizedError {
    case startFailed(Int32)

    var errorDescription: String? {
        switch self {
        case .startFailed(let code):
            return "AgentjailTunnelStart returned error code \(code)"
        }
    }
}
