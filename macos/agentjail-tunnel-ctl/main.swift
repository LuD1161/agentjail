// agentjail-tunnel-ctl — CLI helper called by agentjail-shield to manage the
// NEPacketTunnelProvider system extension.
//
// Usage:
//   agentjail-tunnel-ctl start   — load and start the VPN tunnel
//   agentjail-tunnel-ctl stop    — stop and unload the VPN tunnel
//   agentjail-tunnel-ctl status  — print "active" or "inactive" to stdout
//
// The tool must be run as the user that owns the Network Extension (i.e. not
// as root).  It exits 0 on success and non-zero on error.
//
// Build (from this directory):
//   swiftc -O -o agentjail-tunnel-ctl main.swift \
//       -framework Foundation -framework NetworkExtension

import Foundation
import NetworkExtension

// MARK: - Configuration

/// Bundle identifier of the NEPacketTunnelProvider app extension.
/// Must match the bundle ID in the extension's Info.plist.
let tunnelBundleID = "com.agentjail.tunnel"

/// Human-readable VPN service name shown in System Settings > VPN.
let tunnelServiceName = "AgentJail Shield"

// MARK: - Helpers

/// Load (or create) the NETunnelProviderManager for the agentjail extension.
/// Calls `completion` on the main queue.
func loadManager(completion: @escaping (NETunnelProviderManager?, Error?) -> Void) {
    NETunnelProviderManager.loadAllFromPreferences { managers, error in
        if let error = error {
            completion(nil, error)
            return
        }
        // Reuse an existing manager for our bundle ID if one already exists.
        let existing = managers?.first {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?
                .providerBundleIdentifier == tunnelBundleID
        }
        completion(existing, nil)
    }
}

/// Create and save a new NETunnelProviderManager for the agentjail extension.
func createManager(completion: @escaping (NETunnelProviderManager?, Error?) -> Void) {
    let manager = NETunnelProviderManager()
    manager.localizedDescription = tunnelServiceName

    let proto = NETunnelProviderProtocol()
    proto.providerBundleIdentifier = tunnelBundleID
    proto.serverAddress = "agentjail-local"
    manager.protocolConfiguration = proto

    manager.isEnabled = true
    manager.saveToPreferences { error in
        if let error = error {
            completion(nil, error)
            return
        }
        // Reload so the OS-assigned identifiers are populated.
        manager.loadFromPreferences { error in
            completion(error == nil ? manager : nil, error)
        }
    }
}

// MARK: - Commands

func cmdStart() {
    let sema = DispatchSemaphore(value: 0)
    var exitCode: Int32 = 0

    loadManager { existing, error in
        if let error = error {
            fputs("agentjail-tunnel-ctl: loadAllFromPreferences failed: \(error.localizedDescription)\n", stderr)
            exitCode = 1
            sema.signal()
            return
        }

        func startWith(_ manager: NETunnelProviderManager) {
            manager.isEnabled = true
            manager.saveToPreferences { saveError in
                if let saveError = saveError {
                    fputs("agentjail-tunnel-ctl: saveToPreferences failed: \(saveError.localizedDescription)\n", stderr)
                    exitCode = 1
                    sema.signal()
                    return
                }
                do {
                    try manager.connection.startVPNTunnel()
                    print("agentjail-tunnel-ctl: tunnel start requested")
                } catch {
                    fputs("agentjail-tunnel-ctl: startVPNTunnel failed: \(error.localizedDescription)\n", stderr)
                    exitCode = 1
                }
                sema.signal()
            }
        }

        if let manager = existing {
            startWith(manager)
        } else {
            createManager { newManager, createError in
                if let createError = createError {
                    fputs("agentjail-tunnel-ctl: createManager failed: \(createError.localizedDescription)\n", stderr)
                    exitCode = 1
                    sema.signal()
                    return
                }
                startWith(newManager!)
            }
        }
    }

    sema.wait()
    exit(exitCode)
}

func cmdStop() {
    let sema = DispatchSemaphore(value: 0)
    var exitCode: Int32 = 0

    loadManager { manager, error in
        if let error = error {
            fputs("agentjail-tunnel-ctl: loadAllFromPreferences failed: \(error.localizedDescription)\n", stderr)
            exitCode = 1
            sema.signal()
            return
        }
        guard let manager = manager else {
            // Nothing to stop — treat as success.
            print("agentjail-tunnel-ctl: no tunnel found, nothing to stop")
            sema.signal()
            return
        }
        manager.connection.stopVPNTunnel()
        print("agentjail-tunnel-ctl: tunnel stop requested")
        sema.signal()
    }

    sema.wait()
    exit(exitCode)
}

func cmdStatus() {
    let sema = DispatchSemaphore(value: 0)
    var exitCode: Int32 = 0

    loadManager { manager, error in
        if let error = error {
            fputs("agentjail-tunnel-ctl: loadAllFromPreferences failed: \(error.localizedDescription)\n", stderr)
            exitCode = 1
            sema.signal()
            return
        }
        guard let manager = manager else {
            print("inactive")
            sema.signal()
            return
        }
        switch manager.connection.status {
        case .connected:
            print("active")
        case .connecting, .reasserting:
            print("connecting")
        case .disconnecting:
            print("disconnecting")
        default:
            print("inactive")
        }
        sema.signal()
    }

    sema.wait()
    exit(exitCode)
}

// MARK: - Entry point

let args = CommandLine.arguments
guard args.count >= 2 else {
    fputs("usage: agentjail-tunnel-ctl start|stop|status\n", stderr)
    exit(1)
}

switch args[1] {
case "start":
    cmdStart()
case "stop":
    cmdStop()
case "status":
    cmdStatus()
default:
    fputs("agentjail-tunnel-ctl: unknown command: \(args[1])\n", stderr)
    fputs("usage: agentjail-tunnel-ctl start|stop|status\n", stderr)
    exit(1)
}

// Keep the run-loop alive for the async NetworkExtension callbacks above.
RunLoop.main.run()
