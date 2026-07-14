<<<<<<< HEAD
import Foundation
import NetworkExtension
import os.log

private let log = OSLog(subsystem: "com.blinkerlm.agentjail.tunnel", category: "app")

// MARK: - TunnelManager

/// Manages the lifecycle of the AgentJail packet-tunnel VPN configuration.
///
/// The host app (or agentjail-shield) calls `activate` / `deactivate` to
/// start and stop the NEPacketTunnelProvider system extension.  State is
/// persisted in System Preferences via `NETunnelProviderManager`.
class TunnelManager {

    /// Bundle identifier of the TunnelExtension target.
    private static let extensionBundleID = "com.blinkerlm.agentjail.tunnel.extension"

    /// Human-readable name shown in System Settings > VPN.
    private static let localizedDescription = "AgentJail"

    // MARK: Activate

    /// Loads (or creates) the VPN configuration and starts the tunnel.
    ///
    /// - Parameter completion: Called on the main queue with `nil` on success,
    ///   or an `Error` if loading or starting the tunnel fails.
    static func activate(completion: @escaping (Error?) -> Void) {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if let error = error {
                os_log("loadAllFromPreferences failed: %{public}@",
                       log: log, type: .error, error.localizedDescription)
                DispatchQueue.main.async { completion(error) }
                return
            }

            // Find an existing AgentJail configuration or create a new one.
            let manager = managers?.first(where: { mgr in
                (mgr.protocolConfiguration as? NETunnelProviderProtocol)?
                    .providerBundleIdentifier == extensionBundleID
            }) ?? NETunnelProviderManager()

            // (Re-)configure in case this is the first run.
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = extensionBundleID
            proto.serverAddress = "AgentJail"   // cosmetic; actual routing is done in the extension
            manager.protocolConfiguration = proto
            manager.localizedDescription = localizedDescription
            manager.isEnabled = true

            manager.saveToPreferences { saveError in
                if let saveError = saveError {
                    os_log("saveToPreferences failed: %{public}@",
                           log: log, type: .error, saveError.localizedDescription)
                    DispatchQueue.main.async { completion(saveError) }
                    return
                }

                // Reload after save — required before starting the tunnel.
                manager.loadFromPreferences { loadError in
                    if let loadError = loadError {
                        os_log("loadFromPreferences (post-save) failed: %{public}@",
                               log: log, type: .error, loadError.localizedDescription)
                        DispatchQueue.main.async { completion(loadError) }
                        return
                    }

                    do {
                        try manager.connection.startVPNTunnel()
                        os_log("Tunnel start requested", log: log, type: .info)
                        DispatchQueue.main.async { completion(nil) }
                    } catch {
                        os_log("startVPNTunnel failed: %{public}@",
                               log: log, type: .error, error.localizedDescription)
                        DispatchQueue.main.async { completion(error) }
                    }
                }
            }
        }
    }

    // MARK: Deactivate

    /// Stops the running tunnel (if any).
    static func deactivate() {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if let error = error {
                os_log("deactivate – loadAllFromPreferences failed: %{public}@",
                       log: log, type: .error, error.localizedDescription)
                return
            }
            managers?
                .filter { ($0.protocolConfiguration as? NETunnelProviderProtocol)?
                    .providerBundleIdentifier == extensionBundleID }
                .forEach { mgr in
                    mgr.connection.stopVPNTunnel()
                    os_log("Tunnel stop requested", log: log, type: .info)
                }
        }
    }

    // MARK: Status observation

    /// Registers a block that fires whenever the tunnel connection status changes.
    ///
    /// - Returns: An opaque observer token; retain it for the lifetime of your
    ///   interest.  Passing it to `NotificationCenter.default.removeObserver`
    ///   cancels the subscription.
    @discardableResult
    static func observeStatus(_ handler: @escaping (NEVPNStatus) -> Void) -> NSObjectProtocol {
        NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { notification in
            guard let connection = notification.object as? NEVPNConnection else { return }
            handler(connection.status)
        }
    }
}

// MARK: - Entry point

// When compiled as a standalone CLI shim (for integration with agentjail-shield),
// honour two subcommands: "activate" and "deactivate".
// In a full macOS app the TunnelManager methods would be called by the app delegate
// in response to UI or IPC events.

let args = CommandLine.arguments
guard args.count > 1 else {
    fputs("Usage: agentjail-tunnel <activate|deactivate>\n", stderr)
    exit(1)
}

let sema = DispatchSemaphore(value: 0)

switch args[1] {
case "activate":
    TunnelManager.activate { error in
        if let error = error {
            fputs("Error: \(error.localizedDescription)\n", stderr)
            exit(1)
        }
        print("AgentJail tunnel activated.")
        sema.signal()
    }
    sema.wait()

case "deactivate":
    TunnelManager.deactivate()
    print("AgentJail tunnel deactivation requested.")

default:
    fputs("Unknown command: \(args[1])\n", stderr)
=======
// Host app — activates the system extension and saves a transparent-proxy
// configuration into NETransparentProxyManager.  The extension does the
// per-process filtering itself by walking each flow's audit-token chain
// back to `com.blinkerlm.agentjail.app`, so we don't need NEAppRule /
// matchTools here (which on macOS require an MDM-pushed appmapping
// payload).
//
// CLI invocation:
//   AgentjailTunnel install             — activate sysext + save proxy profile
//   AgentjailTunnel start <wg-conf>     — load WG conf, start proxy
//   AgentjailTunnel stop                — stop proxy
//   AgentjailTunnel run -- <cmd> [args] — fork+exec cmd as child of AgentjailTunnel
//                                         so the extension's PPID-walk picks it up
//   AgentjailTunnel wipe                — remove all proxy configs (cleanup)
import AppKit
import Darwin
import Foundation
import NetworkExtension
import SystemExtensions

let extBundleID = "com.blinkerlm.agentjail.app.extension"
let parentBundleID = "com.blinkerlm.agentjail.app"
let proxyProfileName = "agentjail"

// Routine setup progress is noise during a normal `agentjail run`, so
// it's silenced unless AGENTJAIL_DEBUG is set.  Errors (fail / stderr
// writes) and action-required prompts (system-extension approval) always
// print regardless.
let debugEnabled: Bool = {
    let v = ProcessInfo.processInfo.environment["AGENTJAIL_DEBUG"] ?? ""
    return v != "" && v != "0"
}()

func debugLog(_ msg: String) {
    if debugEnabled { print(msg) }
}

func usage() -> Never {
    FileHandle.standardError.write(Data("usage: AgentjailTunnel {install|start <wg-conf>|stop|run -- <cmd> [args...]|wipe}\n".utf8))
    exit(2)
}

let cmd = CommandLine.arguments.count >= 2 ? CommandLine.arguments[1] : "install"

switch cmd {
case "install": installSystemExtension()
case "start":
    guard CommandLine.arguments.count >= 3 else { usage() }
    startProxy(confPath: CommandLine.arguments[2])
case "stop": stopProxy()
case "run": runWrapped()    // synchronous; calls exit() -- never reaches runloop
case "wipe": wipeAllConfigs()
default: usage()
}

NSApplication.shared.run()

// `AgentjailTunnel run -- <cmd>` forks + execs cmd.  Stays foreground so
// the extension's PPID walk finds AgentjailTunnel's signing identity in
// the cmd's parent chain -> flows from cmd (and its descendants) get
// tunneled.  Exec'ing in-place would replace our process with cmd's
// signing identity, breaking the match.
func runWrapped() {
    let argv = Array(CommandLine.arguments.dropFirst(2)).filter { $0 != "--" }
    if argv.isEmpty { usage() }

    // IPC handshake -- synchronously register our PID with the
    // extension's session listener before posix_spawn'ing the child.
    // The handshake guarantees the ext has the PID in its registry
    // before the child's first flow can fire.
    sessionIPC("register \(getpid())")
    defer { sessionIPC("unregister \(getpid())") }

    var pid: pid_t = 0
    let cargs = argv.map { strdup($0) } + [nil]
    var actions: posix_spawn_file_actions_t? = nil
    posix_spawn_file_actions_init(&actions)
    let rc = posix_spawnp(&pid, argv[0], &actions, nil, cargs, environ)
    posix_spawn_file_actions_destroy(&actions)
    cargs.compactMap { $0 }.forEach { free($0) }
    if rc != 0 {
        FileHandle.standardError.write(Data("posix_spawnp \(argv[0]): \(String(cString: strerror(rc)))\n".utf8))
        exit(127)
    }
    var status: Int32 = 0
    waitpid(pid, &status, 0)
    exit((status >> 8) & 0xff)
}

// sessionIPC dials /tmp/agentjail.sock and sends a single newline-
// framed verb.  Best-effort: failures (sysext not yet running, sandbox
// quirk) just no-op.  The wrapped child won't be tunneled in that
// case, but blocking the user's command on extension plumbing is
// worse than passthrough.
func sessionIPC(_ msg: String) {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    if fd < 0 { return }
    defer { Darwin.close(fd) }
    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    let bytes = "/tmp/agentjail.sock".utf8CString
    withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
        ptr.withMemoryRebound(to: CChar.self, capacity: bytes.count) { p in
            for (i, b) in bytes.enumerated() {
                p.advanced(by: i).pointee = b
            }
        }
    }
    let len = socklen_t(MemoryLayout<sockaddr_un>.size)
    let rc = withUnsafePointer(to: &addr) { ap -> Int32 in
        ap.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
            Darwin.connect(fd, sa, len)
        }
    }
    if rc != 0 { return }
    var line = msg + "\n"
    _ = line.withUTF8 { buf in
        Darwin.write(fd, buf.baseAddress, buf.count)
    }
    var reply = [UInt8](repeating: 0, count: 8)
    _ = reply.withUnsafeMutableBufferPointer { p in
        Darwin.read(fd, p.baseAddress, p.count)
    }
}

class ExtDelegate: NSObject, OSSystemExtensionRequestDelegate {
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        debugLog("system extension: \(result.rawValue)")
        if result == .completed {
            saveProxyProfileAndExit()
        } else {
            // A non-.completed result means activation will only finish
            // after a reboot -- surface that so the user knows it's pending.
            FileHandle.standardError.write(Data("agentjail-macos: system extension activation incomplete (result \(result.rawValue)) -- a reboot may be required\n".utf8))
            exit(1)
        }
    }
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        FileHandle.standardError.write(Data("system extension failed: \(error)\n".utf8))
        exit(1)
    }
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        print("waiting for user approval in System Settings > Login Items & Extensions...")
    }
    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension new: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        return .replace
    }
}

var extDelegate: ExtDelegate?

func installSystemExtension() {
    let delegate = ExtDelegate()
    extDelegate = delegate
    let req = OSSystemExtensionRequest.activationRequest(
        forExtensionWithIdentifier: extBundleID, queue: .main)
    req.delegate = delegate
    OSSystemExtensionManager.shared.submitRequest(req)
}

// saveProxyProfileAndExit writes the NETransparentProxy profile.
// Preserves existing wg-conf when re-running `install` (idempotent).
func saveProxyProfileAndExit() {
    NETransparentProxyManager.loadAllFromPreferences { managers, err in
        if let err = err { fail("loadAll: \(err)") }
        let existing = managers?.first(where: { $0.localizedDescription == proxyProfileName })
        let manager = existing ?? NETransparentProxyManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = extBundleID
        proto.serverAddress = "agentjail-gateway"
        // Carry forward every key from the existing providerConfiguration
        // so that wg-conf survives a re-run of `install` (which the
        // shield issues on every invocation to make sure the sysext is
        // loaded).
        var cfg: [String: Any] = [:]
        if let existingProto = existing?.protocolConfiguration as? NETunnelProviderProtocol,
           let existingCfg = existingProto.providerConfiguration {
            for (k, v) in existingCfg { cfg[k] = v }
        }
        if cfg["wg-conf"] == nil { cfg["wg-conf"] = "" }
        proto.providerConfiguration = cfg
        manager.protocolConfiguration = proto
        manager.localizedDescription = proxyProfileName
        manager.isEnabled = true
        manager.saveToPreferences { err in
            if let err = err { fail("saveToPreferences: \(err)") }
            debugLog("proxy profile installed")
            exit(0)
        }
    }
}

// reloadTunnelAndExit stops the running tunnel, waits for
// .disconnected, then starts it again.  Used after a config change
// (conf swap) that providerConfiguration alone won't surface to
// the running extension.
func reloadTunnelAndExit(manager: NETransparentProxyManager, label: String) {
    debugLog("reloading tunnel for new \(label)")
    manager.connection.stopVPNTunnel()
    var attempts = 0
    func tick() {
        let s = manager.connection.status
        if s == .disconnected || s == .invalid || attempts > 50 {
            do {
                try manager.connection.startVPNTunnel()
                debugLog("tunnel reloaded")
                exit(0)
            } catch {
                fail("startVPNTunnel: \(error)")
            }
            return
        }
        attempts += 1
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2, execute: tick)
    }
    tick()
}

func startProxy(confPath: String) {
    guard let conf = try? String(contentsOfFile: confPath, encoding: .utf8) else {
        fail("read \(confPath)")
    }
    NETransparentProxyManager.loadAllFromPreferences { managers, err in
        if let err = err { fail("loadAll: \(err)") }
        guard let manager = managers?.first(where: { $0.localizedDescription == proxyProfileName }) else {
            fail("no proxy profile -- run `AgentjailTunnel install` first")
        }
        let prevConf: String = (manager.protocolConfiguration as? NETunnelProviderProtocol)?
            .providerConfiguration?["wg-conf"] as? String ?? ""
        if let proto = manager.protocolConfiguration as? NETunnelProviderProtocol {
            var cfg = proto.providerConfiguration ?? [:]
            cfg["wg-conf"] = conf
            proto.providerConfiguration = cfg
            manager.protocolConfiguration = proto
        }
        manager.isEnabled = true
        manager.saveToPreferences { err in
            if let err = err { fail("save: \(err)") }
            manager.loadFromPreferences { err in
                if let err = err { fail("reload: \(err)") }
                let running = manager.connection.status == .connected
                    || manager.connection.status == .connecting
                let confChanged = prevConf != conf
                if running && confChanged {
                    // Conf swap while running -- extension parses wg-conf
                    // once at startProxy.  Force a stop+start so the new
                    // peer key / address takes effect.
                    reloadTunnelAndExit(manager: manager, label: "wg-conf")
                    return
                }
                if running {
                    debugLog("proxy already up (no change)")
                    exit(0)
                }
                do {
                    try manager.connection.startVPNTunnel()
                    debugLog("proxy up")
                    exit(0)
                } catch {
                    fail("startVPNTunnel: \(error)")
                }
            }
        }
    }
}

func stopProxy() {
    NETransparentProxyManager.loadAllFromPreferences { managers, err in
        if let err = err { fail("loadAll: \(err)") }
        guard let manager = managers?.first(where: { $0.localizedDescription == proxyProfileName }) else {
            print("no profile to stop"); exit(0)
        }
        manager.connection.stopVPNTunnel()
        print("proxy down")
        exit(0)
    }
}

// Remove every NETunnelProviderManager AND NETransparentProxyManager
// our app has registered.  Used to clean up stale configs from earlier
// experiments (packet-tunnel days) when System Settings can't open
// the VPN pane to remove them by hand.
func wipeAllConfigs() {
    let group = DispatchGroup()
    var anyErr: Error?
    group.enter()
    NETunnelProviderManager.loadAllFromPreferences { managers, err in
        if let err = err { anyErr = err }
        for m in managers ?? [] {
            group.enter()
            m.removeFromPreferences { rerr in
                if let rerr = rerr { anyErr = rerr }
                group.leave()
            }
        }
        group.leave()
    }
    group.enter()
    NETransparentProxyManager.loadAllFromPreferences { managers, err in
        if let err = err { anyErr = err }
        for m in managers ?? [] {
            group.enter()
            m.removeFromPreferences { rerr in
                if let rerr = rerr { anyErr = rerr }
                group.leave()
            }
        }
        group.leave()
    }
    group.notify(queue: .main) {
        if let e = anyErr { fail("wipe: \(e)") }
        print("all configs removed")
        exit(0)
    }
}

func fail(_ msg: String) -> Never {
    FileHandle.standardError.write(Data("agentjail-macos: \(msg)\n".utf8))
>>>>>>> e090c3f (feat(macos): rewrite host app for NETransparentProxyProvider)
    exit(1)
}
