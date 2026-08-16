// Host app - activates the system extension and saves a transparent-proxy
// configuration into NETransparentProxyManager.  The extension does the
// per-process filtering itself by walking each flow's audit-token chain
// back to `com.blinkerlm.agentjail.app`, so we don't need NEAppRule /
// matchTools here (which on macOS require an MDM-pushed appmapping
// payload).
//
// CLI invocation:
//   AgentjailTunnel install             - activate sysext + save proxy profile
//   AgentjailTunnel start <wg-conf> [generation] - load WG conf, start proxy
//   AgentjailTunnel stop                - stop proxy
//   AgentjailTunnel run -- <cmd> [args] - fork+exec cmd as child of AgentjailTunnel
//                                         so the extension's PPID-walk picks it up
//   AgentjailTunnel wipe                - remove all proxy configs (cleanup)
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
    let generation = CommandLine.arguments.count >= 4
        ? CommandLine.arguments[3] : UUID().uuidString
    startProxy(confPath: CommandLine.arguments[2], generation: generation)
case "stop": stopProxy()
case "run": runWrapped()    // synchronous; calls exit() - never reaches runloop
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

    guard let generationReply = sessionIPC("generation"),
          generationReply.hasPrefix("generation ") else {
        fail("tunnel provider is not ready")
    }
    let generation = generationReply
        .replacingOccurrences(of: "generation ", with: "")
        .trimmingCharacters(in: .whitespacesAndNewlines)
    guard sessionIPC("register \(getpid()) \(generation)") == "ok\n" else {
        fail("tunnel session registration failed")
    }
    defer { _ = sessionIPC("unregister \(getpid()) \(generation)") }

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
// framed verb and returns the provider's bounded acknowledgement.
func sessionIPC(_ msg: String) -> String? {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    if fd < 0 { return nil }
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
    if rc != 0 { return nil }
    var line = msg + "\n"
    _ = line.withUTF8 { buf in
        Darwin.write(fd, buf.baseAddress, buf.count)
    }
    var reply = [UInt8](repeating: 0, count: 256)
    let count = reply.withUnsafeMutableBufferPointer { p in
        Darwin.read(fd, p.baseAddress, p.count)
    }
    if count <= 0 { return nil }
    return String(bytes: reply[0..<count], encoding: .utf8)
}

class ExtDelegate: NSObject, OSSystemExtensionRequestDelegate {
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        debugLog("system extension: \(result.rawValue)")
        if result == .completed {
            saveProxyProfileAndExit()
        } else {
            // A non-.completed result means activation will only finish
            // after a reboot - surface that so the user knows it's pending.
            FileHandle.standardError.write(Data("agentjail-macos: system extension activation incomplete (result \(result.rawValue)) - a reboot may be required\n".utf8))
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
func waitForDisconnected(manager: NETransparentProxyManager,
                         label: String,
                         completion: @escaping () -> Void) {
    var attempts = 0
    func tick() {
        let s = manager.connection.status
        if s == .disconnected || s == .invalid {
            completion()
            return
        }
        if attempts > 150 { fail("timed out waiting for \(label) to disconnect") }
        attempts += 1
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2, execute: tick)
    }
    tick()
}

func startTunnelWhenDisconnectedAndExit(manager: NETransparentProxyManager,
                                        label: String) {
    waitForDisconnected(manager: manager, label: label) {
        do {
            try manager.connection.startVPNTunnel()
            debugLog("tunnel started after \(label)")
            exit(0)
        } catch {
            fail("startVPNTunnel: \(error)")
        }
    }
}

func reloadTunnelAndExit(manager: NETransparentProxyManager, label: String) {
    debugLog("reloading tunnel for new \(label)")
    manager.connection.stopVPNTunnel()
    startTunnelWhenDisconnectedAndExit(manager: manager, label: label)
}

func startProxy(confPath: String, generation: String) {
    guard let conf = try? String(contentsOfFile: confPath, encoding: .utf8) else {
        fail("read \(confPath)")
    }
    NETransparentProxyManager.loadAllFromPreferences { managers, err in
        if let err = err { fail("loadAll: \(err)") }
        guard let manager = managers?.first(where: { $0.localizedDescription == proxyProfileName }) else {
            fail("no proxy profile - run `AgentjailTunnel install` first")
        }
        let prevConf: String = (manager.protocolConfiguration as? NETunnelProviderProtocol)?
            .providerConfiguration?["wg-conf"] as? String ?? ""
        if let proto = manager.protocolConfiguration as? NETunnelProviderProtocol {
            var cfg = proto.providerConfiguration ?? [:]
            cfg["wg-conf"] = conf
            cfg["session-generation"] = generation
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
                    // Conf swap while running - extension parses wg-conf
                    // once at startProxy.  Force a stop+start so the new
                    // peer key / address takes effect.
                    reloadTunnelAndExit(manager: manager, label: "wg-conf")
                    return
                }
                if running {
                    debugLog("proxy already up (no change)")
                    exit(0)
                }
                if manager.connection.status == .disconnecting {
                    startTunnelWhenDisconnectedAndExit(manager: manager, label: "prior stop")
                    return
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
        waitForDisconnected(manager: manager, label: "proxy") {
            print("proxy down")
            exit(0)
        }
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
    exit(1)
}
