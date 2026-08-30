import AgentjailApprovalCore
import Foundation
@preconcurrency import NetworkExtension

struct SystemAgentJailSetupHealthInspector: AgentJailSetupHealthInspecting {
    private let appURL: URL
    private let cliURL: URL
    private let bundledCLIURL: URL?
    private let reviewClient: any ReviewControlling

    init(
        bundle: Bundle = .main,
        homeDirectory: URL? = FileManager.default.homeDirectoryForCurrentUser,
        reviewClient: any ReviewControlling = ReviewControlClient()
    ) {
        appURL = bundle.bundleURL
        cliURL = (homeDirectory ?? URL(fileURLWithPath: "/", isDirectory: true))
            .appendingPathComponent(".agentjail/bin/agentjail")
        bundledCLIURL = bundle.resourceURL?
            .appendingPathComponent("bin", isDirectory: true)
            .appendingPathComponent("agentjail")
        self.reviewClient = reviewClient
    }

    func inspect() async -> AgentJailSetupHealth {
        async let tunnelProfile = inspectTunnelProfile()
        async let daemonReachable = inspectDaemon()
        return await AgentJailSetupHealth(
            appInApplications: appURL.resolvingSymlinksInPath().standardizedFileURL.path == "/Applications/AgentJail.app",
            cliInstalled: installedExecutableMatchesBundled(
                installedURL: cliURL,
                bundledURL: bundledCLIURL,
                fileManager: .default
            ),
            daemonReachable: daemonReachable,
            tunnelProfile: tunnelProfile
        )
    }

    private func inspectDaemon() async -> Bool {
        do {
            _ = try await reviewClient.fetchSnapshot()
            return true
        } catch {
            return false
        }
    }

    private func inspectTunnelProfile() async -> AgentJailTunnelProfileState {
        await withCheckedContinuation { continuation in
            NETransparentProxyManager.loadAllFromPreferences { managers, error in
                guard error == nil,
                      let manager = managers?.first(where: { $0.localizedDescription == proxyProfileName })
                else {
                    continuation.resume(returning: .absent)
                    return
                }
                guard manager.isEnabled else {
                    continuation.resume(returning: .disabled)
                    return
                }
                let state: AgentJailTunnelProfileState
                switch manager.connection.status {
                case .disconnected: state = .disconnected
                case .connecting, .reasserting: state = .connecting
                case .connected: state = .connected
                case .disconnecting: state = .disconnecting
                case .invalid: state = .invalid
                @unknown default: state = .invalid
                }
                continuation.resume(returning: state)
            }
        }
    }
}

func installedExecutableMatchesBundled(
    installedURL: URL,
    bundledURL: URL?,
    fileManager: FileManager
) -> Bool {
    guard let bundledURL,
          fileManager.isExecutableFile(atPath: installedURL.path),
          fileManager.isExecutableFile(atPath: bundledURL.path)
    else { return false }
    return fileManager.contentsEqual(atPath: installedURL.path, andPath: bundledURL.path)
}
