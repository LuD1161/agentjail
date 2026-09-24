import AgentjailApprovalCore
import Foundation
@preconcurrency import NetworkExtension

struct SystemAgentJailSetupHealthInspector: AgentJailSetupHealthInspecting {
    private let appURL: URL
    private let reviewClient: any ReviewControlling
    private let statusService: any AgentJailStatusServicing

    init(
        bundle: Bundle = .main,
        reviewClient: any ReviewControlling = ReviewControlClient(),
        statusService: (any AgentJailStatusServicing)? = nil
    ) {
        appURL = bundle.bundleURL
        self.reviewClient = reviewClient
        self.statusService = statusService ?? BundledAgentJailStatusService(runner: BundledAgentJailStatusCommandRunner(bundle: bundle))
    }

    func inspect() async -> AgentJailSetupHealth {
        async let tunnelProfile = inspectTunnelProfile()
        async let daemonReachable = inspectDaemon()
        let installation = (try? await statusService.status())?.installation
        return await setupHealthForInstallation(
            appInApplications: appURL.resolvingSymlinksInPath().standardizedFileURL.path == "/Applications/AgentJail.app",
            installation: installation,
            reviewAvailable: daemonReachable,
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

func setupHealthForInstallation(
    appInApplications: Bool,
    installation: AgentJailInstallationSnapshot?,
    reviewAvailable: Bool,
    tunnelProfile: AgentJailTunnelProfileState
) -> AgentJailSetupHealth {
    AgentJailSetupHealth(
        appInApplications: appInApplications,
        cliPresent: installation?.cliPresent ?? false,
        cliInstalled: installation?.componentsCompatible ?? false,
        daemonReachable: reviewAvailable && (installation?.daemonMatchesInstall ?? false),
        tunnelProfile: tunnelProfile,
        explicitlyUninstalled: installation?.explicitlyUninstalled ?? false,
        canInstallComponents: installation?.canInstallBundledComponents ?? false,
        canRepairInstalledComponents: installation?.canRepairInstalledComponents ?? false
    )
}
