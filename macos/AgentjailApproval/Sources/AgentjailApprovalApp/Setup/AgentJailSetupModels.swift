import Foundation

enum AgentJailSetupPhase: Equatable {
    case checking
    case moveToApplications
    case readyToInstall
    case installingComponents
    case enablingExtension
    case awaitingApproval
    case verifying
    case ready
    case failed(AgentJailSetupFailure)

    var isWorking: Bool {
        switch self {
        case .checking, .installingComponents, .enablingExtension, .awaitingApproval, .verifying:
            true
        case .moveToApplications, .readyToInstall, .ready, .failed:
            false
        }
    }
}

enum AgentJailSetupFailure: Equatable {
    case componentInstall
    case extensionInstall
    case verification
}

enum AgentJailTunnelProfileState: Equatable, Sendable {
    case absent
    case disabled
    case disconnected
    case connecting
    case connected
    case disconnecting
    case invalid

    var isConfigured: Bool {
        switch self {
        case .disconnected, .connecting, .connected, .disconnecting:
            true
        case .absent, .disabled, .invalid:
            false
        }
    }
}

struct AgentJailSetupHealth: Equatable, Sendable {
    let appInApplications: Bool
    let cliPresent: Bool
    let cliInstalled: Bool
    let daemonReachable: Bool
    let tunnelProfile: AgentJailTunnelProfileState

    init(
        appInApplications: Bool,
        cliPresent: Bool? = nil,
        cliInstalled: Bool,
        daemonReachable: Bool,
        tunnelProfile: AgentJailTunnelProfileState
    ) {
        self.appInApplications = appInApplications
        self.cliPresent = cliPresent ?? cliInstalled
        self.cliInstalled = cliInstalled
        self.daemonReachable = daemonReachable
        self.tunnelProfile = tunnelProfile
    }

    static let unknown = AgentJailSetupHealth(
        appInApplications: false,
        cliInstalled: false,
        daemonReachable: false,
        tunnelProfile: .absent
    )

    var isReady: Bool {
        appInApplications && cliInstalled && daemonReachable && tunnelProfile.isConfigured
    }

    var localComponentsReady: Bool {
        appInApplications && cliInstalled && daemonReachable
    }

    var localComponentsNeedUpdate: Bool {
        appInApplications && cliPresent && !cliInstalled
    }
}

enum AgentJailSetupMeasurement: Equatable, Sendable {
    case started
    case componentsStarted
    case componentsSucceeded
    case componentsFailed
    case extensionStarted
    case extensionSucceeded
    case extensionFailed
    case approvalRequired
    case verificationSucceeded
    case verificationFailed

    var arguments: (stage: String, outcome: String) {
        switch self {
        case .started: ("started", "started")
        case .componentsStarted: ("components", "started")
        case .componentsSucceeded: ("components", "succeeded")
        case .componentsFailed: ("components", "failed")
        case .extensionStarted: ("extension", "started")
        case .extensionSucceeded: ("extension", "succeeded")
        case .extensionFailed: ("extension", "failed")
        case .approvalRequired: ("approval", "required")
        case .verificationSucceeded: ("verification", "succeeded")
        case .verificationFailed: ("verification", "failed")
        }
    }
}

enum AgentJailSetupCommand: Equatable, Sendable {
    case installComponents
    case installExtension
    case record(AgentJailSetupMeasurement)
}

enum AgentJailSetupSignal: Equatable, Sendable {
    case approvalRequired
}

struct AgentJailSetupCommandResult: Equatable, Sendable {
    let launched: Bool
    let exitCode: Int32

    var succeeded: Bool { launched && exitCode == 0 }
}

protocol AgentJailSetupCommandRunning: Sendable {
    func run(
        _ command: AgentJailSetupCommand,
        signal: @escaping @Sendable (AgentJailSetupSignal) -> Void
    ) async -> AgentJailSetupCommandResult
}

protocol AgentJailSetupHealthInspecting: Sendable {
    func inspect() async -> AgentJailSetupHealth
}

protocol AgentJailSetupSleeping: Sendable {
    func pause() async
}

struct AgentJailSetupSleeper: AgentJailSetupSleeping {
    func pause() async {
        try? await Task.sleep(for: .milliseconds(300))
    }
}
