import Foundation

@MainActor
final class AgentJailSetupCoordinator: ObservableObject {
    @Published private(set) var phase: AgentJailSetupPhase = .checking
    @Published private(set) var health: AgentJailSetupHealth = .unknown

    private let runner: any AgentJailSetupCommandRunning
    private let inspector: any AgentJailSetupHealthInspecting
    private let sleeper: any AgentJailSetupSleeping
    private var workflowTask: Task<Void, Never>?

    init(
        runner: any AgentJailSetupCommandRunning = BundledAgentJailCommandRunner(),
        inspector: any AgentJailSetupHealthInspecting = SystemAgentJailSetupHealthInspector(),
        sleeper: any AgentJailSetupSleeping = AgentJailSetupSleeper()
    ) {
        self.runner = runner
        self.inspector = inspector
        self.sleeper = sleeper
    }

    deinit {
        workflowTask?.cancel()
    }

    @discardableResult
    func refresh() async -> AgentJailSetupHealth {
        guard !phase.isWorking || phase == .checking else { return health }
        phase = .checking
        let inspected = await inspector.inspect()
        health = inspected
        phase = phaseForHealth(inspected)
        return inspected
    }

    func beginSetup() {
        guard workflowTask == nil, !phase.isWorking, health.appInApplications else { return }
        workflowTask = Task { [weak self] in
            await self?.runSetup()
            self?.workflowTask = nil
        }
    }

    func retry() {
        guard workflowTask == nil else { return }
        workflowTask = Task { [weak self] in
            guard let self else { return }
            _ = await self.refresh()
            self.workflowTask = nil
        }
    }

    private func runSetup() async {
        record(.started)

        if !health.localComponentsReady {
            phase = .installingComponents
            record(.componentsStarted)
            let result = await runner.run(.installComponents, signal: { _ in })
            guard result.succeeded else {
                phase = .failed(.componentInstall)
                record(.componentsFailed)
                return
            }
            record(.componentsSucceeded)
            health = await inspector.inspect()
            phase = phaseForHealth(health)
            return
        }

        if !health.tunnelProfile.isConfigured {
            phase = .enablingExtension
            record(.extensionStarted)
            // The Apple notice can be dismissed without approval, so the app
            // must already expose the durable next step. See ADR 0141-unified-macos-app.
            phase = .awaitingApproval
            let result = await runner.run(.installExtension) { [weak self] signal in
                guard signal == .approvalRequired else { return }
                Task { @MainActor [weak self] in
                    self?.record(.approvalRequired)
                }
            }
            guard result.succeeded else {
                phase = .failed(.extensionInstall)
                record(.extensionFailed)
                return
            }
            record(.extensionSucceeded)
        }

        phase = .verifying
        for _ in 0..<10 {
            guard !Task.isCancelled else { return }
            health = await inspector.inspect()
            if health.isReady {
                phase = .ready
                record(.verificationSucceeded)
                return
            }
            await sleeper.pause()
        }
        phase = .failed(.verification)
        record(.verificationFailed)
    }

    private func record(_ measurement: AgentJailSetupMeasurement) {
        Task { [runner] in
            _ = await runner.run(.record(measurement), signal: { _ in })
        }
    }

    private func phaseForHealth(_ health: AgentJailSetupHealth) -> AgentJailSetupPhase {
        if !health.appInApplications { return .moveToApplications }
        if health.isReady { return .ready }
        return .readyToInstall
    }
}
