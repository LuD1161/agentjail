import XCTest
@testable import AgentjailApprovalApp

@MainActor
final class AgentJailSetupCoordinatorTests: XCTestCase {
    func testRefreshRequiresStableApplicationsLocationBeforeSetup() async {
        let health = AgentJailSetupHealth(appInApplications: false, cliInstalled: false, daemonReachable: false, tunnelProfile: .absent)
        let coordinator = AgentJailSetupCoordinator(
            runner: SetupCommandRunner(),
            inspector: SetupHealthInspector([health]),
            sleeper: ImmediateSetupSleeper()
        )

        _ = await coordinator.refresh()

        XCTAssertEqual(coordinator.phase, .moveToApplications)
        coordinator.beginSetup()
        XCTAssertEqual(coordinator.phase, .moveToApplications)
    }

    func testSetupInstallsComponentsRequestsApprovalAndVerifiesHealth() async {
        let runner = SetupCommandRunner(approvalRequired: true)
        let inspector = SetupHealthInspector([
            health(cli: false, daemon: false, tunnel: .absent),
            health(cli: true, daemon: true, tunnel: .absent),
            health(cli: true, daemon: true, tunnel: .disconnected),
        ])
        let coordinator = AgentJailSetupCoordinator(runner: runner, inspector: inspector, sleeper: ImmediateSetupSleeper())
        _ = await coordinator.refresh()

        coordinator.beginSetup()
        await eventually { coordinator.phase == .ready }
        await eventually(runner: runner, contains: .record(.verificationSucceeded))

        let commands = await runner.commands()
        XCTAssertTrue(commands.contains(.installComponents))
        XCTAssertTrue(commands.contains(.installExtension))
        XCTAssertTrue(commands.contains(.record(.approvalRequired)))
        XCTAssertTrue(commands.contains(.record(.verificationSucceeded)))
        XCTAssertEqual(coordinator.health.tunnelProfile, .disconnected)
    }

    func testComponentFailureStopsBeforeExtensionAndRemainsRetryable() async {
        let runner = SetupCommandRunner(failing: .installComponents)
        let coordinator = AgentJailSetupCoordinator(
            runner: runner,
            inspector: SetupHealthInspector([health(cli: false, daemon: false, tunnel: .absent)]),
            sleeper: ImmediateSetupSleeper()
        )
        _ = await coordinator.refresh()

        coordinator.beginSetup()
        await eventually { coordinator.phase == .failed(.componentInstall) }
        await eventually(runner: runner, contains: .record(.componentsFailed))

        let commands = await runner.commands()
        XCTAssertTrue(commands.contains(.installComponents))
        XCTAssertFalse(commands.contains(.installExtension))
        XCTAssertTrue(commands.contains(.record(.componentsFailed)))
    }

    private func health(cli: Bool, daemon: Bool, tunnel: AgentJailTunnelProfileState) -> AgentJailSetupHealth {
        AgentJailSetupHealth(appInApplications: true, cliInstalled: cli, daemonReachable: daemon, tunnelProfile: tunnel)
    }

    private func eventually(timeout: Duration = .seconds(1), condition: @escaping @MainActor () -> Bool) async {
        let clock = ContinuousClock()
        let deadline = clock.now + timeout
        while !condition(), clock.now < deadline {
            await Task.yield()
        }
        XCTAssertTrue(condition())
    }

    private func eventually(
        runner: SetupCommandRunner,
        contains command: AgentJailSetupCommand,
        timeout: Duration = .seconds(1)
    ) async {
        let clock = ContinuousClock()
        let deadline = clock.now + timeout
        while !(await runner.commands()).contains(command), clock.now < deadline {
            await Task.yield()
        }
        let found = (await runner.commands()).contains(command)
        XCTAssertTrue(found)
    }
}

private actor SetupCommandRunner: AgentJailSetupCommandRunning {
    private var recordedCommands: [AgentJailSetupCommand] = []
    private let failingCommand: AgentJailSetupCommand?
    private let approvalRequired: Bool

    init(failing: AgentJailSetupCommand? = nil, approvalRequired: Bool = false) {
        failingCommand = failing
        self.approvalRequired = approvalRequired
    }

    func run(_ command: AgentJailSetupCommand, signal: @escaping @Sendable (AgentJailSetupSignal) -> Void) async -> AgentJailSetupCommandResult {
        recordedCommands.append(command)
        if command == .installExtension, approvalRequired {
            signal(.approvalRequired)
            await Task.yield()
        }
        return AgentJailSetupCommandResult(launched: true, exitCode: command == failingCommand ? 1 : 0)
    }

    func commands() -> [AgentJailSetupCommand] { recordedCommands }
}

private actor SetupHealthInspector: AgentJailSetupHealthInspecting {
    private var snapshots: [AgentJailSetupHealth]
    private var latest: AgentJailSetupHealth

    init(_ snapshots: [AgentJailSetupHealth]) {
        precondition(!snapshots.isEmpty)
        self.snapshots = snapshots
        latest = snapshots[0]
    }

    func inspect() async -> AgentJailSetupHealth {
        guard !snapshots.isEmpty else { return latest }
        latest = snapshots.removeFirst()
        return latest
    }
}

private struct ImmediateSetupSleeper: AgentJailSetupSleeping {
    func pause() async { await Task.yield() }
}
