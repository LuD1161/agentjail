import AgentjailApprovalCore
import Foundation
import Testing
@testable import AgentjailApprovalApp

@MainActor
struct DashboardOverviewRefreshTests {
    @Test func installedDaemonRecoversWithoutManualRefresh() async throws {
        let inspector = StartupInspector(cliPresent: true, daemonStates: [false, true])
        let setup = AgentJailSetupCoordinator(inspector: inspector)
        let client = StartupDashboardClient(failures: 1, snapshot: try snapshot())
        let dashboard = DashboardStore(client: client)
        let sleeper = CountingRetrySleeper()

        await DashboardOverviewRefresh.untilAvailable(setup: setup, dashboard: dashboard, sleeper: sleeper)

        #expect(setup.health.isReady)
        #expect(dashboard.snapshot?.totalCalls == 4)
        #expect(!dashboard.unavailable)
        #expect(await sleeper.count == 1)
        #expect(await client.calls == 2)
    }

    @Test func retriesDashboardEvenWhenHealthRequestSucceeds() async throws {
        let setup = AgentJailSetupCoordinator(inspector: StartupInspector(cliPresent: true, daemonStates: [true]))
        let client = StartupDashboardClient(failures: 1, snapshot: try snapshot())
        let dashboard = DashboardStore(client: client)
        let sleeper = CountingRetrySleeper()

        await DashboardOverviewRefresh.untilAvailable(setup: setup, dashboard: dashboard, sleeper: sleeper)

        #expect(dashboard.snapshot?.totalCalls == 4)
        #expect(await sleeper.count == 1)
    }

    @Test func missingInstallationDoesNotPoll() async throws {
        let setup = AgentJailSetupCoordinator(inspector: StartupInspector(cliPresent: false, daemonStates: [false]))
        let client = StartupDashboardClient(failures: 1, snapshot: try snapshot())
        let dashboard = DashboardStore(client: client)
        let sleeper = CountingRetrySleeper()

        await DashboardOverviewRefresh.untilAvailable(setup: setup, dashboard: dashboard, sleeper: sleeper)

        #expect(setup.phase == .readyToInstall)
        #expect(await sleeper.count == 0)
        #expect(await client.calls == 1)
    }

    @Test func leavingOverviewCancelsRecovery() async throws {
        let setup = AgentJailSetupCoordinator(inspector: StartupInspector(cliPresent: true, daemonStates: [false]))
        let client = StartupDashboardClient(failures: 1, snapshot: try snapshot())
        let dashboard = DashboardStore(client: client)
        let sleeper = SuspendedRetrySleeper()
        let task = Task {
            await DashboardOverviewRefresh.untilAvailable(setup: setup, dashboard: dashboard, sleeper: sleeper)
        }
        await sleeper.waitUntilSleeping()
        task.cancel()
        await task.value

        #expect(await client.calls == 1)
    }

    private func snapshot() throws -> DashboardSnapshotV1 {
        try JSONDecoder().decode(DashboardSnapshotV1.self, from: Data("""
        {"protocol_version":1,"generated_at_unix_ms":1788020000000,"total_calls":4,"allowed_calls":3,"denied_calls":1,"asked_calls":0,"total_sessions":4,"active_sessions":0,"recent_sessions":[],"activity":[],"tokens":[],"token_agents":[],"token_coverage":[],"token_status":"ready"}
        """.utf8))
    }
}

private actor StartupInspector: AgentJailSetupHealthInspecting {
    let cliPresent: Bool
    var daemonStates: [Bool]
    init(cliPresent: Bool, daemonStates: [Bool]) {
        self.cliPresent = cliPresent
        self.daemonStates = daemonStates
    }
    func inspect() async -> AgentJailSetupHealth {
        let reachable = daemonStates.count > 1 ? daemonStates.removeFirst() : daemonStates[0]
        return AgentJailSetupHealth(appInApplications: true, cliInstalled: cliPresent, daemonReachable: reachable, tunnelProfile: .connected)
    }
}

private actor StartupDashboardClient: DashboardControlling {
    var calls = 0
    let failures: Int
    let snapshot: DashboardSnapshotV1
    init(failures: Int, snapshot: DashboardSnapshotV1) {
        self.failures = failures
        self.snapshot = snapshot
    }
    func fetchDashboard() async throws -> DashboardSnapshotV1 {
        calls += 1
        if calls <= failures { throw ApprovalControlError.daemonUnavailable }
        return snapshot
    }
}

private actor CountingRetrySleeper: DashboardSleeping {
    var count = 0
    func pause() async throws { count += 1 }
}

private actor SuspendedRetrySleeper: DashboardSleeping {
    private var sleeping = false
    private var observer: CheckedContinuation<Void, Never>?
    func pause() async throws {
        sleeping = true
        observer?.resume()
        observer = nil
        try await Task.sleep(for: .seconds(3600))
    }
    func waitUntilSleeping() async {
        guard !sleeping else { return }
        await withCheckedContinuation { observer = $0 }
    }
}
