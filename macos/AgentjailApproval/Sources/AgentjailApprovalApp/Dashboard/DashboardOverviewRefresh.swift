import Foundation

@MainActor
enum DashboardOverviewRefresh {
    static func refresh(setup: AgentJailSetupCoordinator, dashboard: DashboardStore) async {
        guard !Task.isCancelled else { return }
        _ = await setup.refresh()
        guard !Task.isCancelled else { return }
        await dashboard.refresh()
    }

    static func untilAvailable(
        setup: AgentJailSetupCoordinator,
        dashboard: DashboardStore,
        sleeper: any DashboardSleeping = TaskDashboardSleeper()
    ) async {
        while !Task.isCancelled {
            await refresh(setup: setup, dashboard: dashboard)
            guard !Task.isCancelled,
                  setup.health.cliPresent,
                  !setup.health.daemonReachable || dashboard.unavailable else { return }
            do { try await sleeper.pause() }
            catch { return }
        }
    }
}
