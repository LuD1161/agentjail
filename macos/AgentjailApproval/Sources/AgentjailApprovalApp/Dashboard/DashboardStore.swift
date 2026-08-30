import AgentjailApprovalCore
import Foundation

@MainActor
final class DashboardStore: ObservableObject {
    @Published private(set) var snapshot: DashboardSnapshotV1?
    @Published private(set) var isRefreshing = false
    @Published private(set) var unavailable = false
    private let client: any DashboardControlling
    private let sleeper: any DashboardSleeping
    private let tokenPollLimit: Int

    init(
        client: any DashboardControlling = DashboardControlClient(),
        sleeper: any DashboardSleeping = TaskDashboardSleeper(),
        tokenPollLimit: Int = 60
    ) {
        self.client = client
        self.sleeper = sleeper
        self.tokenPollLimit = max(tokenPollLimit, 1)
    }

    func refresh() async {
        guard !isRefreshing else { return }
        isRefreshing = true
        defer { isRefreshing = false }
        for attempt in 0..<tokenPollLimit {
            do {
                snapshot = try await client.fetchDashboard()
                unavailable = false
            } catch is CancellationError {
                return
            } catch {
                unavailable = snapshot == nil
                return
            }
            guard snapshot?.tokenStatus == .loading, attempt + 1 < tokenPollLimit else { return }
            do { try await sleeper.pause() } catch { return }
        }
    }
}

protocol DashboardSleeping: Sendable {
    func pause() async throws
}

struct TaskDashboardSleeper: DashboardSleeping {
    func pause() async throws { try await Task.sleep(for: .seconds(1)) }
}
