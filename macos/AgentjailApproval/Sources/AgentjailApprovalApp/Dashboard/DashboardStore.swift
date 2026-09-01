import AgentjailApprovalCore
import Foundation

@MainActor
final class DashboardStore: ObservableObject {
    @Published private(set) var snapshot: DashboardSnapshotV1?
    @Published private(set) var tokenSnapshot: DashboardSnapshotV1?
    @Published private(set) var isRefreshing = false
    @Published private(set) var unavailable = false
    private let client: any DashboardControlling
    private let sleeper: any DashboardSleeping
    private let tokenPollLimit: Int
    private var tokenRefreshTask: Task<Void, Never>?

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
        tokenRefreshTask?.cancel()
        isRefreshing = true
        defer { isRefreshing = false }
        do {
            let freshSnapshot = try await client.fetchDashboard()
            snapshot = freshSnapshot
            tokenSnapshot = freshSnapshot
            unavailable = false
            beginTokenRefreshIfNeeded(after: freshSnapshot)
        } catch is CancellationError {
            return
        } catch {
            unavailable = snapshot == nil
        }
    }

    private func beginTokenRefreshIfNeeded(after freshSnapshot: DashboardSnapshotV1) {
        guard freshSnapshot.tokenStatus == .loading, tokenPollLimit > 1 else { return }
        tokenRefreshTask = Task { [weak self] in
            guard let self else { return }
            for _ in 1..<tokenPollLimit {
                do {
                    try await sleeper.pause()
                    try Task.checkCancellation()
                    let refreshedTokens = try await client.fetchDashboard()
                    tokenSnapshot = refreshedTokens
                    guard refreshedTokens.tokenStatus == .loading else { return }
                } catch {
                    return
                }
            }
        }
    }
}

protocol DashboardSleeping: Sendable {
    func pause() async throws
}

struct TaskDashboardSleeper: DashboardSleeping {
    func pause() async throws { try await Task.sleep(for: .seconds(1)) }
}
