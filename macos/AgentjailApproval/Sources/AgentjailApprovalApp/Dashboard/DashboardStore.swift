import AgentjailApprovalCore
import Foundation

@MainActor
final class DashboardStore: ObservableObject {
    @Published private(set) var snapshot: DashboardSnapshotV1?
    @Published private(set) var isRefreshing = false
    @Published private(set) var unavailable = false
    private let client: any DashboardControlling

    init(client: any DashboardControlling = DashboardControlClient()) { self.client = client }

    func refresh() async {
        guard !isRefreshing else { return }
        isRefreshing = true
        defer { isRefreshing = false }
        do {
            snapshot = try await client.fetchDashboard()
            unavailable = false
        } catch {
            unavailable = true
        }
    }
}
