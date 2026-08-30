import AgentjailApprovalCore
import Foundation

@MainActor
final class MCPInventoryStore: ObservableObject {
    @Published private(set) var snapshot = MCPInventorySnapshot(items: [])
    @Published private(set) var isRefreshing = false
    @Published private(set) var observedToolsByServer: [String: [String]] = [:]
    @Published private(set) var toolDataUnavailable = false

    private let discovery: MCPInventoryDiscovery
    private let dashboardClient: any DashboardControlling
    private let homeDirectory: String

    init(
        discovery: MCPInventoryDiscovery = MCPInventoryDiscovery(),
        dashboardClient: any DashboardControlling = DashboardControlClient(),
        homeDirectory: String = FileManager.default.homeDirectoryForCurrentUser.path
    ) {
        self.discovery = discovery
        self.dashboardClient = dashboardClient
        self.homeDirectory = homeDirectory
    }

    func refresh() async {
        guard !isRefreshing else { return }
        isRefreshing = true
        defer { isRefreshing = false }
        snapshot = discovery.discover(homeDirectory: homeDirectory)
        do {
            let dashboard = try await dashboardClient.fetchDashboard()
            observedToolsByServer = dashboard.mcpTools.reduce(into: [:]) { result, server in
                let key = normalize(server.server)
                result[key] = Array(Set((result[key] ?? []) + server.tools)).sorted()
            }
            toolDataUnavailable = false
        } catch is CancellationError {
            return
        } catch {
            observedToolsByServer = [:]
            toolDataUnavailable = true
        }
    }

    func observedTools(for server: String) -> [String] {
        observedToolsByServer[normalize(server)] ?? []
    }

    private func normalize(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }
}
