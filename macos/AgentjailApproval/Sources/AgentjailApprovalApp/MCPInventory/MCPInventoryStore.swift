import AgentjailApprovalCore
import Foundation

@MainActor
final class MCPInventoryStore: ObservableObject {
    @Published private(set) var snapshot = MCPInventorySnapshot(items: [])
    @Published private(set) var isRefreshing = false
    @Published private(set) var observedToolsByServer: [String: [String]] = [:]
    @Published private(set) var toolDataUnavailable = false
    @Published private(set) var isDiscoveringTools = false
    @Published private(set) var discoveryStatusByServer: [String: MCPToolDiscoveryStatus] = [:]
    @Published private(set) var discoverySummary: String?

    private let discovery: MCPInventoryDiscovery
    private let dashboardClient: any DashboardControlling
    private let toolDiscoveryClient: any MCPToolDiscoveryControlling
    private let homeDirectory: String

    init(
        discovery: MCPInventoryDiscovery = MCPInventoryDiscovery(),
        dashboardClient: any DashboardControlling = DashboardControlClient(),
        toolDiscoveryClient: any MCPToolDiscoveryControlling = MCPToolDiscoveryCLIClient(),
        homeDirectory: String = FileManager.default.homeDirectoryForCurrentUser.path
    ) {
        self.discovery = discovery
        self.dashboardClient = dashboardClient
        self.toolDiscoveryClient = toolDiscoveryClient
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
            discoveryStatusByServer = dashboard.mcpDiscoveryStatuses.reduce(into: [:]) { result, server in
                result[normalize(server.server)] = server.status
            }
            toolDataUnavailable = false
        } catch is CancellationError {
            return
        } catch {
            toolDataUnavailable = observedToolsByServer.isEmpty
        }
    }

    func observedTools(for server: String) -> [String] {
        observedToolsByServer[normalize(server)] ?? []
    }

    func discoveryStatus(for server: String) -> MCPToolDiscoveryStatus? {
        discoveryStatusByServer[normalize(server)]
    }

    func discoverTools() async {
        guard !isDiscoveringTools else { return }
        isDiscoveringTools = true
        defer { isDiscoveringTools = false }
        do {
            let result = try await toolDiscoveryClient.discoverTools()
            discoveryStatusByServer = result.servers.reduce(into: [:]) { statuses, server in
                statuses[normalize(server.server)] = server.status
            }
            for server in result.servers where !server.tools.isEmpty {
                let key = normalize(server.server)
                observedToolsByServer[key] = Array(Set((observedToolsByServer[key] ?? []) + server.tools)).sorted()
            }
            toolDataUnavailable = false
            let connected = result.servers.filter { $0.status == .connected }.count
            let tools = result.servers.reduce(0) { $0 + $1.tools.count }
            discoverySummary = "Found \(tools) tools across \(connected) connected servers"
            snapshot = discovery.discover(homeDirectory: homeDirectory)
        } catch is CancellationError {
            return
        } catch {
            discoverySummary = "Tool discovery could not complete"
        }
    }

    private func normalize(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }
}
