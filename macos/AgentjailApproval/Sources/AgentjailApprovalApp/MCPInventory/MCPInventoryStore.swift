import AgentjailApprovalCore
import Foundation

@MainActor
final class MCPInventoryStore: ObservableObject {
    @Published private(set) var snapshot = MCPInventorySnapshot(items: [])
    @Published private(set) var isRefreshing = false

    private let discovery: MCPInventoryDiscovery
    private let homeDirectory: String

    init(
        discovery: MCPInventoryDiscovery = MCPInventoryDiscovery(),
        homeDirectory: String = FileManager.default.homeDirectoryForCurrentUser.path
    ) {
        self.discovery = discovery
        self.homeDirectory = homeDirectory
    }

    func refresh() {
        guard !isRefreshing else { return }
        isRefreshing = true
        snapshot = discovery.discover(homeDirectory: homeDirectory)
        isRefreshing = false
    }
}
