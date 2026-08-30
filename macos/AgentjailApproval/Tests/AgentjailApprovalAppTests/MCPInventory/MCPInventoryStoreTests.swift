import AgentjailApprovalCore
import Foundation
import XCTest
@testable import AgentjailApprovalApp

@MainActor
final class MCPInventoryStoreTests: XCTestCase {
    func testStoreDoesNotReadUntilRefreshAndRetainsOnlySanitizedSnapshot() async throws {
        let home = "/Users/fixture"
        let secret = "sk-store-secret"
        let data = try XCTUnwrap("""
        {"mcpServers":{"safe":{"command":"npx","args":["--token","\(secret)"]}}}
        """.data(using: .utf8))
        let reader = StoreFixtureReader(files: ["\(home)/.claude.json": .data(data)])
        let store = MCPInventoryStore(
            discovery: MCPInventoryDiscovery(reader: reader),
            dashboardClient: MCPInventoryDashboardClient(snapshot: try dashboardSnapshot()),
            homeDirectory: home
        )

        XCTAssertEqual(reader.readCount, 0)
        XCTAssertTrue(store.snapshot.items.isEmpty)

        await store.refresh()

        XCTAssertEqual(reader.readCount, 3)
        XCTAssertEqual(store.snapshot.items.count, 1)
        XCTAssertEqual(store.snapshot.items[0].target, "npx • 2 arguments hidden")
        XCTAssertFalse(store.snapshot.items[0].target.contains(secret))
        XCTAssertEqual(store.observedTools(for: "safe"), ["read_file", "write_file"])
        XCTAssertEqual(store.discoveryStatus(for: "safe"), .connected)
        XCTAssertFalse(store.isRefreshing)
    }

    func testExplicitDiscoveryPublishesCLIResultsAndPerServerStatus() async throws {
        let home = "/Users/fixture"
        let config = try XCTUnwrap(#"{"mcpServers":{"linear":{"url":"https://mcp.linear.app"}}}"#.data(using: .utf8))
        let reader = StoreFixtureReader(files: ["\(home)/.claude.json": .data(config)])
        let discoveryData = Data(#"{"protocol_version":1,"servers":[{"server":"linear","status":"connected","tools":["get_issue","list_issues"]},{"server":"private","status":"auth_required","tools":[]}]}"#.utf8)
        let toolSnapshot = try JSONDecoder().decode(MCPToolDiscoverySnapshot.self, from: discoveryData)
        let store = MCPInventoryStore(
            discovery: MCPInventoryDiscovery(reader: reader),
            dashboardClient: MCPInventoryDashboardClient(snapshot: try dashboardSnapshot()),
            toolDiscoveryClient: MCPInventoryToolDiscoveryClient(snapshot: toolSnapshot),
            homeDirectory: home
        )

        await store.discoverTools()

        XCTAssertEqual(store.observedTools(for: "linear"), ["get_issue", "list_issues"])
        XCTAssertEqual(store.discoveryStatus(for: "linear"), .connected)
        XCTAssertEqual(store.discoveryStatus(for: "private"), .authRequired)
        XCTAssertEqual(store.discoverySummary, "Found 2 tools across 1 connected servers")
        XCTAssertFalse(store.isDiscoveringTools)
    }

    private func dashboardSnapshot() throws -> DashboardSnapshotV1 {
        let data = Data("""
        {"protocol_version":1,"generated_at_unix_ms":1788020000000,"total_calls":2,"allowed_calls":2,"denied_calls":0,"asked_calls":0,"total_sessions":1,"active_sessions":0,"recent_sessions":[],"activity":[],"tokens":[],"token_agents":[],"mcp_tools":[{"server":"safe","tools":["write_file","read_file"]}],"mcp_discovery_status":[{"server":"safe","status":"connected"}],"token_coverage":[],"token_status":"ready"}
        """.utf8)
        return try JSONDecoder().decode(DashboardSnapshotV1.self, from: data)
    }
}

private actor MCPInventoryToolDiscoveryClient: MCPToolDiscoveryControlling {
    let snapshot: MCPToolDiscoverySnapshot

    init(snapshot: MCPToolDiscoverySnapshot) {
        self.snapshot = snapshot
    }

    func discoverTools() async throws -> MCPToolDiscoverySnapshot { snapshot }
}

private actor MCPInventoryDashboardClient: DashboardControlling {
    let snapshot: DashboardSnapshotV1

    init(snapshot: DashboardSnapshotV1) {
        self.snapshot = snapshot
    }

    func fetchDashboard() async throws -> DashboardSnapshotV1 { snapshot }
}

private final class StoreFixtureReader: MCPConfigFileReading {
    private let files: [String: MCPConfigFileReadResult]
    private(set) var readCount = 0

    init(files: [String: MCPConfigFileReadResult]) {
        self.files = files
    }

    func readFile(at path: String) -> MCPConfigFileReadResult {
        readCount += 1
        return files[path] ?? .missing
    }
}
