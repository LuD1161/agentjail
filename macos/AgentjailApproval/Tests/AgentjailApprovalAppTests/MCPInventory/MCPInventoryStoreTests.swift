import AgentjailApprovalCore
import Foundation
import XCTest
@testable import AgentjailApprovalApp

@MainActor
final class MCPInventoryStoreTests: XCTestCase {
    func testStoreDoesNotReadUntilRefreshAndRetainsOnlySanitizedSnapshot() throws {
        let home = "/Users/fixture"
        let secret = "sk-store-secret"
        let data = try XCTUnwrap("""
        {"mcpServers":{"safe":{"command":"npx","args":["--token","\(secret)"]}}}
        """.data(using: .utf8))
        let reader = StoreFixtureReader(files: ["\(home)/.claude.json": .data(data)])
        let store = MCPInventoryStore(
            discovery: MCPInventoryDiscovery(reader: reader),
            homeDirectory: home
        )

        XCTAssertEqual(reader.readCount, 0)
        XCTAssertTrue(store.snapshot.items.isEmpty)

        store.refresh()

        XCTAssertEqual(reader.readCount, 3)
        XCTAssertEqual(store.snapshot.items.count, 1)
        XCTAssertEqual(store.snapshot.items[0].target, "npx • 2 arguments hidden")
        XCTAssertFalse(store.snapshot.items[0].target.contains(secret))
        XCTAssertFalse(store.isRefreshing)
    }
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
