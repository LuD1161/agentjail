import AgentjailApprovalCore
import Foundation
import XCTest
@testable import AgentjailApprovalApp

@MainActor
final class DashboardStoreTests: XCTestCase {
    func testRefreshPublishesFastSnapshotThenPollsUntilTokensAreReady() async throws {
        let client = DashboardScriptedClient([
            try snapshot(tokenStatus: .loading, totalCalls: 7),
            try snapshot(tokenStatus: .ready, totalCalls: 8),
        ])
        let store = DashboardStore(client: client, sleeper: ImmediateDashboardSleeper(), tokenPollLimit: 3)

        await store.refresh()

        XCTAssertEqual(store.snapshot?.totalCalls, 8)
        XCTAssertEqual(store.snapshot?.tokenStatus, .ready)
        XCTAssertFalse(store.unavailable)
        let fetchCount = await client.fetchCount()
        XCTAssertEqual(fetchCount, 2)
    }

    private func snapshot(tokenStatus: DashboardTokenStatus, totalCalls: Int64) throws -> DashboardSnapshotV1 {
        let data = Data("""
        {"protocol_version":1,"generated_at_unix_ms":1788020000000,"total_calls":\(totalCalls),"allowed_calls":7,"denied_calls":0,"asked_calls":0,"total_sessions":1,"active_sessions":0,"recent_sessions":[],"activity":[],"tokens":[],"token_coverage":["Claude Code","Codex","OpenCode"],"token_status":"\(tokenStatus.rawValue)"}
        """.utf8)
        return try JSONDecoder().decode(DashboardSnapshotV1.self, from: data)
    }
}

private actor DashboardScriptedClient: DashboardControlling {
    private var snapshots: [DashboardSnapshotV1]
    private var count = 0

    init(_ snapshots: [DashboardSnapshotV1]) { self.snapshots = snapshots }

    func fetchDashboard() async throws -> DashboardSnapshotV1 {
        count += 1
        if snapshots.count > 1 { return snapshots.removeFirst() }
        return snapshots[0]
    }

    func fetchCount() -> Int { count }
}

private struct ImmediateDashboardSleeper: DashboardSleeping {
    func pause() async throws { await Task.yield() }
}
