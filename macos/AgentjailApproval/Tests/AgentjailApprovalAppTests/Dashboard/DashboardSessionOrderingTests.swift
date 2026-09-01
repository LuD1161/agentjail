import AgentjailApprovalCore
import Foundation
import XCTest
@testable import AgentjailApprovalApp

final class DashboardSessionOrderingTests: XCTestCase {
    func testLiveSessionsComeFirstWithDeterministicRecencyWithinEachGroup() throws {
        let sessions = try decode([
            session(id: "recent-old", started: 100, ended: 200, active: false),
            session(id: "live-old", started: 300, ended: nil, active: true),
            session(id: "recent-new", started: 400, ended: 500, active: false),
            session(id: "live-new", started: 600, ended: nil, active: true),
        ])

        XCTAssertEqual(
            DashboardSessionOrdering.liveFirst(sessions).map(\.sessionID),
            ["live-new", "live-old", "recent-new", "recent-old"]
        )
    }

    private func session(id: String, started: Int64, ended: Int64?, active: Bool) -> [String: Any] {
        var value: [String: Any] = [
            "session_id": id,
            "agent": "codex",
            "project": id,
            "started_at_unix_ms": started,
            "audited_calls": 1,
            "active": active,
        ]
        if let ended { value["ended_at_unix_ms"] = ended }
        return value
    }

    private func decode(_ values: [[String: Any]]) throws -> [DashboardSession] {
        try JSONDecoder().decode([DashboardSession].self, from: JSONSerialization.data(withJSONObject: values))
    }
}
