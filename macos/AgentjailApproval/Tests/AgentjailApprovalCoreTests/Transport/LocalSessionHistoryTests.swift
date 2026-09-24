import Foundation
import Testing
@testable import AgentjailApprovalCore

struct LocalSessionHistoryTests {
    @Test func decodesMetadataIndependentlyOfAuditCounts() throws {
        let data = Data("""
        {"id":"opaque","agent":"codex","project":"demo","started_at_unix_ms":1234}
        """.utf8)
        let session = try JSONDecoder().decode(DashboardLocalSession.self, from: data)
        #expect(session.agent == "codex")
        #expect(session.project == "demo")
        #expect(session.startedAtUnixMs == 1234)
    }

    @Test(arguments: ["", String(repeating: "x", count: 129)])
    func rejectsInvalidIdentity(identity: String) throws {
        let data = try JSONSerialization.data(withJSONObject: ["id": identity, "agent": "codex", "project": "demo", "started_at_unix_ms": 1234])
        #expect(throws: DashboardModelError.invalidProjection) {
            try JSONDecoder().decode(DashboardLocalSession.self, from: data)
        }
    }
}
