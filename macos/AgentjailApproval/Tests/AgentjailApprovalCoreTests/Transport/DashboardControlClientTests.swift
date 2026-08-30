import Foundation
import XCTest
@testable import AgentjailApprovalCore

final class DashboardControlClientTests: XCTestCase {
    func testRequestIsReadOnlyVersionedAndResponseIsTyped() async throws {
        let token = String(repeating: "a", count: 64)
        let transport = DashboardRecordingTransport(reply: validFrame())
        let snapshot = try await DashboardControlClient(tokenLoader: DashboardTokenLoader(token: token), transport: transport).fetchDashboard()
        XCTAssertEqual(snapshot.totalCalls, 9)
        XCTAssertEqual(snapshot.tokenStatus, .loading)
        XCTAssertEqual(snapshot.mcpTools.first?.tools, ["navigate_page", "take_snapshot"])
        let request = try transport.request()
        XCTAssertEqual(Set(request.keys), ["type", "ctl_token", "protocol_version"])
        XCTAssertEqual(request["type"] as? String, "dashboard_snapshot")
        XCTAssertEqual(request["protocol_version"] as? Int, 1)
    }

    func testMalformedProjectionAndSecretBearingFailureAreSafe() async throws {
        let token = String(repeating: "b", count: 64)
        let malformed = Data("{\"ok\":true,\"dashboard_snapshot\":{\"protocol_version\":1}}\n".utf8)
        do {
            _ = try await DashboardControlClient(tokenLoader: DashboardTokenLoader(token: token), transport: DashboardRecordingTransport(reply: malformed)).fetchDashboard()
            XCTFail("expected malformed projection")
        } catch let error as ApprovalControlError {
            XCTAssertEqual(error, .malformedReply)
        }

        let refused = Data("{\"ok\":false,\"error\":\"failed \(token)\"}\n".utf8)
        do {
            _ = try await DashboardControlClient(tokenLoader: DashboardTokenLoader(token: token), transport: DashboardRecordingTransport(reply: refused)).fetchDashboard()
            XCTFail("expected refusal")
        } catch let error as ApprovalControlError {
            XCTAssertEqual(error, .serverRefused("failed [redacted]"))
            XCTAssertFalse(String(describing: error).contains(token))
        }
    }

    private func validFrame() -> Data {
        Data("""
        {"ok":true,"dashboard_snapshot":{"protocol_version":1,"generated_at_unix_ms":1788020000000,"total_calls":9,"allowed_calls":7,"denied_calls":1,"asked_calls":1,"total_sessions":2,"active_sessions":1,"recent_sessions":[],"activity":[],"tokens":[],"token_agents":[],"mcp_tools":[{"server":"chrome-devtools","tools":["navigate_page","take_snapshot"]}],"token_coverage":["Claude Code","Codex"],"token_status":"loading"}}
        """.utf8) + Data([10])
    }
}

private struct DashboardTokenLoader: ControlTokenLoading {
    let token: String
    func loadToken() throws -> String { token }
}

private final class DashboardRecordingTransport: ControlFraming, @unchecked Sendable {
    private let reply: Data
    private let lock = NSLock()
    private var frame: Data?
    init(reply: Data) { self.reply = reply }
    func roundTrip(_ frame: Data) async throws -> Data { lock.withLock { self.frame = frame }; return reply }
    func request() throws -> [String: Any] {
        let data = try XCTUnwrap(lock.withLock { frame })
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data.dropLast()) as? [String: Any])
    }
}
