import Foundation
import XCTest
@testable import AgentjailApprovalCore

final class ActivityControlClientTests: XCTestCase {
    func testNetworkRequestIsReadOnlyVersionedAndResponseIsTyped() async throws {
        let token = String(repeating: "n", count: 64)
        let transport = ActivityRecordingTransport(reply: networkFrame())

        let snapshot = try await ActivityControlClient(
            tokenLoader: ActivityTokenLoader(token: token),
            transport: transport
        ).fetchNetwork()

        XCTAssertTrue(snapshot.available)
        XCTAssertEqual(snapshot.events.first?.host, "api.example.com")
        XCTAssertEqual(snapshot.events.first?.path, "/v1/models")
        let request = try transport.request()
        XCTAssertEqual(Set(request.keys), ["type", "ctl_token", "protocol_version"])
        XCTAssertEqual(request["type"] as? String, "network_snapshot")
        XCTAssertEqual(request["protocol_version"] as? Int, 1)
    }

    func testSessionRequestCarriesExactSessionAndResponseIsTyped() async throws {
        let token = String(repeating: "s", count: 64)
        let transport = ActivityRecordingTransport(reply: sessionFrame())

        let snapshot = try await ActivityControlClient(
            tokenLoader: ActivityTokenLoader(token: token),
            transport: transport
        ).fetchSessionLog(sessionID: "session-1")

        XCTAssertEqual(snapshot.selectedSessionID, "session-1")
        XCTAssertEqual(snapshot.entries.first?.toolName, "Bash")
        XCTAssertEqual(snapshot.entries.first?.finalAction, "deny")
        let request = try transport.request()
        XCTAssertEqual(Set(request.keys), ["type", "ctl_token", "protocol_version", "session_id"])
        XCTAssertEqual(request["type"] as? String, "session_log_snapshot")
        XCTAssertEqual(request["session_id"] as? String, "session-1")
    }

    func testActionDetailRequestCarriesExactSelectorsAndReturnsRedactedCommand() async throws {
        let token = String(repeating: "d", count: 64)
        let transport = ActivityRecordingTransport(reply: detailFrame())

        let detail = try await ActivityControlClient(
            tokenLoader: ActivityTokenLoader(token: token),
            transport: transport
        ).fetchSessionActionDetail(sessionID: "session-1", actionID: 11)

        XCTAssertEqual(detail.command, "git status --short")
        let request = try transport.request()
        XCTAssertEqual(Set(request.keys), ["type", "ctl_token", "protocol_version", "session_id", "action_id"])
        XCTAssertEqual(request["type"] as? String, "session_action_detail")
        XCTAssertEqual(request["session_id"] as? String, "session-1")
        XCTAssertEqual(request["action_id"] as? Int, 11)
    }

    func testMalformedProjectionAndSecretBearingFailureAreSafe() async throws {
        let token = String(repeating: "x", count: 64)
        let malformed = Data("{\"ok\":true,\"network_snapshot\":{\"protocol_version\":1}}\n".utf8)
        do {
            _ = try await ActivityControlClient(
                tokenLoader: ActivityTokenLoader(token: token),
                transport: ActivityRecordingTransport(reply: malformed)
            ).fetchNetwork()
            XCTFail("expected malformed projection")
        } catch let error as ApprovalControlError {
            XCTAssertEqual(error, .malformedReply)
        }

        let refused = Data("{\"ok\":false,\"error\":\"failed \(token)\"}\n".utf8)
        do {
            _ = try await ActivityControlClient(
                tokenLoader: ActivityTokenLoader(token: token),
                transport: ActivityRecordingTransport(reply: refused)
            ).fetchNetwork()
            XCTFail("expected refusal")
        } catch let error as ApprovalControlError {
            XCTAssertEqual(error, .serverRefused("failed [redacted]"))
            XCTAssertFalse(String(describing: error).contains(token))
        }
    }

    private func networkFrame() -> Data {
        Data("""
        {"ok":true,"network_snapshot":{"protocol_version":1,"generated_at_unix_ms":1788020000000,"available":true,"events":[{"id":9,"timestamp_unix_ms":1788020000000,"host":"api.example.com","method":"GET","path":"/v1/models","status_code":200,"request_size":12,"response_size":42,"elapsed_ms":18,"session_id":"session-1","agent":"Codex","project":"agentjail","tool_name":"WebFetch","policy_action":"allow"}]}}
        """.utf8) + Data([10])
    }

    private func sessionFrame() -> Data {
        Data("""
        {"ok":true,"session_log_snapshot":{"protocol_version":1,"generated_at_unix_ms":1788020000000,"selected_session_id":"session-1","sessions":[{"session_id":"session-1","agent":"Codex","project":"agentjail","started_at_unix_ms":1788010000000,"audited_calls":1,"active":true}],"entries":[{"id":11,"timestamp_unix_ms":1788020000000,"tool_name":"Bash","summary":"blocked destructive command","action":"deny","rule_id":"command_policy/no-rm-rf","reason":"protected path","elapsed_us":210,"final_action":"deny"}],"truncated":false}}
        """.utf8) + Data([10])
    }

    private func detailFrame() -> Data {
        Data("""
        {"ok":true,"session_action_detail":{"protocol_version":1,"action_id":11,"session_id":"session-1","command":"git status --short"}}
        """.utf8) + Data([10])
    }
}

private struct ActivityTokenLoader: ControlTokenLoading {
    let token: String
    func loadToken() throws -> String { token }
}

private final class ActivityRecordingTransport: ControlFraming, @unchecked Sendable {
    private let reply: Data
    private let lock = NSLock()
    private var frame: Data?

    init(reply: Data) { self.reply = reply }

    func roundTrip(_ frame: Data) async throws -> Data {
        lock.withLock { self.frame = frame }
        return reply
    }

    func request() throws -> [String: Any] {
        let data = try XCTUnwrap(lock.withLock { frame })
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data.dropLast()) as? [String: Any])
    }
}
