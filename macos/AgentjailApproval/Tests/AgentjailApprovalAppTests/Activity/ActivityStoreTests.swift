import AgentjailApprovalCore
import Foundation
import XCTest
@testable import AgentjailApprovalApp

@MainActor
final class ActivityStoreTests: XCTestCase {
    func testRefreshesNetworkAndExactSelectedSession() async throws {
        let client = ActivityScriptedClient(
            network: try networkSnapshot(),
            sessions: [try sessionSnapshot(id: "session-1")]
        )
        let store = ActivityStore(client: client)

        await store.refreshNetwork()
        store.startLogPolling(sessionID: "session-1")
        for _ in 0..<20 where store.sessionLogSnapshot == nil { await Task.yield() }
        store.stopLogPolling()

        XCTAssertEqual(store.networkSnapshot?.events.first?.host, "api.example.com")
        XCTAssertEqual(store.sessionLogSnapshot?.selectedSessionID, "session-1")
        XCTAssertFalse(store.networkUnavailable)
        XCTAssertFalse(store.logsUnavailable)
        let requestedSessions = await client.requestedSessions()
        XCTAssertEqual(requestedSessions, ["session-1"])
    }

    func testFailedInitialFeedsBecomeUnavailable() async {
        let store = ActivityStore(client: FailingActivityClient())

        await store.refreshNetwork()
        await store.refreshLogs()

        XCTAssertTrue(store.networkUnavailable)
        XCTAssertTrue(store.logsUnavailable)
    }

    func testSessionSelectionPublishesImmediatelyAndLoadsThatExactSession() async throws {
        let client = ActivityScriptedClient(
            network: try networkSnapshot(),
            sessions: [try sessionSnapshot(id: "session-1"), try sessionSnapshot(id: "session-2")]
        )
        let store = ActivityStore(client: client)
        store.startLogPolling(sessionID: "session-1")
        for _ in 0..<20 where store.sessionLogSnapshot?.selectedSessionID != "session-1" { await Task.yield() }

        store.selectSession("session-2")
        XCTAssertEqual(store.selectedSessionID, "session-2")
        for _ in 0..<20 where store.sessionLogSnapshot?.selectedSessionID != "session-2" { await Task.yield() }
        store.stopLogPolling()

        XCTAssertEqual(store.sessionLogSnapshot?.selectedSessionID, "session-2")
        let requestedSessions = await client.requestedSessions()
        XCTAssertTrue(requestedSessions.contains("session-2"))
    }

    func testSlowCancelledSessionCannotBlockOrReplaceNewSelection() async throws {
        let client = SwitchingActivityClient(network: try networkSnapshot())
        let store = ActivityStore(client: client)
        store.startLogPolling(sessionID: "session-1")
        for _ in 0..<100 where !(await client.hasRequest("session-1")) { await Task.yield() }
        let requestedFirstSession = await client.hasRequest("session-1")
        XCTAssertTrue(requestedFirstSession)

        store.selectSession("session-2")
        for _ in 0..<100 where !(await client.hasRequest("session-2")) { await Task.yield() }
        let requestedSecondSession = await client.hasRequest("session-2")
        XCTAssertTrue(requestedSecondSession)
        await client.resolve(try sessionSnapshot(id: "session-2"))
        for _ in 0..<100 where store.sessionLogSnapshot?.selectedSessionID != "session-2" { await Task.yield() }
        XCTAssertEqual(store.sessionLogSnapshot?.selectedSessionID, "session-2")

        await client.resolve(try sessionSnapshot(id: "session-1"))
        for _ in 0..<20 { await Task.yield() }
        store.stopLogPolling()
        XCTAssertEqual(store.sessionLogSnapshot?.selectedSessionID, "session-2")
    }

    func testOpeningActionLoadsExactDetailForSelectedSession() async throws {
        let snapshot = try sessionSnapshot(id: "session-1")
        let client = ActivityScriptedClient(network: try networkSnapshot(), sessions: [snapshot])
        let store = ActivityStore(client: client)
        store.startLogPolling(sessionID: "session-1")
        for _ in 0..<20 where store.sessionLogSnapshot == nil { await Task.yield() }
        store.stopLogPolling()
        let entry = try XCTUnwrap(store.sessionLogSnapshot?.entries.first)

        await store.loadActionDetail(entry)

        XCTAssertEqual(store.actionDetail?.command, "git status --short")
        let requests = await client.requestedDetails()
        XCTAssertEqual(requests.count, 1)
        XCTAssertEqual(requests.first?.sessionID, "session-1")
        XCTAssertEqual(requests.first?.actionID, entry.id)
    }

    private func networkSnapshot() throws -> NetworkSnapshotV1 {
        try JSONDecoder().decode(NetworkSnapshotV1.self, from: Data("""
        {"protocol_version":1,"generated_at_unix_ms":1788020000000,"available":true,"events":[{"id":9,"timestamp_unix_ms":1788020000000,"host":"api.example.com","method":"GET","path":"/v1/models","status_code":200,"request_size":12,"response_size":42,"elapsed_ms":18}]}
        """.utf8))
    }

    private func sessionSnapshot(id: String) throws -> SessionLogSnapshotV1 {
        try JSONDecoder().decode(SessionLogSnapshotV1.self, from: Data("""
        {"protocol_version":1,"generated_at_unix_ms":1788020000000,"selected_session_id":"\(id)","sessions":[{"session_id":"\(id)","agent":"Codex","project":"agentjail","started_at_unix_ms":1788010000000,"audited_calls":1,"active":true}],"entries":[{"id":11,"timestamp_unix_ms":1788020000000,"tool_name":"Bash","action":"allow","elapsed_us":210}]}
        """.utf8))
    }
}

private actor ActivityScriptedClient: ActivityControlling {
    let network: NetworkSnapshotV1
    var sessions: [SessionLogSnapshotV1]
    var requested: [String] = []
    var details: [(sessionID: String, actionID: Int64)] = []

    init(network: NetworkSnapshotV1, sessions: [SessionLogSnapshotV1]) {
        self.network = network
        self.sessions = sessions
    }

    func fetchNetwork() async throws -> NetworkSnapshotV1 { network }

    func fetchSessionLog(sessionID: String?) async throws -> SessionLogSnapshotV1 {
        requested.append(sessionID ?? "")
        return sessions.first(where: { $0.selectedSessionID == sessionID }) ?? sessions[0]
    }

    func requestedSessions() -> [String] { requested }

    func fetchSessionActionDetail(sessionID: String, actionID: Int64) async throws -> SessionActionDetailV1 {
        details.append((sessionID, actionID))
        return try JSONDecoder().decode(SessionActionDetailV1.self, from: Data("""
        {"protocol_version":1,"action_id":\(actionID),"session_id":"\(sessionID)","command":"git status --short"}
        """.utf8))
    }

    func requestedDetails() -> [(sessionID: String, actionID: Int64)] { details }
}

private struct FailingActivityClient: ActivityControlling {
    func fetchNetwork() async throws -> NetworkSnapshotV1 { throw ActivityTestError.failed }
    func fetchSessionLog(sessionID: String?) async throws -> SessionLogSnapshotV1 { throw ActivityTestError.failed }
    func fetchSessionActionDetail(sessionID: String, actionID: Int64) async throws -> SessionActionDetailV1 {
        throw ActivityTestError.failed
    }
}

private actor SwitchingActivityClient: ActivityControlling {
    let network: NetworkSnapshotV1
    private var pending: [String: CheckedContinuation<SessionLogSnapshotV1, Never>] = [:]

    init(network: NetworkSnapshotV1) { self.network = network }

    func fetchNetwork() async throws -> NetworkSnapshotV1 { network }

    func fetchSessionLog(sessionID: String?) async throws -> SessionLogSnapshotV1 {
        await withCheckedContinuation { continuation in
            pending[sessionID ?? ""] = continuation
        }
    }

    func fetchSessionActionDetail(sessionID: String, actionID: Int64) async throws -> SessionActionDetailV1 {
        throw ActivityTestError.failed
    }

    func hasRequest(_ sessionID: String) -> Bool { pending[sessionID] != nil }

    func resolve(_ snapshot: SessionLogSnapshotV1) {
        pending.removeValue(forKey: snapshot.selectedSessionID)?.resume(returning: snapshot)
    }
}

private enum ActivityTestError: Error { case failed }
