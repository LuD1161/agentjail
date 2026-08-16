import Foundation
import XCTest
@testable import AgentjailApprovalCore

final class ReviewControlClientTests: XCTestCase {
    func testSnapshotUsesFreshTokenAndExplicitVersion() async throws {
        let loader = RotatingTokenLoader(tokens: [String(repeating: "a", count: 64)])
        let transport = RecordingTransport(reply: try fixtureFrame())
        let client = ReviewControlClient(tokenLoader: loader, transport: transport)

        let snapshot = try await client.fetchSnapshot()

        XCTAssertEqual(snapshot.reviews.count, 3)
        XCTAssertEqual(loader.calls, 1)
        let request = try transport.request()
        XCTAssertEqual(request["type"] as? String, "review_snapshot")
        XCTAssertEqual(request["protocol_version"] as? Int, 1)
        XCTAssertEqual(request["ctl_token"] as? String, String(repeating: "a", count: 64))
    }

    func testMutationsContainOnlyIdentityAndAreNotRetried() async throws {
        let id = try ReviewID(rawValue: "review-verified-001")
        let loader = RotatingTokenLoader(tokens: [String(repeating: "a", count: 64), String(repeating: "b", count: 64)])
        let transport = RecordingTransport(reply: Data("{\"ok\":true}\n".utf8))
        let client = ReviewControlClient(tokenLoader: loader, transport: transport)

        try await client.approve(id)
        let approve = try transport.request()
        XCTAssertEqual(Set(approve.keys), ["type", "ctl_token", "grant_id"])
        XCTAssertEqual(approve["type"] as? String, "grant_approve")
        XCTAssertEqual(approve["grant_id"] as? String, id.rawValue)

        try await client.deny(id)
        XCTAssertEqual(loader.calls, 2)
        XCTAssertEqual(transport.calls, 2)
        let deny = try transport.request(at: 1)
        XCTAssertEqual(deny["type"] as? String, "grant_deny")
        XCTAssertEqual(deny["ctl_token"] as? String, String(repeating: "b", count: 64))
    }

    func testTypedFailuresDoNotContainToken() async throws {
        let token = String(repeating: "c", count: 64)
        let client = ReviewControlClient(tokenLoader: RotatingTokenLoader(tokens: [token]), transport: RecordingTransport(reply: Data("{\"ok\":false,\"error\":\"unauthorized \(token)\"}\n".utf8)))
        do {
            _ = try await client.fetchSnapshot()
            XCTFail("expected unauthorized")
        } catch let error as ApprovalControlError {
            XCTAssertEqual(error, .serverRefused("unauthorized [redacted]"))
            XCTAssertFalse(String(describing: error).contains(token))
        }
    }

    @MainActor
    func testMainActorCallerRunsTokenAndSocketWorkOffMainThread() async throws {
        let loader = ThreadRecordingTokenLoader(token: String(repeating: "e", count: 64))
        let transport = ThreadRecordingTransport(reply: try fixtureFrame())
        let client = ReviewControlClient(tokenLoader: loader, transport: transport)
        _ = try await client.fetchSnapshot()
        XCTAssertFalse(loader.wasCalledOnMainThread)
        XCTAssertFalse(transport.wasCalledOnMainThread)
    }

    func testUnexpectedLoaderAndTransportErrorsBecomeTokenFreeTypedFailures() async throws {
        let token = String(repeating: "f", count: 64)
        let loaderClient = ReviewControlClient(tokenLoader: ThrowingTokenLoader(error: LeakyError(value: token)), transport: RecordingTransport(reply: Data()))
        do {
            _ = try await loaderClient.fetchSnapshot()
            XCTFail("expected loader failure")
        } catch let error as ApprovalControlError {
            XCTAssertEqual(error, .tokenUnreadable)
            XCTAssertFalse(String(describing: error).contains(token))
        }

        let transportClient = ReviewControlClient(tokenLoader: RotatingTokenLoader(tokens: [token]), transport: ThrowingTransport(error: LeakyError(value: token)))
        do {
            _ = try await transportClient.fetchSnapshot()
            XCTFail("expected transport failure")
        } catch let error as ApprovalControlError {
            XCTAssertEqual(error, .daemonUnavailable)
            XCTAssertFalse(String(describing: error).contains(token))
        }
    }

    func testFileTokenLoaderRejectsMissingInvalidAndAcceptsTrimmedLowerHex() throws {
        let root = URL(fileURLWithPath: "/private/tmp/agentjail-approval-token-tests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root.deletingLastPathComponent(), withIntermediateDirectories: true)
        let loader = FileControlTokenLoader(path: root)
        XCTAssertThrowsError(try loader.loadToken()) { XCTAssertEqual($0 as? ApprovalControlError, .tokenMissing) }
        try Data("ABC\n".utf8).write(to: root)
        XCTAssertThrowsError(try loader.loadToken()) { XCTAssertEqual($0 as? ApprovalControlError, .tokenUnreadable) }
        let valid = String(repeating: "d", count: 64)
        try Data(("  \(valid)\n").utf8).write(to: root)
        XCTAssertEqual(try loader.loadToken(), valid)
    }

    private func fixtureFrame() throws -> Data {
        let fixture = try Data(contentsOf: fixtureURL())
        return fixture.last == 10 ? fixture : fixture + Data([10])
    }

    private func fixtureURL() -> URL {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        return url.appendingPathComponent("internal/grantctl/testdata/review_snapshot_v1.json")
    }
}

private final class RotatingTokenLoader: ControlTokenLoading, @unchecked Sendable {
    private let lock = NSLock()
    private var tokens: [String]
    private(set) var calls = 0

    init(tokens: [String]) { self.tokens = tokens }

    func loadToken() throws -> String {
        lock.lock()
        defer { lock.unlock() }
        let index = min(calls, tokens.count - 1)
        calls += 1
        return tokens[index]
    }
}

private final class RecordingTransport: ControlFraming, @unchecked Sendable {
    private let lock = NSLock()
    private let reply: Data
    private var frames: [Data] = []

    init(reply: Data) { self.reply = reply }

    var calls: Int { lock.withLock { frames.count } }

    func roundTrip(_ frame: Data) throws -> Data {
        lock.lock()
        frames.append(frame)
        lock.unlock()
        return reply
    }

    func request(at index: Int = 0) throws -> [String: Any] {
        let frame = lock.withLock { frames[index] }
        return try XCTUnwrap(JSONSerialization.jsonObject(with: frame.dropLast()) as? [String: Any])
    }
}

private final class ThreadRecordingTokenLoader: ControlTokenLoading, @unchecked Sendable {
    private let token: String
    private let lock = NSLock()
    private var calledOnMainThread = true

    init(token: String) { self.token = token }
    var wasCalledOnMainThread: Bool { lock.withLock { calledOnMainThread } }
    func loadToken() throws -> String {
        lock.withLock { calledOnMainThread = Thread.isMainThread }
        return token
    }
}

private final class ThreadRecordingTransport: ControlFraming, @unchecked Sendable {
    private let reply: Data
    private let lock = NSLock()
    private var calledOnMainThread = true

    init(reply: Data) { self.reply = reply }
    var wasCalledOnMainThread: Bool { lock.withLock { calledOnMainThread } }
    func roundTrip(_ frame: Data) throws -> Data {
        lock.withLock { calledOnMainThread = Thread.isMainThread }
        return reply
    }
}

private struct LeakyError: Error, CustomStringConvertible, Sendable {
    let value: String
    var description: String { value }
}

private struct ThrowingTokenLoader: ControlTokenLoading {
    let error: LeakyError
    func loadToken() throws -> String { throw error }
}

private struct ThrowingTransport: ControlFraming {
    let error: LeakyError
    func roundTrip(_ frame: Data) throws -> Data { throw error }
}
