import Darwin
import Foundation
import XCTest
@testable import AgentjailApprovalCore

final class UnixControlTransportTests: XCTestCase {
    func testPartialResponseAndWriteThenCloseReturnFirstFrame() async throws {
        let server = try FakeUnixServer(chunks: [Data("{\"ok\":".utf8), Data("true}\n{\"ok\":false}\n".utf8)])
        defer { server.cleanUp() }
        let reply = try await UnixControlTransport(socketPath: server.path, timeout: 1).roundTrip(Data("{\"type\":\"review_snapshot\"}\n".utf8))
        XCTAssertEqual(reply, Data("{\"ok\":true}\n".utf8))
        XCTAssertEqual(try server.request(), Data("{\"type\":\"review_snapshot\"}\n".utf8))
    }

    func testExactLimitIsAcceptedAndMaxPlusOneIsRejectedWithoutOverAllocation() async throws {
        let exact = exactJSONFrame(length: UnixControlTransport.maximumFrameBytes)
        let exactServer = try FakeUnixServer(chunks: [exact])
        defer { exactServer.cleanUp() }
        let exactReply = try await UnixControlTransport(socketPath: exactServer.path, timeout: 1).roundTrip(Data("{}\n".utf8))
        XCTAssertEqual(exactReply.count, UnixControlTransport.maximumFrameBytes)

        let tooLarge = exactJSONFrame(length: UnixControlTransport.maximumFrameBytes + 1)
        let largeServer = try FakeUnixServer(chunks: [tooLarge])
        defer { largeServer.cleanUp() }
        do { _ = try await UnixControlTransport(socketPath: largeServer.path, timeout: 1).roundTrip(Data("{}\n".utf8)); XCTFail("expected oversize") } catch { XCTAssertEqual(error as? ApprovalControlError, .oversizedReply) }
    }

    func testMissingDelimiterTrailingJunkAndTimeoutAreTyped() async throws {
        let junk = try FakeUnixServer(chunks: [Data("{\"ok\":true}junk\n".utf8)])
        defer { junk.cleanUp() }
        do { _ = try await UnixControlTransport(socketPath: junk.path, timeout: 1).roundTrip(Data("{}\n".utf8)); XCTFail("expected malformed") } catch { XCTAssertEqual(error as? ApprovalControlError, .malformedReply) }

        let secondValue = try FakeUnixServer(chunks: [Data("{\"ok\":true} {\"ok\":false}\n".utf8)])
        defer { secondValue.cleanUp() }
        do { _ = try await UnixControlTransport(socketPath: secondValue.path, timeout: 1).roundTrip(Data("{}\n".utf8)); XCTFail("expected malformed") } catch { XCTAssertEqual(error as? ApprovalControlError, .malformedReply) }

        let padded = try FakeUnixServer(chunks: [Data("{\"ok\":true} \t\r\n".utf8)])
        defer { padded.cleanUp() }
        let paddedReply = try await UnixControlTransport(socketPath: padded.path, timeout: 1).roundTrip(Data("{}\n".utf8))
        XCTAssertEqual(paddedReply, Data("{\"ok\":true} \t\r\n".utf8))

        let invalidUTF8 = try FakeUnixServer(chunks: [Data([0x7B, 0xFF, 0x7D, 0x0A])])
        defer { invalidUTF8.cleanUp() }
        do { _ = try await UnixControlTransport(socketPath: invalidUTF8.path, timeout: 1).roundTrip(Data("{}\n".utf8)); XCTFail("expected malformed") } catch { XCTAssertEqual(error as? ApprovalControlError, .malformedReply) }

        let stalled = try FakeUnixServer(chunks: [], waitForClientClose: true)
        defer { stalled.cleanUp() }
        do { _ = try await UnixControlTransport(socketPath: stalled.path, timeout: 0.02).roundTrip(Data("{}\n".utf8)); XCTFail("expected timeout") } catch { XCTAssertEqual(error as? ApprovalControlError, .timeout) }
    }

    func testHUPOnlyAfterIncompleteFrameIsMalformedReply() async throws {
        let server = try FakeUnixServer(chunks: [Data("{\"ok\":true}".utf8)])
        defer { server.cleanUp() }
        do {
            _ = try await UnixControlTransport(socketPath: server.path, timeout: 1).roundTrip(Data("{}\n".utf8))
            XCTFail("expected malformed reply")
        } catch {
            XCTAssertEqual(error as? ApprovalControlError, .malformedReply)
        }
    }

    func testInvalidSocketPathIsRejectedBeforeConnecting() async {
        let path = String(repeating: "x", count: 200)
        do { _ = try await UnixControlTransport(socketPath: path).roundTrip(Data("{}\n".utf8)); XCTFail("expected invalid path") } catch { XCTAssertEqual(error as? ApprovalControlError, .invalidSocketPath) }
    }

    func testHUPOnlyIsReadReadyButNotWriteReady() {
        XCTAssertTrue(UnixControlTransport.shouldReadAfterPoll(Int16(POLLHUP)))
        XCTAssertTrue(UnixControlTransport.shouldReadAfterPoll(Int16(POLLIN | POLLHUP)))
        XCTAssertFalse(UnixControlTransport.shouldReadAfterPoll(Int16(POLLOUT)))
    }

    func testNonFiniteZeroAndHugeTimeoutsFailWithoutIntegerConversion() async {
        for timeout in [0, -1, Double.nan, Double.infinity, Double.greatestFiniteMagnitude] {
            do { _ = try await UnixControlTransport(socketPath: "/private/tmp/unused.sock", timeout: timeout).roundTrip(Data("{}\n".utf8)); XCTFail("expected timeout") } catch { XCTAssertEqual(error as? ApprovalControlError, .timeout) }
        }
    }

    func testCancellationShutsDownSocketAndUnblocksServer() async throws {
        let server = try FakeUnixServer(chunks: [], waitForClientClose: true)
        defer { server.cleanUp() }
        let request = Task {
            try await UnixControlTransport(socketPath: server.path, timeout: 3).roundTrip(Data("{}\n".utf8))
        }
        XCTAssertEqual(try server.request(), Data("{}\n".utf8))

        request.cancel()
        do {
            _ = try await request.value
            XCTFail("expected cancellation")
        } catch is CancellationError {
        }
        XCTAssertTrue(server.waitForFinish())
    }

    func testSocketOwnershipSerializesShutdownCloseAndRejectsLateRegistration() throws {
        let shutdownStarted = DispatchSemaphore(value: 0)
        let finishShutdown = DispatchSemaphore(value: 0)
        let closeFinished = DispatchSemaphore(value: 0)
        let cancellationFinished = DispatchSemaphore(value: 0)
        let eventsLock = NSLock()
        var events: [String] = []
        let ownership = SocketOwnership(
            shutdown: { descriptor in
                shutdownStarted.signal()
                _ = finishShutdown.wait(timeout: .distantFuture)
                eventsLock.withLock { events.append("shutdown \(descriptor)") }
                return 0
            },
            close: { descriptor in
                eventsLock.withLock { events.append("close \(descriptor)") }
                return 0
            }
        )
        try ownership.register(41)
        DispatchQueue.global(qos: .userInitiated).async {
            ownership.cancel()
            cancellationFinished.signal()
        }
        XCTAssertEqual(shutdownStarted.wait(timeout: .now() + 1), .success)
        DispatchQueue.global(qos: .userInitiated).async {
            ownership.close(41)
            closeFinished.signal()
        }
        XCTAssertEqual(closeFinished.wait(timeout: .now() + .milliseconds(20)), .timedOut)
        finishShutdown.signal()
        XCTAssertEqual(cancellationFinished.wait(timeout: .now() + 1), .success)
        XCTAssertEqual(closeFinished.wait(timeout: .now() + 1), .success)
        XCTAssertEqual(eventsLock.withLock { events }, ["shutdown 41", "close 41"])

        XCTAssertThrowsError(try ownership.register(42)) { error in
            XCTAssertTrue(error is CancellationError)
        }
        XCTAssertEqual(eventsLock.withLock { events }, ["shutdown 41", "close 41", "close 42"])
    }

    private func exactJSONFrame(length: Int) -> Data {
        let prefix = "{\"ok\":true,\"padding\":\""
        let suffix = "\"}\n"
        return Data((prefix + String(repeating: "a", count: length - prefix.utf8.count - suffix.utf8.count) + suffix).utf8)
    }
}

private final class FakeUnixServer: @unchecked Sendable {
    let path: String
    private let descriptor: Int32
    private let finished = DispatchSemaphore(value: 0)
    private let requestReceived = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var received = Data()
    private var cleanedUp = false
    private var didFinish = false

    init(chunks: [Data], waitForClientClose: Bool = false) throws {
        let directory = URL(fileURLWithPath: "/private/tmp/agentjail-approval-socket-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        path = directory.appendingPathComponent("control.sock").path
        descriptor = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw ApprovalControlError.daemonUnavailable }
        do {
            var address = sockaddr_un()
            address.sun_family = sa_family_t(AF_UNIX)
            withUnsafeMutableBytes(of: &address.sun_path) { destination in
                path.withCString { source in destination.copyBytes(from: UnsafeRawBufferPointer(start: source, count: path.utf8.count + 1)) }
            }
            let result = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            guard result == 0, Darwin.listen(descriptor, 1) == 0 else { throw ApprovalControlError.daemonUnavailable }
        } catch {
            Darwin.close(descriptor)
            try? FileManager.default.removeItem(at: directory)
            throw error
        }
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            defer { finished.signal() }
            let connection = Darwin.accept(descriptor, nil, nil)
            guard connection >= 0 else { return }
            defer { Darwin.close(connection) }
            var buffer = [UInt8](repeating: 0, count: 256)
            while true {
                let count = Darwin.read(connection, &buffer, buffer.count)
                if count <= 0 { return }
                lock.lock()
                received.append(buffer, count: count)
                let complete = received.contains(10)
                lock.unlock()
                if complete {
                    requestReceived.signal()
                    break
                }
            }
            if waitForClientClose {
                while Darwin.read(connection, &buffer, buffer.count) > 0 {}
                return
            }
            for chunk in chunks { writeAll(chunk, descriptor: connection) }
        }
    }

    deinit {
        cleanUp()
    }

    func cleanUp() {
        lock.lock()
        if cleanedUp {
            lock.unlock()
            return
        }
        cleanedUp = true
        lock.unlock()
        Darwin.close(descriptor)
        waitForFinish()
        try? FileManager.default.removeItem(at: URL(fileURLWithPath: path).deletingLastPathComponent())
    }

    func request() throws -> Data {
        guard requestReceived.wait(timeout: .now() + 1) == .success else { throw ApprovalControlError.timeout }
        return lock.withLock { received }
    }

    @discardableResult
    func waitForFinish() -> Bool {
        lock.lock()
        let shouldWait = !didFinish
        lock.unlock()
        guard shouldWait else { return true }
        let completed = finished.wait(timeout: .now() + 1) == .success
        if completed { lock.withLock { didFinish = true } }
        return completed
    }

    private func writeAll(_ data: Data, descriptor: Int32) {
        data.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            var offset = 0
            while offset < data.count {
                let count = Darwin.write(descriptor, base.advanced(by: offset), data.count - offset)
                if count <= 0 { return }
                offset += count
            }
        }
    }
}
