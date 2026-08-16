import Darwin
import Foundation
import XCTest
@testable import AgentjailApprovalCore

final class UnixControlTransportTests: XCTestCase {
    func testPartialResponseAndWriteThenCloseReturnFirstFrame() throws {
        let server = try FakeUnixServer(chunks: [Data("{\"ok\":".utf8), Data("true}\n{\"ok\":false}\n".utf8)])
        defer { server.cleanUp() }
        let reply = try UnixControlTransport(socketPath: server.path, timeout: 1).roundTrip(Data("{\"type\":\"review_snapshot\"}\n".utf8))
        XCTAssertEqual(reply, Data("{\"ok\":true}\n".utf8))
        XCTAssertEqual(try server.request(), Data("{\"type\":\"review_snapshot\"}\n".utf8))
    }

    func testExactLimitIsAcceptedAndMaxPlusOneIsRejectedWithoutOverAllocation() throws {
        let exact = exactJSONFrame(length: UnixControlTransport.maximumFrameBytes)
        let exactServer = try FakeUnixServer(chunks: [exact])
        defer { exactServer.cleanUp() }
        XCTAssertEqual(try UnixControlTransport(socketPath: exactServer.path, timeout: 1).roundTrip(Data("{}\n".utf8)).count, UnixControlTransport.maximumFrameBytes)

        let tooLarge = exactJSONFrame(length: UnixControlTransport.maximumFrameBytes + 1)
        let largeServer = try FakeUnixServer(chunks: [tooLarge])
        defer { largeServer.cleanUp() }
        XCTAssertThrowsError(try UnixControlTransport(socketPath: largeServer.path, timeout: 1).roundTrip(Data("{}\n".utf8))) {
            XCTAssertEqual($0 as? ApprovalControlError, .oversizedReply)
        }
    }

    func testMissingDelimiterTrailingJunkAndTimeoutAreTyped() throws {
        let missing = try FakeUnixServer(chunks: [Data("{\"ok\":true}".utf8)])
        defer { missing.cleanUp() }
        XCTAssertThrowsError(try UnixControlTransport(socketPath: missing.path, timeout: 1).roundTrip(Data("{}\n".utf8))) {
            XCTAssertEqual($0 as? ApprovalControlError, .malformedReply)
        }

        let junk = try FakeUnixServer(chunks: [Data("{\"ok\":true}junk\n".utf8)])
        defer { junk.cleanUp() }
        XCTAssertThrowsError(try UnixControlTransport(socketPath: junk.path, timeout: 1).roundTrip(Data("{}\n".utf8))) {
            XCTAssertEqual($0 as? ApprovalControlError, .malformedReply)
        }

        let secondValue = try FakeUnixServer(chunks: [Data("{\"ok\":true} {\"ok\":false}\n".utf8)])
        defer { secondValue.cleanUp() }
        XCTAssertThrowsError(try UnixControlTransport(socketPath: secondValue.path, timeout: 1).roundTrip(Data("{}\n".utf8))) {
            XCTAssertEqual($0 as? ApprovalControlError, .malformedReply)
        }

        let padded = try FakeUnixServer(chunks: [Data("{\"ok\":true} \t\r\n".utf8)])
        defer { padded.cleanUp() }
        XCTAssertEqual(try UnixControlTransport(socketPath: padded.path, timeout: 1).roundTrip(Data("{}\n".utf8)), Data("{\"ok\":true} \t\r\n".utf8))

        let invalidUTF8 = try FakeUnixServer(chunks: [Data([0x7B, 0xFF, 0x7D, 0x0A])])
        defer { invalidUTF8.cleanUp() }
        XCTAssertThrowsError(try UnixControlTransport(socketPath: invalidUTF8.path, timeout: 1).roundTrip(Data("{}\n".utf8))) {
            XCTAssertEqual($0 as? ApprovalControlError, .malformedReply)
        }

        let stalled = try FakeUnixServer(chunks: [], holdOpen: true)
        defer { stalled.cleanUp() }
        XCTAssertThrowsError(try UnixControlTransport(socketPath: stalled.path, timeout: 0.02).roundTrip(Data("{}\n".utf8))) {
            XCTAssertEqual($0 as? ApprovalControlError, .timeout)
        }
    }

    func testInvalidSocketPathIsRejectedBeforeConnecting() {
        let path = String(repeating: "x", count: 200)
        XCTAssertThrowsError(try UnixControlTransport(socketPath: path).roundTrip(Data("{}\n".utf8))) {
            XCTAssertEqual($0 as? ApprovalControlError, .invalidSocketPath)
        }
    }

    func testNonFiniteZeroAndHugeTimeoutsFailWithoutIntegerConversion() {
        for timeout in [0, -1, Double.nan, Double.infinity, Double.greatestFiniteMagnitude] {
            XCTAssertThrowsError(try UnixControlTransport(socketPath: "/private/tmp/unused.sock", timeout: timeout).roundTrip(Data("{}\n".utf8))) {
                XCTAssertEqual($0 as? ApprovalControlError, .timeout)
            }
        }
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
    private let lock = NSLock()
    private var received = Data()
    private var cleanedUp = false
    private var didFinish = false

    init(chunks: [Data], holdOpen: Bool = false) throws {
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
                if complete { break }
            }
            if holdOpen {
                Thread.sleep(forTimeInterval: 0.2)
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
        waitForFinish()
        return lock.withLock { received }
    }

    private func waitForFinish() {
        lock.lock()
        let shouldWait = !didFinish
        lock.unlock()
        guard shouldWait else { return }
        _ = finished.wait(timeout: .now() + 1)
        lock.withLock { didFinish = true }
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
