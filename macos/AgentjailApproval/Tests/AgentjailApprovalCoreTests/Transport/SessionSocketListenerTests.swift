import Darwin
import Foundation
import Testing
@testable import AgentjailApprovalCore

struct SessionSocketListenerTests {
    @Test func repeatedStartStopKeepsNewGenerationReachable() throws {
        let path = "/tmp/aj-listener-\(UUID().uuidString).sock"
        let listener = SessionSocketListener()
        defer { listener.stop() }
        for generation in 0..<40 {
            try listener.start(path: path) { fd in
                defer { Darwin.close(fd) }
                var value = UInt8(generation)
                _ = Darwin.write(fd, &value, 1)
            }
            let client = try connect(path)
            var timeout = timeval(tv_sec: 2, tv_usec: 0)
            _ = setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
            var value: UInt8 = 255
            let count = Darwin.read(client, &value, 1)
            Darwin.close(client)
            #expect(count == 1)
            #expect(value == UInt8(generation))
            listener.stop()
            #expect(!FileManager.default.fileExists(atPath: path))
            listener.stop()
        }
    }

    @Test func rejectsOverlongSocketPath() {
        let listener = SessionSocketListener()
        #expect(throws: (any Error).self) {
            try listener.start(path: "/tmp/" + String(repeating: "a", count: 200)) { Darwin.close($0) }
        }
        listener.stop()
    }

    private func connect(_ path: String) throws -> Int32 {
        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = path.utf8CString
        withUnsafeMutablePointer(to: &address.sun_path) {
            $0.withMemoryRebound(to: CChar.self, capacity: bytes.count) { destination in
                for (index, byte) in bytes.enumerated() { destination[index] = byte }
            }
        }
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 else {
            let code = errno
            Darwin.close(fd)
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(code))
        }
        return fd
    }
}
