import Darwin
import Foundation

public protocol ControlFraming: Sendable {
    func roundTrip(_ frame: Data) async throws -> Data
}

public struct UnixControlTransport: ControlFraming {
    public static let maximumFrameBytes = 64 * 1024
    public let socketPath: String
    public let timeout: TimeInterval

    public init(socketPath: String = FileManager.default.homeDirectoryForCurrentUser.path + "/.agentjail/run/daemon-ctl.sock", timeout: TimeInterval = 3) {
        self.socketPath = socketPath
        self.timeout = timeout
    }

    public func roundTrip(_ frame: Data) async throws -> Data {
        guard frame.count <= Self.maximumFrameBytes, frame.last == 10 else { throw ApprovalControlError.malformedReply }
        let ownership = SocketOwnership()
        return try await withTaskCancellationHandler(operation: {
            try Task.checkCancellation()
            do {
                let reply = try await Task.detached(priority: .userInitiated) {
                    try roundTripBlocking(frame, ownership: ownership)
                }.value
                try Task.checkCancellation()
                return reply
            } catch {
                if ownership.isCancelled { throw CancellationError() }
                throw error
            }
        }, onCancel: {
            ownership.cancel()
        })
    }

    private func roundTripBlocking(_ frame: Data, ownership: SocketOwnership) throws -> Data {
        do {
            let deadline = try monotonicDeadline()
            let descriptor = try connect(deadline: deadline, ownership: ownership)
            defer { ownership.close(descriptor) }
            try writeAll(frame, descriptor: descriptor, deadline: deadline, ownership: ownership)
            return try readFrame(descriptor: descriptor, deadline: deadline, ownership: ownership)
        } catch {
            if ownership.isCancelled { throw CancellationError() }
            throw error
        }
    }

    private func connect(deadline: UInt64, ownership: SocketOwnership) throws -> Int32 {
        guard !socketPath.utf8.contains(0), socketPath.utf8.count < MemoryLayout.size(ofValue: sockaddr_un().sun_path) else {
            throw ApprovalControlError.invalidSocketPath
        }
        let descriptor = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw mapErrno() }
        do {
            try ownership.register(descriptor)
            try setNonBlocking(descriptor)
            var address = sockaddr_un()
            address.sun_family = sa_family_t(AF_UNIX)
            withUnsafeMutableBytes(of: &address.sun_path) { destination in
                socketPath.withCString { source in destination.copyBytes(from: UnsafeRawBufferPointer(start: source, count: socketPath.utf8.count + 1)) }
            }
            let connected = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            if connected == 0 { return descriptor }
            guard errno == EINPROGRESS else { throw mapErrno() }
            try wait(descriptor, events: Int16(POLLOUT), deadline: deadline, ownership: ownership)
            var error: Int32 = 0
            var length = socklen_t(MemoryLayout<Int32>.size)
            guard getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &error, &length) == 0 else { throw mapErrno() }
            guard error == 0 else { throw mapErrno(error) }
            return descriptor
        } catch {
            ownership.close(descriptor)
            throw error
        }
    }

    private func readFrame(descriptor: Int32, deadline: UInt64, ownership: SocketOwnership) throws -> Data {
        var frame = Data()
        var bytes = [UInt8](repeating: 0, count: 4096)
        while true {
            try wait(descriptor, events: Int16(POLLIN), deadline: deadline, ownership: ownership)
            let readable = min(bytes.count, Self.maximumFrameBytes + 1 - frame.count)
            let count = Darwin.read(descriptor, &bytes, readable)
            if count > 0 {
                frame.append(bytes, count: count)
                if let delimiter = frame.firstIndex(of: 10) {
                    let complete = frame.prefix(through: delimiter)
                    guard complete.count <= Self.maximumFrameBytes else { throw ApprovalControlError.oversizedReply }
                    try validateFrame(Data(complete))
                    return Data(complete)
                }
                if frame.count == Self.maximumFrameBytes + 1 { throw ApprovalControlError.oversizedReply }
                continue
            }
            if count == 0 { throw ApprovalControlError.malformedReply }
            if errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK { continue }
            throw mapErrno()
        }
    }

    private func writeAll(_ frame: Data, descriptor: Int32, deadline: UInt64, ownership: SocketOwnership) throws {
        var offset = 0
        try frame.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress else { throw ApprovalControlError.malformedReply }
            while offset < frame.count {
                try wait(descriptor, events: Int16(POLLOUT), deadline: deadline, ownership: ownership)
                let count = Darwin.write(descriptor, base.advanced(by: offset), frame.count - offset)
                if count > 0 { offset += count; continue }
                if count < 0, errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK { continue }
                throw mapErrno()
            }
        }
    }

    private func validateFrame(_ frame: Data) throws {
        guard frame.last == 10, frame.count <= Self.maximumFrameBytes else { throw ApprovalControlError.oversizedReply }
        let content = frame.dropLast()
        guard String(data: content, encoding: .utf8) != nil else { throw ApprovalControlError.malformedReply }
        do {
            _ = try JSONSerialization.jsonObject(with: Data(content), options: [])
        } catch {
            throw ApprovalControlError.malformedReply
        }
    }

    private func setNonBlocking(_ descriptor: Int32) throws {
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else { throw mapErrno() }
    }

    private func monotonicDeadline() throws -> UInt64 {
        guard timeout.isFinite, timeout > 0, timeout < Double(UInt64.max) / 1_000_000_000 else {
            throw ApprovalControlError.timeout
        }
        let now = DispatchTime.now().uptimeNanoseconds
        let duration = UInt64(timeout * 1_000_000_000)
        guard now <= UInt64.max - duration else { throw ApprovalControlError.timeout }
        return now + duration
    }

    static func shouldReadAfterPoll(_ revents: Int16) -> Bool {
        revents & Int16(POLLIN | POLLHUP) != 0
    }

    private func wait(_ descriptor: Int32, events: Int16, deadline: UInt64, ownership: SocketOwnership) throws {
        while true {
            if ownership.isCancelled { throw CancellationError() }
            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadline else { throw ApprovalControlError.timeout }
            var pollDescriptor = pollfd(fd: descriptor, events: events, revents: 0)
            let remainingNanoseconds = deadline - now
            let milliseconds = Int32(min(remainingNanoseconds / 1_000_000 + (remainingNanoseconds % 1_000_000 == 0 ? 0 : 1), UInt64(Int32.max)))
            let result = Darwin.poll(&pollDescriptor, 1, milliseconds)
            if result == 0 { throw ApprovalControlError.timeout }
            if result < 0 {
                if errno == EINTR { continue }
                throw mapErrno()
            }
            if ownership.isCancelled { throw CancellationError() }
            if events == Int16(POLLIN), Self.shouldReadAfterPoll(pollDescriptor.revents) { return }
            if pollDescriptor.revents & Int16(POLLERR | POLLHUP | POLLNVAL) != 0 { throw ApprovalControlError.daemonUnavailable }
            if pollDescriptor.revents & events != 0 { return }
        }
    }

    private func mapErrno(_ code: Int32 = errno) -> ApprovalControlError {
        switch code {
        case ENOENT, ECONNREFUSED, ENOTCONN: return .daemonUnavailable
        case ETIMEDOUT: return .timeout
        default: return .daemonUnavailable
        }
    }
}

final class SocketOwnership: @unchecked Sendable {
    private let lock = NSLock()
    private var descriptor: Int32?
    private var cancelled = false
    private let shutdownDescriptor: (Int32) -> Int32
    private let closeDescriptor: (Int32) -> Int32

    init(
        shutdown: @escaping (Int32) -> Int32 = { Darwin.shutdown($0, SHUT_RDWR) },
        close: @escaping (Int32) -> Int32 = { Darwin.close($0) }
    ) {
        shutdownDescriptor = shutdown
        closeDescriptor = close
    }

    var isCancelled: Bool { lock.withLock { cancelled } }

    func register(_ newDescriptor: Int32) throws {
        lock.lock()
        if cancelled {
            lock.unlock()
            _ = closeDescriptor(newDescriptor)
            throw CancellationError()
        }
        descriptor = newDescriptor
        lock.unlock()
    }

    func cancel() {
        lock.lock()
        cancelled = true
        if let descriptor { _ = shutdownDescriptor(descriptor) }
        lock.unlock()
    }

    func close(_ closingDescriptor: Int32) {
        lock.lock()
        guard descriptor == closingDescriptor else {
            lock.unlock()
            return
        }
        descriptor = nil
        _ = closeDescriptor(closingDescriptor)
        lock.unlock()
    }
}
