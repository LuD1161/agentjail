import Darwin
import Foundation

// The serial queue owns listener state and descriptor lifetime. Accepted descriptors
// transfer to the handler; cancellation closes only its own listener generation.
final class SessionSocketListener: @unchecked Sendable {
    private let queue = DispatchQueue(label: "com.agentjail.session-listener")
    private var source: DispatchSourceRead?
    private var path: String?

    func start(path: String, handler: @escaping @Sendable (Int32) -> Void) throws {
        try queue.sync {
            guard source == nil else { return }
            let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
            guard fd >= 0 else { throw failure("socket") }
            var installed = false
            defer { if !installed { Darwin.close(fd) } }
            guard fcntl(fd, F_SETFL, O_NONBLOCK) == 0 else { throw failure("nonblocking") }
            var address = sockaddr_un()
            address.sun_family = sa_family_t(AF_UNIX)
            let bytes = path.utf8CString
            guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
                throw NSError(domain: NSPOSIXErrorDomain, code: Int(ENAMETOOLONG))
            }
            withUnsafeMutablePointer(to: &address.sun_path) { pointer in
                pointer.withMemoryRebound(to: CChar.self, capacity: bytes.count) { destination in
                    for (index, byte) in bytes.enumerated() { destination[index] = byte }
                }
            }
            unlink(path)
            let bound = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            guard bound == 0 else { throw failure("bind") }
            guard chmod(path, 0o666) == 0, listen(fd, 16) == 0 else {
                let error = failure("listen")
                unlink(path)
                throw error
            }
            let listener = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
            listener.setEventHandler { [weak self] in
                while true {
                    let client = Darwin.accept(fd, nil, nil)
                    if client >= 0 {
                        DispatchQueue.global(qos: .userInitiated).async { handler(client) }
                    } else if errno == EINTR {
                        continue
                    } else if errno == EAGAIN || errno == EWOULDBLOCK {
                        return
                    } else {
                        self?.stopOnQueue()
                        return
                    }
                }
            }
            listener.setCancelHandler { Darwin.close(fd) }
            self.path = path
            source = listener
            installed = true
            listener.resume()
        }
    }

    func stop() { queue.sync { stopOnQueue() } }

    private func stopOnQueue() {
        guard let source else { return }
        if let path { unlink(path) }
        self.path = nil
        self.source = nil
        source.cancel()
    }

    private func failure(_ operation: String) -> NSError {
        NSError(domain: NSPOSIXErrorDomain, code: Int(errno), userInfo: [NSLocalizedDescriptionKey: "Session listener \(operation) failed"])
    }
}
