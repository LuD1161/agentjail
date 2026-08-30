import Foundation

public protocol MCPToolDiscoveryCommandRunning: Sendable {
    func discoverToolsJSON() async throws -> Data
}

public struct MCPToolDiscoveryCLIClient: MCPToolDiscoveryControlling {
    private let runner: any MCPToolDiscoveryCommandRunning

    public init(runner: any MCPToolDiscoveryCommandRunning = BundledMCPToolDiscoveryCommandRunner()) {
        self.runner = runner
    }

    public func discoverTools() async throws -> MCPToolDiscoverySnapshot {
        let data = try await runner.discoverToolsJSON()
        guard data.count <= UnixControlTransport.maximumFrameBytes else {
            throw ApprovalControlError.oversizedReply
        }
        do {
            return try JSONDecoder().decode(MCPToolDiscoverySnapshot.self, from: data)
        } catch let error as ApprovalControlError {
            throw error
        } catch {
            throw ApprovalControlError.malformedReply
        }
    }
}

public struct BundledMCPToolDiscoveryCommandRunner: MCPToolDiscoveryCommandRunning {
    private let executableURL: URL?

    public init(bundle: Bundle = .main) {
        executableURL = bundle.resourceURL?
            .appendingPathComponent("bin", isDirectory: true)
            .appendingPathComponent("agentjail")
    }

    public func discoverToolsJSON() async throws -> Data {
        guard let executableURL else { throw ApprovalControlError.daemonUnavailable }
        let processState = MCPToolDiscoveryProcessState()
        return try await withTaskCancellationHandler {
            try await Task.detached(priority: .userInitiated) {
                let process = Process()
                let stdout = Pipe()
                let stderr = Pipe()
                process.executableURL = executableURL
                process.arguments = ["--no-color", "mcp", "tool", "discover", "--json"]
                process.standardOutput = stdout
                process.standardError = stderr
                processState.register(process)
                do {
                    try process.run()
                } catch {
                    throw ApprovalControlError.daemonUnavailable
                }
                processState.terminateIfCancelled()
                process.waitUntilExit()
                try Task.checkCancellation()
                let data = stdout.fileHandleForReading.readDataToEndOfFile()
                guard process.terminationStatus == 0 else {
                    throw ApprovalControlError.serverRefused("MCP tool discovery could not complete")
                }
                return data
            }.value
        } onCancel: {
            processState.cancel()
        }
    }
}

private final class MCPToolDiscoveryProcessState: @unchecked Sendable {
    private let lock = NSLock()
    private var process: Process?
    private var cancelled = false

    func register(_ process: Process) {
        lock.lock()
        self.process = process
        let shouldCancel = cancelled
        lock.unlock()
        if shouldCancel, process.isRunning {
            process.terminate()
        }
    }

    func cancel() {
        lock.lock()
        cancelled = true
        let process = process
        lock.unlock()
        if let process, process.isRunning {
            process.terminate()
        }
    }

    func terminateIfCancelled() {
        lock.lock()
        let shouldTerminate = cancelled
        let process = process
        lock.unlock()
        if shouldTerminate, let process, process.isRunning {
            process.terminate()
        }
    }
}
