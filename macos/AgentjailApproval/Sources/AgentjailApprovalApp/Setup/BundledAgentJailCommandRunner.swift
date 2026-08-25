import Foundation

struct BundledAgentJailCommandRunner: AgentJailSetupCommandRunning {
    private let cliURL: URL?
    private let appExecutableURL: URL?

    init(bundle: Bundle = .main) {
        cliURL = bundle.resourceURL?
            .appendingPathComponent("bin", isDirectory: true)
            .appendingPathComponent("agentjail")
        appExecutableURL = bundle.executableURL
    }

    func run(
        _ command: AgentJailSetupCommand,
        signal: @escaping @Sendable (AgentJailSetupSignal) -> Void = { _ in }
    ) async -> AgentJailSetupCommandResult {
        guard let invocation = invocation(for: command) else {
            return AgentJailSetupCommandResult(launched: false, exitCode: -1)
        }
        return await Task.detached(priority: .userInitiated) {
            let process = Process()
            let pipe = Pipe()
            let collector = AgentJailSetupOutputCollector(signal: signal)
            process.executableURL = invocation.executableURL
            process.arguments = invocation.arguments
            process.environment = invocation.environment
            process.standardOutput = pipe
            process.standardError = pipe
            pipe.fileHandleForReading.readabilityHandler = { handle in
                collector.consume(handle.availableData)
            }
            do {
                try process.run()
            } catch {
                pipe.fileHandleForReading.readabilityHandler = nil
                return AgentJailSetupCommandResult(launched: false, exitCode: -1)
            }
            process.waitUntilExit()
            pipe.fileHandleForReading.readabilityHandler = nil
            collector.consume(pipe.fileHandleForReading.readDataToEndOfFile())
            return AgentJailSetupCommandResult(launched: true, exitCode: process.terminationStatus)
        }.value
    }

    private func invocation(for command: AgentJailSetupCommand) -> AgentJailSetupInvocation? {
        switch command {
        case .installComponents:
            guard let cliURL else { return nil }
            var environment = ProcessInfo.processInfo.environment
            environment["AGENTJAIL_INSTALL_METHOD"] = "app"
            environment["AGENTJAIL_ASSUME_YES"] = "1"
            return AgentJailSetupInvocation(
                executableURL: cliURL,
                arguments: ["--no-color", "install", "--all", "--yes"],
                environment: environment
            )
        case .installExtension:
            guard let appExecutableURL else { return nil }
            return AgentJailSetupInvocation(
                executableURL: appExecutableURL,
                arguments: ["install-extension"],
                environment: ProcessInfo.processInfo.environment
            )
        case let .record(measurement):
            guard let cliURL else { return nil }
            let value = measurement.arguments
            return AgentJailSetupInvocation(
                executableURL: cliURL,
                arguments: ["telemetry", "macos-setup", value.stage, value.outcome],
                environment: ProcessInfo.processInfo.environment
            )
        }
    }
}

private struct AgentJailSetupInvocation: Sendable {
    let executableURL: URL
    let arguments: [String]
    let environment: [String: String]
}

private final class AgentJailSetupOutputCollector: @unchecked Sendable {
    private static let approvalMarker = Data("waiting for user approval".utf8)
    private static let maximumBytes = 64 * 1024

    private let lock = NSLock()
    private let signal: @Sendable (AgentJailSetupSignal) -> Void
    private var data = Data()
    private var reportedApproval = false

    init(signal: @escaping @Sendable (AgentJailSetupSignal) -> Void) {
        self.signal = signal
    }

    func consume(_ chunk: Data) {
        guard !chunk.isEmpty else { return }
        var shouldReport = false
        lock.lock()
        if data.count < Self.maximumBytes {
            data.append(chunk.prefix(Self.maximumBytes - data.count))
        }
        if !reportedApproval, data.range(of: Self.approvalMarker) != nil {
            reportedApproval = true
            shouldReport = true
        }
        lock.unlock()
        if shouldReport {
            signal(.approvalRequired)
        }
    }
}
