import Foundation

enum ApprovalTelemetrySource: Equatable, Sendable {
    case config
    case environment
    case continuousIntegration
    case unknown

    init(wireValue: String) {
        switch wireValue {
        case "config": self = .config
        case "env": self = .environment
        case "ci": self = .continuousIntegration
        default: self = .unknown
        }
    }
}

enum ApprovalTelemetryStatus: Equatable, Sendable {
    case unknown
    case enabled(ApprovalTelemetrySource)
    case disabled(ApprovalTelemetrySource)
    case updating(Bool)
    case unavailable

    var isEnabled: Bool {
        switch self {
        case .enabled, .updating(true): true
        case .unknown, .disabled, .updating(false), .unavailable: false
        }
    }

    var canChange: Bool {
        switch self {
        case .enabled(.config), .disabled(.config): true
        case .unknown, .enabled, .disabled, .updating, .unavailable: false
        }
    }
}

protocol ApprovalTelemetryServicing: Sendable {
    func status() async -> ApprovalTelemetryStatus
    func setEnabled(_ enabled: Bool) async -> ApprovalTelemetryStatus
}

struct BundledAgentJailTelemetryService: ApprovalTelemetryServicing {
    private let cliURL: URL?

    init(bundle: Bundle = .main) {
        cliURL = bundle.resourceURL?
            .appendingPathComponent("bin", isDirectory: true)
            .appendingPathComponent("agentjail")
    }

    init(cliURL: URL?) {
        self.cliURL = cliURL
    }

    func status() async -> ApprovalTelemetryStatus {
        guard let result = await run(arguments: ["telemetry", "status", "--json"]),
              result.exitCode == 0,
              let wire = try? JSONDecoder().decode(ApprovalTelemetryStatusWire.self, from: result.output)
        else {
            return .unavailable
        }
        let source = ApprovalTelemetrySource(wireValue: wire.source)
        return wire.enabled ? .enabled(source) : .disabled(source)
    }

    func setEnabled(_ enabled: Bool) async -> ApprovalTelemetryStatus {
        let action = enabled ? "enable" : "disable"
        guard let result = await run(arguments: ["telemetry", action]), result.exitCode == 0 else {
            return .unavailable
        }
        return await status()
    }

    private func run(arguments: [String]) async -> ApprovalTelemetryCommandResult? {
        guard let cliURL else { return nil }
        return await Task.detached(priority: .userInitiated) {
            let process = Process()
            let pipe = Pipe()
            let collector = ApprovalTelemetryOutputCollector()
            process.executableURL = cliURL
            process.arguments = arguments
            process.standardOutput = pipe
            process.standardError = FileHandle.nullDevice
            pipe.fileHandleForReading.readabilityHandler = { handle in
                collector.consume(handle.availableData)
            }
            do {
                try process.run()
            } catch {
                pipe.fileHandleForReading.readabilityHandler = nil
                return nil
            }
            process.waitUntilExit()
            pipe.fileHandleForReading.readabilityHandler = nil
            collector.consume(pipe.fileHandleForReading.readDataToEndOfFile())
            return ApprovalTelemetryCommandResult(
                exitCode: process.terminationStatus,
                output: collector.snapshot()
            )
        }.value
    }
}

private struct ApprovalTelemetryStatusWire: Decodable {
    let enabled: Bool
    let source: String
}

private struct ApprovalTelemetryCommandResult: Sendable {
    let exitCode: Int32
    let output: Data
}

private final class ApprovalTelemetryOutputCollector: @unchecked Sendable {
    private static let maximumBytes = 4 * 1024
    private let lock = NSLock()
    private var data = Data()

    func consume(_ chunk: Data) {
        guard !chunk.isEmpty else { return }
        lock.lock()
        if data.count < Self.maximumBytes {
            data.append(chunk.prefix(Self.maximumBytes - data.count))
        }
        lock.unlock()
    }

    func snapshot() -> Data {
        lock.lock()
        defer { lock.unlock() }
        return data
    }
}
