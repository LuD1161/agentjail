import Foundation

struct PolicyInventorySnapshot: Decodable, Equatable, Sendable {
    static let protocolVersion: UInt32 = 1

    let protocolVersion: UInt32
    let historyAvailable: Bool
    let policies: [Policy]
    let sources: [Source]
    let breakdownLimited: Bool

    struct Policy: Decodable, Equatable, Identifiable, Sendable {
        let id: String
        let name: String
        let description: String
        let source: SourceKind
        let sourceFile: String
        let locked: Bool
        let matchedCount: Int64
        let agentCount: Int64
        let sessionCount: Int64
        let breakdownLimited: Bool
        let examples: [Example]
        let evaluations: [Evaluation]

        enum CodingKeys: String, CodingKey {
            case id, name, description, source, locked, examples, evaluations
            case sourceFile = "source_file"
            case matchedCount = "matched_count"
            case agentCount = "agent_count"
            case sessionCount = "session_count"
            case breakdownLimited = "breakdown_limited"
        }
    }

    enum SourceKind: String, Decodable, Equatable, Sendable {
        case core
        case library
        case custom

        var label: String {
            switch self {
            case .core: "Core"
            case .library: "Optional"
            case .custom: "Custom"
            }
        }
    }

    struct Source: Decodable, Equatable, Identifiable, Sendable {
        var id: String { filename }
        let filename: String
        let rego: String
    }

    struct Example: Decodable, Equatable, Identifiable, Sendable {
        var id: String { "\(action)\u{0}\(reason)\u{0}\(impact)" }
        let action: String
        let reason: String
        let impact: String
    }

    struct Evaluation: Decodable, Equatable, Identifiable, Sendable {
        var id: String { "\(agent)\u{0}\(sessionID)" }
        let agent: String
        let sessionID: String
        let sessionFolder: String
        let matchedCount: Int64

        enum CodingKeys: String, CodingKey {
            case agent
            case sessionID = "session_id"
            case sessionFolder = "session_folder"
            case matchedCount = "matched_count"
        }
    }

    enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol_version"
        case historyAvailable = "history_available"
        case policies, sources
        case breakdownLimited = "breakdown_limited"
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        protocolVersion = try values.decode(UInt32.self, forKey: .protocolVersion)
        guard protocolVersion == Self.protocolVersion else { throw PolicyInventoryError.unsupportedProtocol }
        historyAvailable = try values.decode(Bool.self, forKey: .historyAvailable)
        policies = try values.decode([Policy].self, forKey: .policies)
        sources = try values.decode([Source].self, forKey: .sources)
        breakdownLimited = try values.decode(Bool.self, forKey: .breakdownLimited)

        let sourceNames = Set(sources.map(\.filename))
        let evaluationCount = policies.reduce(0) { $0 + $1.evaluations.count }
        let sourceBytes = sources.reduce(0) { $0 + $1.rego.utf8.count }
        guard policies.count <= 512,
              sources.count <= 128,
              sourceNames.count == sources.count,
              evaluationCount <= 2_000,
              sourceBytes <= 1_048_576,
              policies.allSatisfy({ policy in
                  !policy.id.isEmpty && policy.id.utf8.count <= 256 &&
                  !policy.name.isEmpty && policy.name.utf8.count <= 128 &&
                  policy.description.utf8.count <= 2_048 &&
                  sourceNames.contains(policy.sourceFile) &&
                  policy.matchedCount >= 0 && policy.agentCount >= 0 && policy.sessionCount >= 0 &&
                  policy.examples.count <= 3 && policy.evaluations.allSatisfy({ evaluation in
                      !evaluation.agent.isEmpty && evaluation.agent.utf8.count <= 256 &&
                      !evaluation.sessionID.isEmpty && evaluation.sessionID.utf8.count <= 512 &&
                      evaluation.sessionFolder.utf8.count <= 512 && evaluation.matchedCount > 0
                  })
              })
        else {
            throw PolicyInventoryError.invalidProjection
        }
    }

    func rego(for policy: Policy) -> String {
        sources.first(where: { $0.filename == policy.sourceFile })?.rego ?? ""
    }
}

enum PolicyInventoryError: Error, Equatable, Sendable {
    case unavailable
    case commandFailed
    case oversizedReply
    case unsupportedProtocol
    case invalidProjection
    case malformedReply
}

protocol PolicyInventoryServicing: Sendable {
    func inventory() async throws -> PolicyInventorySnapshot
}

protocol PolicyInventoryCommandRunning: Sendable {
    func policyInventoryJSON() async throws -> Data
}

struct BundledPolicyInventoryService: PolicyInventoryServicing {
    private let runner: any PolicyInventoryCommandRunning

    init(runner: any PolicyInventoryCommandRunning = BundledPolicyInventoryCommandRunner()) {
        self.runner = runner
    }

    func inventory() async throws -> PolicyInventorySnapshot {
        let data = try await runner.policyInventoryJSON()
        guard data.count <= BundledPolicyInventoryCommandRunner.maximumBytes else {
            throw PolicyInventoryError.oversizedReply
        }
        do {
            return try JSONDecoder().decode(PolicyInventorySnapshot.self, from: data)
        } catch let error as PolicyInventoryError {
            throw error
        } catch {
            throw PolicyInventoryError.malformedReply
        }
    }
}

struct BundledPolicyInventoryCommandRunner: PolicyInventoryCommandRunning {
    static let maximumBytes = 4 * 1024 * 1024
    private let executableURL: URL?

    init(bundle: Bundle = .main) {
        executableURL = bundle.resourceURL?
            .appendingPathComponent("bin", isDirectory: true)
            .appendingPathComponent("agentjail")
    }

    init(executableURL: URL?) {
        self.executableURL = executableURL
    }

    func policyInventoryJSON() async throws -> Data {
        guard let executableURL else { throw PolicyInventoryError.unavailable }
        return try await Task.detached(priority: .userInitiated) {
            let process = Process()
            let stdout = Pipe()
            process.executableURL = executableURL
            process.arguments = ["--no-color", "policy", "list", "--json"]
            process.standardOutput = stdout
            process.standardError = FileHandle.nullDevice
            do {
                try process.run()
            } catch {
                throw PolicyInventoryError.unavailable
            }
            let data = try stdout.fileHandleForReading.readToEnd() ?? Data()
            process.waitUntilExit()
            try Task.checkCancellation()
            guard process.terminationStatus == 0 else { throw PolicyInventoryError.commandFailed }
            guard data.count <= Self.maximumBytes else { throw PolicyInventoryError.oversizedReply }
            return data
        }.value
    }
}

@MainActor
final class PolicyInventoryStore: ObservableObject {
    @Published private(set) var snapshot: PolicyInventorySnapshot?
    @Published private(set) var isRefreshing = false
    @Published private(set) var unavailable = false

    private let service: any PolicyInventoryServicing

    init(service: any PolicyInventoryServicing = BundledPolicyInventoryService()) {
        self.service = service
    }

    func refresh() async {
        guard !isRefreshing else { return }
        isRefreshing = true
        defer { isRefreshing = false }
        do {
            snapshot = try await service.inventory()
            unavailable = false
        } catch is CancellationError {
            return
        } catch {
            unavailable = snapshot == nil
        }
    }
}
