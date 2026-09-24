import Darwin
import Foundation

struct AgentJailStatusSnapshot: Decodable, Equatable, Sendable {
    static let protocolVersion: UInt32 = 1

    let protocolVersion: UInt32
    let version: String
    let installation: AgentJailInstallationSnapshot?
    let infrastructure: Infrastructure
    let policies: Policies
    let agents: [Agent]

    struct Infrastructure: Decodable, Equatable, Sendable {
        let cliInstalled: Bool
        let hookBinaryInstalled: Bool
        let daemonBinaryInstalled: Bool
        let serviceDefinitionPresent: Bool
        let daemonRunning: Bool

        enum CodingKeys: String, CodingKey {
            case cliInstalled = "cli_installed"
            case hookBinaryInstalled = "hook_binary_installed"
            case daemonBinaryInstalled = "daemon_binary_installed"
            case serviceDefinitionPresent = "service_definition_present"
            case daemonRunning = "daemon_running"
        }
    }

    struct Policies: Decodable, Equatable, Sendable {
        let configured: Bool
        let readable: Bool
        let activeRules: Int

        enum CodingKeys: String, CodingKey {
            case configured, readable
            case activeRules = "active_rules"
        }
    }

    struct Agent: Decodable, Equatable, Identifiable, Sendable {
        let id: String
        let displayName: String
        let detected: Bool
        let hookInstalled: Bool

        enum CodingKeys: String, CodingKey {
            case id, detected
            case displayName = "display_name"
            case hookInstalled = "hook_installed"
        }
    }

    enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol_version"
        case version, installation, infrastructure, policies, agents
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        protocolVersion = try values.decode(UInt32.self, forKey: .protocolVersion)
        guard protocolVersion == Self.protocolVersion else { throw AgentJailStatusError.unsupportedProtocol }
        version = try values.decode(String.self, forKey: .version)
        installation = try values.decodeIfPresent(AgentJailInstallationSnapshot.self, forKey: .installation)
        infrastructure = try values.decode(Infrastructure.self, forKey: .infrastructure)
        policies = try values.decode(Policies.self, forKey: .policies)
        agents = try values.decode([Agent].self, forKey: .agents)
        guard !version.isEmpty, version.utf8.count <= 64,
              policies.activeRules >= 0, policies.activeRules <= 10_000,
              agents.count <= 16,
              agents.allSatisfy({ !$0.id.isEmpty && $0.id.utf8.count <= 64 && !$0.displayName.isEmpty && $0.displayName.utf8.count <= 128 })
        else {
            throw AgentJailStatusError.invalidProjection
        }
    }
}

enum AgentJailStatusError: Error, Equatable, Sendable {
    case unavailable
    case commandFailed
    case oversizedReply
    case unsupportedProtocol
    case invalidProjection
    case malformedReply
}

protocol AgentJailStatusServicing: Sendable {
    func status() async throws -> AgentJailStatusSnapshot
}

protocol AgentJailStatusCommandRunning: Sendable {
    func statusJSON() async throws -> Data
}

struct BundledAgentJailStatusService: AgentJailStatusServicing {
    private let runner: any AgentJailStatusCommandRunning

    init(runner: any AgentJailStatusCommandRunning = BundledAgentJailStatusCommandRunner()) {
        self.runner = runner
    }

    func status() async throws -> AgentJailStatusSnapshot {
        let data = try await runner.statusJSON()
        guard data.count <= BundledAgentJailStatusCommandRunner.maximumBytes else {
            throw AgentJailStatusError.oversizedReply
        }
        do {
            return try JSONDecoder().decode(AgentJailStatusSnapshot.self, from: data)
        } catch let error as AgentJailStatusError {
            throw error
        } catch {
            throw AgentJailStatusError.malformedReply
        }
    }
}

struct BundledAgentJailStatusCommandRunner: AgentJailStatusCommandRunning {
    static let maximumBytes = 64 * 1024
    private let executableURL: URL?

    init(bundle: Bundle = .main) {
        executableURL = bundle.resourceURL?
            .appendingPathComponent("bin", isDirectory: true)
            .appendingPathComponent("agentjail")
    }

    init(executableURL: URL?) {
        self.executableURL = executableURL
    }

    func statusJSON() async throws -> Data {
        guard let executableURL else { throw AgentJailStatusError.unavailable }
        return try await Task.detached(priority: .userInitiated) {
            let process = Process()
            let stdout = Pipe()
            process.executableURL = executableURL
            process.arguments = ["--no-color", "status", "--json"]
            process.standardInput = FileHandle.nullDevice
            process.standardOutput = stdout
            process.standardError = FileHandle.nullDevice
            do {
                try process.run()
            } catch {
                throw AgentJailStatusError.unavailable
            }
            defer {
                if process.isRunning { kill(process.processIdentifier, SIGKILL) }
                process.waitUntilExit()
                try? stdout.fileHandleForReading.close()
            }
            let descriptor = stdout.fileHandleForReading.fileDescriptor
            let flags = fcntl(descriptor, F_GETFL)
            guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
                throw AgentJailStatusError.commandFailed
            }
            let deadline = DispatchTime.now().uptimeNanoseconds + 3_000_000_000
            var data = Data()
            var outputClosed = false
            var bytes = [UInt8](repeating: 0, count: 4096)
            while !outputClosed || process.isRunning {
                guard DispatchTime.now().uptimeNanoseconds < deadline else { throw AgentJailStatusError.commandFailed }
                if outputClosed {
                    _ = Darwin.poll(nil, 0, 10)
                    continue
                }
                var readable = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
                let ready = Darwin.poll(&readable, 1, 50)
                if ready < 0 {
                    if errno == EINTR { continue }
                    throw AgentJailStatusError.commandFailed
                }
                if ready == 0 { continue }
                let count = Darwin.read(descriptor, &bytes, bytes.count)
                if count == 0 { outputClosed = true; continue }
                if count < 0 {
                    if errno == EAGAIN || errno == EINTR { continue }
                    throw AgentJailStatusError.commandFailed
                }
                guard data.count + count <= Self.maximumBytes else { throw AgentJailStatusError.oversizedReply }
                data.append(bytes, count: count)
            }
            process.waitUntilExit()
            try Task.checkCancellation()
            guard process.terminationStatus == 0 else { throw AgentJailStatusError.commandFailed }
            guard data.count <= Self.maximumBytes else { throw AgentJailStatusError.oversizedReply }
            return data
        }.value
    }
}

@MainActor
final class AgentJailStatusStore: ObservableObject {
    @Published private(set) var snapshot: AgentJailStatusSnapshot?
    @Published private(set) var isRefreshing = false
    @Published private(set) var unavailable = false

    private let service: any AgentJailStatusServicing

    init(service: any AgentJailStatusServicing = BundledAgentJailStatusService()) {
        self.service = service
    }

    func refresh() async {
        guard !isRefreshing else { return }
        isRefreshing = true
        defer { isRefreshing = false }
        do {
            snapshot = try await service.status()
            unavailable = false
        } catch is CancellationError {
            return
        } catch {
            unavailable = snapshot == nil
        }
    }
}
