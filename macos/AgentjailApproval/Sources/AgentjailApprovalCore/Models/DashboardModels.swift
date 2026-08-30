import Foundation

public struct DashboardSnapshotV1: Decodable, Equatable, Sendable {
    public static let protocolVersion: UInt32 = 1
    public let protocolVersion: UInt32
    public let generatedAtUnixMs: Int64
    public let totalCalls: Int64
    public let allowedCalls: Int64
    public let deniedCalls: Int64
    public let askedCalls: Int64
    public let totalSessions: Int64
    public let activeSessions: Int
    public let recentSessions: [DashboardSession]
    public let activity: [DashboardDay]
    public let tokens: [DashboardTokenDay]
    public let tokenAgents: [DashboardTokenAgent]
    public let mcpTools: [DashboardMCPTools]
    public let tokenCoverage: [String]
    public let tokenStatus: DashboardTokenStatus

    enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol_version", generatedAtUnixMs = "generated_at_unix_ms"
        case totalCalls = "total_calls", allowedCalls = "allowed_calls", deniedCalls = "denied_calls", askedCalls = "asked_calls"
        case totalSessions = "total_sessions", activeSessions = "active_sessions", recentSessions = "recent_sessions"
        case activity, tokens, tokenAgents = "token_agents", mcpTools = "mcp_tools", tokenCoverage = "token_coverage", tokenStatus = "token_status"
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        protocolVersion = try values.decode(UInt32.self, forKey: .protocolVersion)
        guard protocolVersion == Self.protocolVersion else { throw DashboardModelError.unsupportedProtocolVersion }
        generatedAtUnixMs = try values.decode(Int64.self, forKey: .generatedAtUnixMs)
        totalCalls = try values.decode(Int64.self, forKey: .totalCalls)
        allowedCalls = try values.decode(Int64.self, forKey: .allowedCalls)
        deniedCalls = try values.decode(Int64.self, forKey: .deniedCalls)
        askedCalls = try values.decode(Int64.self, forKey: .askedCalls)
        totalSessions = try values.decode(Int64.self, forKey: .totalSessions)
        activeSessions = try values.decode(Int.self, forKey: .activeSessions)
        recentSessions = try values.decode([DashboardSession].self, forKey: .recentSessions)
        activity = try values.decode([DashboardDay].self, forKey: .activity)
        tokens = try values.decode([DashboardTokenDay].self, forKey: .tokens)
        tokenAgents = try values.decodeIfPresent([DashboardTokenAgent].self, forKey: .tokenAgents) ?? []
        mcpTools = try values.decodeIfPresent([DashboardMCPTools].self, forKey: .mcpTools) ?? []
        tokenCoverage = try values.decode([String].self, forKey: .tokenCoverage)
        tokenStatus = try values.decodeIfPresent(DashboardTokenStatus.self, forKey: .tokenStatus) ?? .ready
        guard totalCalls >= 0, allowedCalls >= 0, deniedCalls >= 0, askedCalls >= 0,
              totalSessions >= 0, activeSessions >= 0, recentSessions.count <= 12,
              activity.count <= 35, tokens.count <= 35, tokenAgents.count <= 8, mcpTools.count <= 64,
              tokenCoverage.allSatisfy({ $0.utf8.count <= 128 }) else {
            throw DashboardModelError.invalidProjection
        }
    }
}

public struct DashboardMCPTools: Decodable, Equatable, Sendable {
    public let server: String
    public let tools: [String]

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        server = DisplaySanitizer.text(try values.decode(String.self, forKey: .server), limit: 128).text
        tools = try values.decode([String].self, forKey: .tools).map {
            DisplaySanitizer.text($0, limit: 128).text
        }
        guard !server.isEmpty, server.utf8.count <= 128, tools.count <= 128,
              tools.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 128 }) else {
            throw DashboardModelError.invalidProjection
        }
    }

    private enum CodingKeys: String, CodingKey { case server, tools }
}

public enum DashboardTokenStatus: String, Decodable, Equatable, Sendable {
    case loading
    case ready
}

public struct DashboardSession: Decodable, Identifiable, Equatable, Sendable {
    public let sessionID: String
    public let agent: String
    public let project: String
    public let startedAtUnixMs: Int64
    public let endedAtUnixMs: Int64?
    public let auditedCalls: Int
    public let active: Bool
    public var id: String { sessionID }

    enum CodingKeys: String, CodingKey {
        case sessionID = "session_id", agent, project, startedAtUnixMs = "started_at_unix_ms"
        case endedAtUnixMs = "ended_at_unix_ms", auditedCalls = "audited_calls", active
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        sessionID = try values.decode(String.self, forKey: .sessionID)
        agent = DisplaySanitizer.text(try values.decode(String.self, forKey: .agent), limit: 128).text
        project = DisplaySanitizer.text(try values.decode(String.self, forKey: .project), limit: 128).text
        startedAtUnixMs = try values.decode(Int64.self, forKey: .startedAtUnixMs)
        endedAtUnixMs = try values.decodeIfPresent(Int64.self, forKey: .endedAtUnixMs)
        auditedCalls = try values.decode(Int.self, forKey: .auditedCalls)
        active = try values.decode(Bool.self, forKey: .active)
        guard !sessionID.isEmpty, sessionID.utf8.count <= 128, agent.utf8.count <= 128,
              project.utf8.count <= 128, auditedCalls >= 0 else { throw DashboardModelError.invalidProjection }
    }
}

public struct DashboardDay: Decodable, Identifiable, Equatable, Sendable {
    public let day: String
    public let count: Int64
    public var id: String { day }

    enum CodingKeys: String, CodingKey { case day, count }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        day = try values.decode(String.self, forKey: .day)
        count = try values.decode(Int64.self, forKey: .count)
        guard day.utf8.count == 10, count >= 0 else { throw DashboardModelError.invalidProjection }
    }
}

public struct DashboardTokenDay: Decodable, Identifiable, Equatable, Sendable {
    public let day: String
    public let inputTokens: Int64
    public let outputTokens: Int64
    public let cacheTokens: Int64
    public var id: String { day }
    public var totalTokens: Int64 { inputTokens + outputTokens + cacheTokens }

    enum CodingKeys: String, CodingKey {
        case day, inputTokens = "input_tokens", outputTokens = "output_tokens", cacheTokens = "cache_tokens"
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        day = try values.decode(String.self, forKey: .day)
        inputTokens = try values.decode(Int64.self, forKey: .inputTokens)
        outputTokens = try values.decode(Int64.self, forKey: .outputTokens)
        cacheTokens = try values.decode(Int64.self, forKey: .cacheTokens)
        guard day.utf8.count == 10, inputTokens >= 0, outputTokens >= 0, cacheTokens >= 0 else { throw DashboardModelError.invalidProjection }
    }
}

public struct DashboardTokenAgent: Decodable, Identifiable, Equatable, Sendable {
    public let agent: String
    public let inputTokens: Int64
    public let outputTokens: Int64
    public let cacheTokens: Int64
    public var id: String { agent }
    public var totalTokens: Int64 { inputTokens + outputTokens + cacheTokens }

    enum CodingKeys: String, CodingKey { case agent, inputTokens = "input_tokens", outputTokens = "output_tokens", cacheTokens = "cache_tokens" }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        agent = try values.decode(String.self, forKey: .agent)
        inputTokens = try values.decode(Int64.self, forKey: .inputTokens)
        outputTokens = try values.decode(Int64.self, forKey: .outputTokens)
        cacheTokens = try values.decode(Int64.self, forKey: .cacheTokens)
        guard !agent.isEmpty, agent.utf8.count <= 128, inputTokens >= 0, outputTokens >= 0, cacheTokens >= 0 else { throw DashboardModelError.invalidProjection }
    }
}

public enum DashboardModelError: Error, Equatable, Sendable {
    case unsupportedProtocolVersion
    case invalidProjection
}

public protocol DashboardControlling: Sendable {
    func fetchDashboard() async throws -> DashboardSnapshotV1
}
