import Foundation

public struct NetworkSnapshotV1: Decodable, Equatable, Sendable {
    public static let protocolVersion: UInt32 = 1
    public let protocolVersion: UInt32
    public let generatedAtUnixMs: Int64
    public let available: Bool
    public let events: [NetworkEvent]

    enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol_version", generatedAtUnixMs = "generated_at_unix_ms", available, events
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        protocolVersion = try values.decode(UInt32.self, forKey: .protocolVersion)
        guard protocolVersion == Self.protocolVersion else { throw ActivityModelError.unsupportedProtocolVersion }
        generatedAtUnixMs = try values.decode(Int64.self, forKey: .generatedAtUnixMs)
        available = try values.decode(Bool.self, forKey: .available)
        events = try values.decode([NetworkEvent].self, forKey: .events)
        guard generatedAtUnixMs > 0, events.count <= 200 else { throw ActivityModelError.invalidProjection }
    }
}

public struct NetworkEvent: Decodable, Identifiable, Equatable, Sendable {
    public let id: Int64
    public let timestampUnixMs: Int64
    public let host: String
    public let method: String
    public let path: String
    public let statusCode: Int
    public let requestSize: Int64
    public let responseSize: Int64
    public let elapsedMs: Int64
    public let error: String
    public let sessionID: String
    public let agent: String
    public let project: String
    public let toolName: String
    public let policyAction: String
    public let policyReason: String
    public let service: String
    public let verb: String
    public let resourceType: String

    enum CodingKeys: String, CodingKey {
        case id, host, method, path, error, agent, project, service, verb
        case timestampUnixMs = "timestamp_unix_ms", statusCode = "status_code"
        case requestSize = "request_size", responseSize = "response_size", elapsedMs = "elapsed_ms"
        case sessionID = "session_id", toolName = "tool_name", policyAction = "policy_action"
        case policyReason = "policy_reason", resourceType = "resource_type"
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(Int64.self, forKey: .id)
        timestampUnixMs = try values.decode(Int64.self, forKey: .timestampUnixMs)
        host = try sanitizedRequired(values, .host)
        method = try sanitized(values, .method)
        path = try sanitized(values, .path)
        statusCode = try values.decode(Int.self, forKey: .statusCode)
        requestSize = try values.decode(Int64.self, forKey: .requestSize)
        responseSize = try values.decode(Int64.self, forKey: .responseSize)
        elapsedMs = try values.decode(Int64.self, forKey: .elapsedMs)
        error = try sanitized(values, .error)
        sessionID = try sanitized(values, .sessionID)
        agent = try sanitized(values, .agent)
        project = try sanitized(values, .project)
        toolName = try sanitized(values, .toolName)
        policyAction = try sanitized(values, .policyAction)
        policyReason = try sanitized(values, .policyReason)
        service = try sanitized(values, .service)
        verb = try sanitized(values, .verb)
        resourceType = try sanitized(values, .resourceType)
        guard id > 0, timestampUnixMs > 0, statusCode >= 0, requestSize >= 0,
              responseSize >= 0, elapsedMs >= 0 else { throw ActivityModelError.invalidProjection }
    }
}

public struct SessionLogSnapshotV1: Decodable, Equatable, Sendable {
    public static let protocolVersion: UInt32 = 1
    public let protocolVersion: UInt32
    public let generatedAtUnixMs: Int64
    public let selectedSessionID: String
    public let sessions: [ActivitySession]
    public let entries: [SessionAction]
    public let totalMatches: Int
    public let hasMore: Bool
    public let nextBeforeID: Int64?
    public let truncated: Bool

    enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol_version", generatedAtUnixMs = "generated_at_unix_ms"
        case selectedSessionID = "selected_session_id", sessions, entries, truncated
        case totalMatches = "total_matches", hasMore = "has_more", nextBeforeID = "next_before_id"
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        protocolVersion = try values.decode(UInt32.self, forKey: .protocolVersion)
        guard protocolVersion == Self.protocolVersion else { throw ActivityModelError.unsupportedProtocolVersion }
        generatedAtUnixMs = try values.decode(Int64.self, forKey: .generatedAtUnixMs)
        selectedSessionID = try sanitized(values, .selectedSessionID, limit: 128)
        sessions = try values.decode([ActivitySession].self, forKey: .sessions)
        entries = try values.decode([SessionAction].self, forKey: .entries)
        truncated = try values.decodeIfPresent(Bool.self, forKey: .truncated) ?? false
        totalMatches = try values.decodeIfPresent(Int.self, forKey: .totalMatches) ?? entries.count
        hasMore = try values.decodeIfPresent(Bool.self, forKey: .hasMore) ?? false
        nextBeforeID = try values.decodeIfPresent(Int64.self, forKey: .nextBeforeID)
        guard generatedAtUnixMs > 0, sessions.count <= 50, entries.count <= 500,
              totalMatches >= entries.count,
              (!hasMore && nextBeforeID == nil) || (hasMore && nextBeforeID == entries.last?.id),
              selectedSessionID.isEmpty || sessions.contains(where: { $0.sessionID == selectedSessionID }) else {
            throw ActivityModelError.invalidProjection
        }
    }
}

public enum SessionActionOutcome: String, Encodable, Equatable, Sendable {
    case allow, ask, deny, block
}

public struct SessionLogQuery: Equatable, Sendable {
    public let sessionID: String?
    public let beforeID: Int64?
    public let search: String
    public let outcomes: [SessionActionOutcome]

    public init(
        sessionID: String? = nil,
        beforeID: Int64? = nil,
        search: String = "",
        outcomes: [SessionActionOutcome] = []
    ) {
        self.sessionID = sessionID
        self.beforeID = beforeID
        self.search = String(search.prefix(256))
        self.outcomes = outcomes
    }
}

public struct ActivitySession: Decodable, Identifiable, Equatable, Sendable {
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
        sessionID = try sanitizedRequired(values, .sessionID, limit: 128)
        agent = try sanitized(values, .agent, limit: 128)
        project = try sanitized(values, .project, limit: 128)
        startedAtUnixMs = try values.decode(Int64.self, forKey: .startedAtUnixMs)
        endedAtUnixMs = try values.decodeIfPresent(Int64.self, forKey: .endedAtUnixMs)
        auditedCalls = try values.decode(Int.self, forKey: .auditedCalls)
        active = try values.decode(Bool.self, forKey: .active)
        guard startedAtUnixMs > 0, auditedCalls >= 0 else { throw ActivityModelError.invalidProjection }
    }
}

public struct SessionAction: Decodable, Identifiable, Equatable, Sendable {
    public let id: Int64
    public let timestampUnixMs: Int64
    public let toolName: String
    public let summary: String
    public let action: String
    public let ruleID: String
    public let reason: String
    public let impact: String
    public let elapsedUs: Int64
    public let wouldAction: String
    public let policyAction: String
    public let effectiveAction: String
    public let adapter: String
    public let translationReason: String
    public let finalAction: String
    public let enforcer: String

    enum CodingKeys: String, CodingKey {
        case id, summary, action, reason, impact, adapter, enforcer
        case timestampUnixMs = "timestamp_unix_ms", toolName = "tool_name", ruleID = "rule_id"
        case elapsedUs = "elapsed_us", wouldAction = "would_action", policyAction = "policy_action"
        case effectiveAction = "effective_action", translationReason = "translation_reason"
        case finalAction = "final_action"
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(Int64.self, forKey: .id)
        timestampUnixMs = try values.decode(Int64.self, forKey: .timestampUnixMs)
        toolName = try sanitizedRequired(values, .toolName)
        summary = try sanitized(values, .summary)
        action = try sanitizedRequired(values, .action)
        ruleID = try sanitized(values, .ruleID)
        reason = try sanitized(values, .reason)
        impact = try sanitized(values, .impact)
        elapsedUs = try values.decode(Int64.self, forKey: .elapsedUs)
        wouldAction = try sanitized(values, .wouldAction)
        policyAction = try sanitized(values, .policyAction)
        effectiveAction = try sanitized(values, .effectiveAction)
        adapter = try sanitized(values, .adapter)
        translationReason = try sanitized(values, .translationReason)
        finalAction = try sanitized(values, .finalAction)
        enforcer = try sanitized(values, .enforcer)
        guard id > 0, timestampUnixMs > 0, elapsedUs >= 0 else { throw ActivityModelError.invalidProjection }
    }
}

public struct SessionActionDetailV1: Decodable, Equatable, Sendable {
    public static let protocolVersion: UInt32 = 1
    public let protocolVersion: UInt32
    public let actionID: Int64
    public let sessionID: String
    public let command: String

    enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol_version", actionID = "action_id"
        case sessionID = "session_id", command
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        protocolVersion = try values.decode(UInt32.self, forKey: .protocolVersion)
        guard protocolVersion == Self.protocolVersion else { throw ActivityModelError.unsupportedProtocolVersion }
        actionID = try values.decode(Int64.self, forKey: .actionID)
        sessionID = try sanitizedRequired(values, .sessionID, limit: 128)
        command = try sanitized(values, .command, limit: 4_096)
        guard actionID > 0 else { throw ActivityModelError.invalidProjection }
    }
}

public enum ActivityModelError: Error, Equatable, Sendable {
    case unsupportedProtocolVersion
    case invalidProjection
}

public protocol ActivityControlling: Sendable {
    func fetchNetwork() async throws -> NetworkSnapshotV1
    func fetchSessionLog(_ query: SessionLogQuery) async throws -> SessionLogSnapshotV1
    func fetchSessionActionDetail(sessionID: String, actionID: Int64) async throws -> SessionActionDetailV1
}

private func sanitized<Key: CodingKey>(
    _ values: KeyedDecodingContainer<Key>,
    _ key: Key,
    limit: Int = 512
) throws -> String {
    DisplaySanitizer.text(try values.decodeIfPresent(String.self, forKey: key) ?? "", limit: limit).text
}

private func sanitizedRequired<Key: CodingKey>(
    _ values: KeyedDecodingContainer<Key>,
    _ key: Key,
    limit: Int = 512
) throws -> String {
    let value = try sanitized(values, key, limit: limit)
    guard !value.isEmpty else { throw ActivityModelError.invalidProjection }
    return value
}
