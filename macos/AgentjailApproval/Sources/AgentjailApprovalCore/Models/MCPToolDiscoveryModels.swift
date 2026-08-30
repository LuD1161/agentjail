import Foundation

public enum MCPToolDiscoveryStatus: String, Decodable, Equatable, Sendable {
    case connected
    case authRequired = "auth_required"
    case unreachable
    case timeout
}

public struct MCPToolDiscoverySnapshot: Decodable, Equatable, Sendable {
    public static let supportedProtocolVersion = 1
    public let protocolVersion: Int
    public let servers: [MCPServerToolDiscovery]

    enum CodingKeys: String, CodingKey { case protocolVersion = "protocol_version", servers }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        protocolVersion = try values.decode(Int.self, forKey: .protocolVersion)
        servers = try values.decode([MCPServerToolDiscovery].self, forKey: .servers)
        guard protocolVersion == Self.supportedProtocolVersion, servers.count <= 64 else {
            throw DashboardModelError.invalidProjection
        }
    }
}

public struct MCPServerToolDiscovery: Decodable, Equatable, Sendable {
    public let server: String
    public let status: MCPToolDiscoveryStatus
    public let tools: [String]

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        server = DisplaySanitizer.text(try values.decode(String.self, forKey: .server), limit: 128).text
        status = try values.decode(MCPToolDiscoveryStatus.self, forKey: .status)
        tools = try values.decode([String].self, forKey: .tools).map {
            DisplaySanitizer.text($0, limit: 128).text
        }
        guard !server.isEmpty, tools.count <= 128, tools.allSatisfy({ !$0.isEmpty }) else {
            throw DashboardModelError.invalidProjection
        }
    }

    private enum CodingKeys: String, CodingKey { case server, status, tools }
}

public protocol MCPToolDiscoveryControlling: Sendable {
    func discoverTools() async throws -> MCPToolDiscoverySnapshot
}
