import Foundation

public enum MCPSourceClient: String, CaseIterable, Equatable, Sendable {
    case claudeCode
    case codex
    case cursor

    public var displayName: String {
        switch self {
        case .claudeCode: "Claude Code"
        case .codex: "Codex"
        case .cursor: "Cursor"
        }
    }
}

public enum MCPServerKind: String, Equatable, Sendable {
    case local
    case remote
    case unknown

    public var displayName: String {
        switch self {
        case .local: "Local"
        case .remote: "Remote"
        case .unknown: "Unknown"
        }
    }
}

public enum MCPConfigurationStatus: Equatable, Sendable {
    case configured
    case disabled
    case issue(String)

    public var displayName: String {
        switch self {
        case .configured: "Configured"
        case .disabled: "Disabled"
        case .issue: "Configuration issue"
        }
    }

    public var detail: String? {
        guard case let .issue(detail) = self else { return nil }
        return detail
    }
}

public struct MCPInventoryItem: Identifiable, Equatable, Sendable {
    public let id: String
    public let name: String
    public let sourceClient: MCPSourceClient
    public let sourceLabel: String
    public let adapterVersion: String
    public let kind: MCPServerKind
    public let target: String
    public let status: MCPConfigurationStatus
    public let duplicateCount: Int

    public init(
        id: String,
        name: String,
        sourceClient: MCPSourceClient,
        sourceLabel: String,
        adapterVersion: String,
        kind: MCPServerKind,
        target: String,
        status: MCPConfigurationStatus,
        duplicateCount: Int = 1
    ) {
        self.id = id
        self.name = name
        self.sourceClient = sourceClient
        self.sourceLabel = sourceLabel
        self.adapterVersion = adapterVersion
        self.kind = kind
        self.target = target
        self.status = status
        self.duplicateCount = duplicateCount
    }

    public var isDuplicate: Bool { duplicateCount > 1 }
}

public struct MCPInventorySnapshot: Equatable, Sendable {
    public let items: [MCPInventoryItem]

    public init(items: [MCPInventoryItem]) {
        self.items = items
    }

    public var configuredCount: Int {
        items.reduce(into: 0) { count, item in
            if item.status == .configured {
                count += 1
            }
        }
    }

    public var issueCount: Int {
        items.reduce(into: 0) { count, item in
            if case .issue = item.status {
                count += 1
            }
        }
    }

    public var duplicateCount: Int {
        Set(items.filter(\.isDuplicate).map { MCPIdentity.normalize($0.name) }).count
    }
}

public enum MCPConfigFileReadResult: Equatable, Sendable {
    case missing
    case data(Data)
    case unreadable
}

public protocol MCPConfigFileReading {
    func readFile(at path: String) -> MCPConfigFileReadResult
}

public struct SystemMCPConfigFileReader: MCPConfigFileReading {
    static let maximumBytes = 2 * 1024 * 1024

    public init() {}

    public func readFile(at path: String) -> MCPConfigFileReadResult {
        guard FileManager.default.fileExists(atPath: path) else { return .missing }
        let url = URL(fileURLWithPath: path).resolvingSymlinksInPath()
        do {
            let values = try url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
            guard values.isRegularFile == true, values.fileSize.map({ $0 <= Self.maximumBytes }) ?? false else {
                return .unreadable
            }
            let handle = try FileHandle(forReadingFrom: url)
            defer { try? handle.close() }
            let data = try handle.read(upToCount: Self.maximumBytes + 1) ?? Data()
            guard data.count <= Self.maximumBytes else {
                return .unreadable
            }
            return .data(data)
        } catch {
            return .unreadable
        }
    }
}

public protocol MCPConfigAdapting {
    var sourceClient: MCPSourceClient { get }
    var sourceLabel: String { get }
    var version: String { get }
    func parse(_ data: Data) -> [MCPInventoryItem]
}

public struct MCPInventoryDiscovery {
    private let reader: any MCPConfigFileReading

    public init(reader: any MCPConfigFileReading = SystemMCPConfigFileReader()) {
        self.reader = reader
    }

    public func discover(homeDirectory: String) -> MCPInventorySnapshot {
        let sources: [(path: String, adapter: any MCPConfigAdapting)] = [
            (
                path: URL(fileURLWithPath: homeDirectory).appendingPathComponent(".claude.json").path,
                adapter: ClaudeMCPConfigAdapter()
            ),
            (
                path: URL(fileURLWithPath: homeDirectory).appendingPathComponent(".codex/config.toml").path,
                adapter: CodexMCPConfigAdapter()
            ),
            (
                path: URL(fileURLWithPath: homeDirectory).appendingPathComponent(".cursor/mcp.json").path,
                adapter: CursorMCPConfigAdapter()
            ),
        ]

        var items: [MCPInventoryItem] = []
        for source in sources {
            switch reader.readFile(at: source.path) {
            case .missing:
                continue
            case let .data(data):
                items.append(contentsOf: source.adapter.parse(data))
            case .unreadable:
                items.append(MCPInventoryItem(
                    id: "\(source.adapter.sourceClient.rawValue)|\(source.adapter.sourceLabel)|unreadable",
                    name: "Configuration issue",
                    sourceClient: source.adapter.sourceClient,
                    sourceLabel: source.adapter.sourceLabel,
                    adapterVersion: source.adapter.version,
                    kind: .unknown,
                    target: "Not available",
                    status: .issue("AgentJail could not safely read this configuration file.")
                ))
            }
        }

        let counts = Dictionary(grouping: items.filter { item in
            if case .issue = item.status { return false }
            return item.name != "[redacted server name]" && item.name != "Unnamed server"
        }, by: { MCPIdentity.normalize($0.name) }).mapValues(\.count)

        let normalized = items.map { item in
            MCPInventoryItem(
                id: item.id,
                name: item.name,
                sourceClient: item.sourceClient,
                sourceLabel: item.sourceLabel,
                adapterVersion: item.adapterVersion,
                kind: item.kind,
                target: item.target,
                status: item.status,
                duplicateCount: counts[MCPIdentity.normalize(item.name), default: 1]
            )
        }
        .sorted {
            if $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedSame {
                return $0.sourceClient.displayName < $1.sourceClient.displayName
            }
            return $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
        }

        return MCPInventorySnapshot(items: normalized)
    }
}

enum MCPIdentity {
    static func normalize(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }
}
