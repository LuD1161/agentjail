import Foundation

public struct ClaudeMCPConfigAdapter: MCPConfigAdapting {
    public let sourceClient = MCPSourceClient.claudeCode
    public let sourceLabel = "~/.claude.json"
    public let version = "claude-code-json-v1"

    public init() {}

    public func parse(_ data: Data) -> [MCPInventoryItem] {
        JSONMCPConfigParser.parse(
            data,
            sourceClient: sourceClient,
            sourceLabel: sourceLabel,
            adapterVersion: version
        )
    }
}

public struct CursorMCPConfigAdapter: MCPConfigAdapting {
    public let sourceClient = MCPSourceClient.cursor
    public let sourceLabel = "~/.cursor/mcp.json"
    public let version = "cursor-json-v1"

    public init() {}

    public func parse(_ data: Data) -> [MCPInventoryItem] {
        JSONMCPConfigParser.parse(
            data,
            sourceClient: sourceClient,
            sourceLabel: sourceLabel,
            adapterVersion: version
        )
    }
}

public struct CodexMCPConfigAdapter: MCPConfigAdapting {
    public let sourceClient = MCPSourceClient.codex
    public let sourceLabel = "~/.codex/config.toml"
    public let version = "codex-toml-v1"

    public init() {}

    public func parse(_ data: Data) -> [MCPInventoryItem] {
        guard let text = String(data: data, encoding: .utf8) else {
            return [sourceIssue("The configuration is not valid UTF-8.")]
        }

        var builders: [String: CodexServerBuilder] = [:]
        var order: [String] = []
        var currentServer: String?
        var currentDepth = 0
        var sourceHasMalformedMCP = false

        for rawLine in text.components(separatedBy: .newlines) {
            let line = TOMLLine.stripComment(rawLine).trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty else { continue }

            if line.hasPrefix("[") {
                guard line.hasSuffix("]"), !line.hasPrefix("[[") else {
                    if line.contains("mcp_servers") { sourceHasMalformedMCP = true }
                    currentServer = nil
                    continue
                }
                let body = String(line.dropFirst().dropLast())
                guard let components = TOMLLine.dottedKey(body), components.first == "mcp_servers", components.count >= 2 else {
                    if body.contains("mcp_servers") { sourceHasMalformedMCP = true }
                    currentServer = nil
                    continue
                }
                let name = components[1]
                guard !name.isEmpty else {
                    sourceHasMalformedMCP = true
                    currentServer = nil
                    continue
                }
                currentServer = name
                currentDepth = components.count
                if builders[name] == nil {
                    builders[name] = CodexServerBuilder(name: name)
                    order.append(name)
                } else if components.count == 2 {
                    builders[name]?.issue = "This server is declared more than once."
                }
                continue
            }

            guard let currentServer, currentDepth == 2 else { continue }
            guard let assignment = TOMLLine.assignment(line) else {
                builders[currentServer]?.issue = "This server contains malformed configuration."
                continue
            }
            switch assignment.key {
            case "command":
                guard let value = TOMLLine.stringValue(assignment.value), !value.isEmpty else {
                    builders[currentServer]?.issue = "The local command is malformed."
                    continue
                }
                builders[currentServer]?.command = value
            case "url":
                guard let value = TOMLLine.stringValue(assignment.value), !value.isEmpty else {
                    builders[currentServer]?.issue = "The remote URL is malformed."
                    continue
                }
                builders[currentServer]?.url = value
            case "enabled":
                switch assignment.value {
                case "true": builders[currentServer]?.enabled = true
                case "false": builders[currentServer]?.enabled = false
                default: builders[currentServer]?.issue = "The enabled value must be true or false."
                }
            default:
                continue
            }
        }

        var items = order.compactMap { name in
            builders[name]?.item(
                sourceClient: sourceClient,
                sourceLabel: sourceLabel,
                adapterVersion: version
            )
        }
        if sourceHasMalformedMCP {
            items.append(sourceIssue("The MCP table structure is malformed or unsupported."))
        }
        return items
    }

    private func sourceIssue(_ detail: String) -> MCPInventoryItem {
        MCPInventoryItem(
            id: "\(sourceClient.rawValue)|\(sourceLabel)|source-issue",
            name: "Configuration issue",
            sourceClient: sourceClient,
            sourceLabel: sourceLabel,
            adapterVersion: version,
            kind: .unknown,
            target: "Not available",
            status: .issue(detail)
        )
    }
}

private enum JSONMCPConfigParser {
    static func parse(
        _ data: Data,
        sourceClient: MCPSourceClient,
        sourceLabel: String,
        adapterVersion: String
    ) -> [MCPInventoryItem] {
        let root: Any
        do {
            root = try JSONSerialization.jsonObject(with: data)
        } catch {
            return [sourceIssue(
                "The configuration is malformed JSON.",
                sourceClient: sourceClient,
                sourceLabel: sourceLabel,
                adapterVersion: adapterVersion
            )]
        }
        guard let object = root as? [String: Any] else {
            return [sourceIssue(
                "The configuration root must be an object.",
                sourceClient: sourceClient,
                sourceLabel: sourceLabel,
                adapterVersion: adapterVersion
            )]
        }
        guard let rawServers = object["mcpServers"] else { return [] }
        guard let servers = rawServers as? [String: Any] else {
            return [sourceIssue(
                "The mcpServers value must be an object.",
                sourceClient: sourceClient,
                sourceLabel: sourceLabel,
                adapterVersion: adapterVersion
            )]
        }

        return servers.keys.sorted().map { rawName in
            let safeName = MCPDisplayRedactor.serverName(rawName)
            let id = "\(sourceClient.rawValue)|\(sourceLabel)|\(safeName)"
            guard let server = servers[rawName] as? [String: Any] else {
                return MCPInventoryItem(
                    id: id,
                    name: safeName,
                    sourceClient: sourceClient,
                    sourceLabel: sourceLabel,
                    adapterVersion: adapterVersion,
                    kind: .unknown,
                    target: "Not available",
                    status: .issue("This server entry must be an object.")
                )
            }
            return JSONServerBuilder(name: safeName, object: server).item(
                id: id,
                sourceClient: sourceClient,
                sourceLabel: sourceLabel,
                adapterVersion: adapterVersion
            )
        }
    }

    private static func sourceIssue(
        _ detail: String,
        sourceClient: MCPSourceClient,
        sourceLabel: String,
        adapterVersion: String
    ) -> MCPInventoryItem {
        MCPInventoryItem(
            id: "\(sourceClient.rawValue)|\(sourceLabel)|source-issue",
            name: "Configuration issue",
            sourceClient: sourceClient,
            sourceLabel: sourceLabel,
            adapterVersion: adapterVersion,
            kind: .unknown,
            target: "Not available",
            status: .issue(detail)
        )
    }
}

private struct JSONServerBuilder {
    let name: String
    let object: [String: Any]

    func item(
        id: String,
        sourceClient: MCPSourceClient,
        sourceLabel: String,
        adapterVersion: String
    ) -> MCPInventoryItem {
        let command = object["command"] as? String
        let url = object["url"] as? String
        let declaredType = (object["type"] as? String)?.lowercased()
        let enabled = (object["enabled"] as? Bool) ?? !((object["disabled"] as? Bool) ?? false)
        let args = object["args"] as? [Any]

        let shapeIssue: String?
        if object["command"] != nil, command == nil {
            shapeIssue = "The local command must be a string."
        } else if object["url"] != nil, url == nil {
            shapeIssue = "The remote URL must be a string."
        } else if object["type"] != nil, declaredType == nil {
            shapeIssue = "The server transport must be a string."
        } else if object["args"] != nil, args == nil || args?.contains(where: { !($0 is String) }) == true {
            shapeIssue = "The server arguments must be an array of strings."
        } else if object["env"] != nil, !(object["env"] is [String: Any]) {
            shapeIssue = "The server environment must be an object."
        } else if object["headers"] != nil, !(object["headers"] is [String: Any]) {
            shapeIssue = "The server headers must be an object."
        } else if object["enabled"] != nil, !(object["enabled"] is Bool) {
            shapeIssue = "The enabled value must be true or false."
        } else if object["disabled"] != nil, !(object["disabled"] is Bool) {
            shapeIssue = "The disabled value must be true or false."
        } else if command != nil, url != nil {
            shapeIssue = "A server cannot declare both a command and a URL."
        } else if let url, !MCPDisplayRedactor.isValidRemoteURL(url) {
            shapeIssue = "The remote URL is invalid."
        } else if command == nil, url == nil {
            shapeIssue = "The server is missing a command or URL."
        } else if let declaredType, !["stdio", "http", "sse", "streamable-http"].contains(declaredType) {
            shapeIssue = "The server transport is unknown."
        } else {
            shapeIssue = nil
        }

        let kind: MCPServerKind
        let target: String
        if let command {
            kind = .local
            target = MCPDisplayRedactor.localCommand(command, argumentCount: args?.count ?? 0)
        } else if let url {
            kind = .remote
            target = MCPDisplayRedactor.remoteOrigin(url)
        } else {
            kind = .unknown
            target = "Not available"
        }

        let status: MCPConfigurationStatus
        if let shapeIssue {
            status = .issue(shapeIssue)
        } else {
            status = enabled ? .configured : .disabled
        }
        return MCPInventoryItem(
            id: id,
            name: name,
            sourceClient: sourceClient,
            sourceLabel: sourceLabel,
            adapterVersion: adapterVersion,
            kind: kind,
            target: target,
            status: status
        )
    }
}

private struct CodexServerBuilder {
    let name: String
    var command: String?
    var url: String?
    var enabled = true
    var issue: String?

    func item(
        sourceClient: MCPSourceClient,
        sourceLabel: String,
        adapterVersion: String
    ) -> MCPInventoryItem {
        let safeName = MCPDisplayRedactor.serverName(name)
        var effectiveIssue = issue
        if command != nil, url != nil {
            effectiveIssue = "A server cannot declare both a command and a URL."
        } else if command == nil, url == nil, effectiveIssue == nil {
            effectiveIssue = "The server is missing a command or URL."
        }

        let kind: MCPServerKind
        let target: String
        if let command {
            kind = .local
            target = MCPDisplayRedactor.localCommand(command, argumentCount: 0)
        } else if let url {
            kind = .remote
            target = MCPDisplayRedactor.remoteOrigin(url)
            if !MCPDisplayRedactor.isValidRemoteURL(url), effectiveIssue == nil {
                effectiveIssue = "The remote URL is invalid."
            }
        } else {
            kind = .unknown
            target = "Not available"
        }

        return MCPInventoryItem(
            id: "\(sourceClient.rawValue)|\(sourceLabel)|\(safeName)",
            name: safeName,
            sourceClient: sourceClient,
            sourceLabel: sourceLabel,
            adapterVersion: adapterVersion,
            kind: kind,
            target: target,
            status: effectiveIssue.map(MCPConfigurationStatus.issue) ?? (enabled ? .configured : .disabled)
        )
    }
}

private enum MCPDisplayRedactor {
    private static let sensitiveFragments = [
        "token", "secret", "password", "passwd", "api_key", "apikey", "authorization", "bearer",
    ]

    static func serverName(_ raw: String) -> String {
        let cleaned = printable(raw).trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleaned.isEmpty else { return "Unnamed server" }
        guard !looksSensitive(cleaned) else { return "[redacted server name]" }
        return String(cleaned.prefix(120))
    }

    static func localCommand(_ raw: String, argumentCount: Int) -> String {
        guard !looksSensitive(raw) else { return "[redacted command]" }
        let firstToken = raw.split(whereSeparator: \.isWhitespace).first.map(String.init) ?? raw
        let executable = URL(fileURLWithPath: firstToken).lastPathComponent
        let cleaned = printable(executable)
        guard !cleaned.isEmpty, !looksSensitive(cleaned) else { return "[redacted command]" }
        if argumentCount == 0 {
            return String(cleaned.prefix(80))
        }
        let noun = argumentCount == 1 ? "argument" : "arguments"
        return "\(String(cleaned.prefix(80))) • \(argumentCount) \(noun) hidden"
    }

    static func remoteOrigin(_ raw: String) -> String {
        guard var components = URLComponents(string: raw),
              let scheme = components.scheme?.lowercased(),
              ["http", "https"].contains(scheme),
              let host = components.host?.lowercased(),
              !host.isEmpty,
              !looksSensitive(host)
        else {
            return looksSensitive(raw) ? "[redacted origin]" : "[invalid remote origin]"
        }
        components.user = nil
        components.password = nil
        components.path = ""
        components.query = nil
        components.fragment = nil
        let defaultPort = (scheme == "https" && components.port == 443) || (scheme == "http" && components.port == 80)
        let port = defaultPort ? "" : components.port.map { ":\($0)" } ?? ""
        return "\(scheme)://\(host)\(port)"
    }

    static func isValidRemoteURL(_ raw: String) -> Bool {
        guard let components = URLComponents(string: raw),
              let scheme = components.scheme?.lowercased(),
              ["http", "https"].contains(scheme),
              let host = components.host,
              !host.isEmpty
        else {
            return false
        }
        return true
    }

    private static func looksSensitive(_ value: String) -> Bool {
        let lower = value.lowercased()
        if sensitiveFragments.contains(where: lower.contains) { return true }
        if lower.contains("-----begin ") { return true }
        if lower.hasPrefix("sk-") || lower.hasPrefix("ghp_") || lower.hasPrefix("github_pat_") { return true }
        return false
    }

    private static func printable(_ value: String) -> String {
        DisplaySanitizer.text(value, limit: max(value.count, 1)).text
    }
}

private enum TOMLLine {
    static func stripComment(_ line: String) -> String {
        var quote: Character?
        var escaped = false
        var result = ""
        for character in line {
            if escaped {
                result.append(character)
                escaped = false
                continue
            }
            if character == "\\", quote == "\"" {
                result.append(character)
                escaped = true
                continue
            }
            if character == "\"" || character == "'" {
                if quote == character {
                    quote = nil
                } else if quote == nil {
                    quote = character
                }
                result.append(character)
                continue
            }
            if character == "#", quote == nil { break }
            result.append(character)
        }
        return result
    }

    static func dottedKey(_ raw: String) -> [String]? {
        var values: [String] = []
        var current = ""
        var quote: Character?
        var escaped = false
        for character in raw {
            if escaped {
                current.append(character)
                escaped = false
                continue
            }
            if character == "\\", quote == "\"" {
                escaped = true
                continue
            }
            if character == "\"" || character == "'" {
                if quote == character {
                    quote = nil
                } else if quote == nil {
                    quote = character
                } else {
                    current.append(character)
                }
                continue
            }
            if character == ".", quote == nil {
                let value = current.trimmingCharacters(in: .whitespaces)
                guard !value.isEmpty else { return nil }
                values.append(value)
                current = ""
                continue
            }
            current.append(character)
        }
        guard quote == nil else { return nil }
        let value = current.trimmingCharacters(in: .whitespaces)
        guard !value.isEmpty else { return nil }
        values.append(value)
        return values
    }

    static func assignment(_ line: String) -> (key: String, value: String)? {
        var quote: Character?
        var escaped = false
        for index in line.indices {
            let character = line[index]
            if escaped {
                escaped = false
                continue
            }
            if character == "\\", quote == "\"" {
                escaped = true
                continue
            }
            if character == "\"" || character == "'" {
                if quote == character { quote = nil } else if quote == nil { quote = character }
                continue
            }
            if character == "=", quote == nil {
                let key = line[..<index].trimmingCharacters(in: .whitespaces)
                let value = line[line.index(after: index)...].trimmingCharacters(in: .whitespaces)
                guard !key.isEmpty, !value.isEmpty else { return nil }
                return (key, value)
            }
        }
        return nil
    }

    static func stringValue(_ value: String) -> String? {
        guard value.count >= 2, let first = value.first, first == value.last, first == "\"" || first == "'" else {
            return nil
        }
        guard !value.hasPrefix("\"\"\"") && !value.hasPrefix("'''") else { return nil }
        let inner = String(value.dropFirst().dropLast())
        if first == "'" { return inner }
        var result = ""
        var escaped = false
        for character in inner {
            if escaped {
                switch character {
                case "\"", "\\": result.append(character)
                case "n": result.append("\n")
                case "r": result.append("\r")
                case "t": result.append("\t")
                default: return nil
                }
                escaped = false
            } else if character == "\\" {
                escaped = true
            } else {
                result.append(character)
            }
        }
        return escaped ? nil : result
    }
}
