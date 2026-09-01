import AppKit

enum RegoSyntaxTokenKind: Equatable, Sendable {
    case plain
    case comment
    case keyword
    case string
    case number
    case operatorSymbol
}

struct RegoSyntaxToken: Equatable, Sendable {
    let kind: RegoSyntaxTokenKind
    let text: String
}

enum RegoSyntaxHighlighter {
    private static let keywords: Set<String> = [
        "as", "contains", "default", "else", "every", "false", "if", "import",
        "in", "not", "null", "package", "some", "true", "with",
    ]
    private static let operatorCharacters = CharacterSet(charactersIn: ":=<>!+-*/%|&")

    static func highlight(_ source: String) -> AttributedString {
        let highlighted = NSMutableAttributedString()
        for token in tokens(in: source) {
            highlighted.append(NSAttributedString(
                string: token.text,
                attributes: [.foregroundColor: color(for: token.kind)]
            ))
        }
        return AttributedString(highlighted)
    }

    static func tokens(in source: String) -> [RegoSyntaxToken] {
        var result: [RegoSyntaxToken] = []
        var index = source.startIndex

        while index < source.endIndex {
            let start = index
            let character = source[index]

            if character == "#" {
                while index < source.endIndex, source[index] != "\n" {
                    index = source.index(after: index)
                }
                append(.comment, source[start..<index], to: &result)
                continue
            }

            if character == "\"" {
                index = source.index(after: index)
                var escaped = false
                while index < source.endIndex {
                    let current = source[index]
                    index = source.index(after: index)
                    if current == "\"", !escaped { break }
                    if current == "\\", !escaped {
                        escaped = true
                    } else {
                        escaped = false
                    }
                }
                append(.string, source[start..<index], to: &result)
                continue
            }

            if character.isLetter || character == "_" {
                index = source.index(after: index)
                while index < source.endIndex {
                    let current = source[index]
                    guard current.isLetter || current.isNumber || current == "_" else { break }
                    index = source.index(after: index)
                }
                let text = String(source[start..<index])
                result.append(RegoSyntaxToken(kind: keywords.contains(text) ? .keyword : .plain, text: text))
                continue
            }

            if character.isNumber {
                index = source.index(after: index)
                while index < source.endIndex {
                    let current = source[index]
                    guard current.isNumber || current == "." else { break }
                    index = source.index(after: index)
                }
                append(.number, source[start..<index], to: &result)
                continue
            }

            if character.unicodeScalars.allSatisfy({ operatorCharacters.contains($0) }) {
                index = source.index(after: index)
                while index < source.endIndex,
                      source[index].unicodeScalars.allSatisfy({ operatorCharacters.contains($0) }) {
                    index = source.index(after: index)
                }
                append(.operatorSymbol, source[start..<index], to: &result)
                continue
            }

            index = source.index(after: index)
            while index < source.endIndex {
                let current = source[index]
                guard current != "#", current != "\"", !current.isLetter, current != "_", !current.isNumber,
                      !current.unicodeScalars.allSatisfy({ operatorCharacters.contains($0) })
                else { break }
                index = source.index(after: index)
            }
            append(.plain, source[start..<index], to: &result)
        }
        return result
    }

    private static func append(
        _ kind: RegoSyntaxTokenKind,
        _ text: Substring,
        to tokens: inout [RegoSyntaxToken]
    ) {
        guard !text.isEmpty else { return }
        tokens.append(RegoSyntaxToken(kind: kind, text: String(text)))
    }

    private static func color(for kind: RegoSyntaxTokenKind) -> NSColor {
        switch kind {
        case .plain: .labelColor
        case .comment: .secondaryLabelColor
        case .keyword: .systemPurple
        case .string: .systemGreen
        case .number: .systemOrange
        case .operatorSymbol: .systemBlue
        }
    }
}

actor RegoHighlightCache {
    static let shared = RegoHighlightCache()

    private let capacity: Int
    private var entries: [String: AttributedString] = [:]
    private var recency: [String] = []

    init(capacity: Int = 16) {
        self.capacity = max(capacity, 1)
    }

    func highlighted(_ source: String) -> AttributedString {
        if let cached = entries[source] {
            markRecent(source)
            return cached
        }

        let highlighted = RegoSyntaxHighlighter.highlight(source)
        entries[source] = highlighted
        markRecent(source)
        while entries.count > capacity, let oldest = recency.first {
            recency.removeFirst()
            entries.removeValue(forKey: oldest)
        }
        return highlighted
    }

    private func markRecent(_ source: String) {
        recency.removeAll { $0 == source }
        recency.append(source)
    }
}
