public struct DisplaySanitization: Equatable, Sendable {
    public let text: String
    public let didSanitizeUnsafeScalars: Bool
    public let didTruncateGraphemes: Bool

    public init(
        text: String,
        didSanitizeUnsafeScalars: Bool,
        didTruncateGraphemes: Bool
    ) {
        self.text = text
        self.didSanitizeUnsafeScalars = didSanitizeUnsafeScalars
        self.didTruncateGraphemes = didTruncateGraphemes
    }
}

public enum DisplaySanitizer {
    public static func text(_ input: String?, limit: Int) -> DisplaySanitization {
        precondition(limit > 0, "Display text limits must be positive")

        let normalized = normalize(input ?? "")
        return truncate(
            normalized.text,
            didSanitizeUnsafeScalars: normalized.didSanitizeUnsafeScalars,
            limit: limit
        )
    }

    public static func reason(_ input: String?, limit: Int) -> DisplaySanitization {
        let result = text(input, limit: limit)
        guard !result.text.isEmpty else {
            return DisplaySanitization(
                text: "No reason provided",
                didSanitizeUnsafeScalars: result.didSanitizeUnsafeScalars,
                didTruncateGraphemes: false
            )
        }
        return result
    }

    private static func normalize(_ input: String) -> (text: String, didSanitizeUnsafeScalars: Bool) {
        var filtered = String.UnicodeScalarView()
        var didSanitizeUnsafeScalars = false

        for scalar in input.unicodeScalars {
            if isRemoved(scalar) {
                didSanitizeUnsafeScalars = true
                continue
            }
            if isControl(scalar) {
                didSanitizeUnsafeScalars = true
                filtered.append(" ")
                continue
            }
            filtered.append(scalar)
        }

        let normalizedWhitespace = String(filtered)
            .split(whereSeparator: { $0.isWhitespace })
            .joined(separator: " ")
        return (normalizedWhitespace, didSanitizeUnsafeScalars)
    }

    private static func truncate(
        _ value: String,
        didSanitizeUnsafeScalars: Bool,
        limit: Int
    ) -> DisplaySanitization {
        guard value.count > limit else {
            return DisplaySanitization(
                text: value,
                didSanitizeUnsafeScalars: didSanitizeUnsafeScalars,
                didTruncateGraphemes: false
            )
        }

        return DisplaySanitization(
            text: String(value.prefix(limit - 1)) + "…",
            didSanitizeUnsafeScalars: didSanitizeUnsafeScalars,
            didTruncateGraphemes: true
        )
    }

    private static func isRemoved(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x001B, 0x061C, 0x200E...0x200F, 0x202A...0x202E, 0x2066...0x2069:
            true
        default:
            false
        }
    }

    private static func isControl(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x0000...0x001F, 0x007F...0x009F:
            true
        default:
            false
        }
    }
}
