import XCTest
@testable import AgentjailApprovalCore

final class DisplaySanitizerTests: XCTestCase {
    func testControlsAreReplacedExceptEscapeIsRemoved() {
        for value in 0x0000...0x001F {
            let scalar = UnicodeScalar(value)!
            let result = DisplaySanitizer.text("left\(scalar)right", limit: 64)

            XCTAssertEqual(result.text, value == 0x001B ? "leftright" : "left right", "U+\(hex(value))")
            XCTAssertTrue(result.didSanitizeUnsafeScalars, "U+\(hex(value))")
            XCTAssertFalse(result.didTruncateGraphemes, "U+\(hex(value))")
            XCTAssertNoForbiddenScalar(result.text, "U+\(hex(value))")
        }

        for value in 0x007F...0x009F {
            let scalar = UnicodeScalar(value)!
            let result = DisplaySanitizer.text("left\(scalar)right", limit: 64)

            XCTAssertEqual(result.text, "left right", "U+\(hex(value))")
            XCTAssertTrue(result.didSanitizeUnsafeScalars, "U+\(hex(value))")
            XCTAssertNoForbiddenScalar(result.text, "U+\(hex(value))")
        }
    }

    func testBidiScalarsAreRemoved() {
        let values = [0x061C] + Array(0x200E...0x200F) + Array(0x202A...0x202E) + Array(0x2066...0x2069)

        for value in values {
            let scalar = UnicodeScalar(value)!
            let result = DisplaySanitizer.text("left\(scalar)right", limit: 64)

            XCTAssertEqual(result.text, "leftright", "U+\(hex(value))")
            XCTAssertTrue(result.didSanitizeUnsafeScalars, "U+\(hex(value))")
            XCTAssertNoForbiddenScalar(result.text, "U+\(hex(value))")
        }
    }

    func testAnsiSequenceRemovesEscapeWithoutParsingTerminalSyntax() {
        let result = DisplaySanitizer.text("\u{001B}[31mDanger\u{001B}[0m", limit: 64)

        XCTAssertEqual(result.text, "[31mDanger[0m")
        XCTAssertTrue(result.didSanitizeUnsafeScalars)
        XCTAssertFalse(result.didTruncateGraphemes)
        XCTAssertNoForbiddenScalar(result.text)
    }

    func testWhitespaceIsCollapsedAndTrimmed() {
        let result = DisplaySanitizer.text("  one\r\n\ttwo\u{00A0}\u{2003}three  ", limit: 64)

        XCTAssertEqual(result.text, "one two three")
        XCTAssertTrue(result.didSanitizeUnsafeScalars)
        XCTAssertFalse(result.didTruncateGraphemes)
        XCTAssertNoForbiddenScalar(result.text)
    }

    func testTextResultFlagsDistinguishSanitizationFromTruncation() {
        XCTAssertEqual(
            DisplaySanitizer.text("safe", limit: 64),
            DisplaySanitization(text: "safe", didSanitizeUnsafeScalars: false, didTruncateGraphemes: false)
        )
        XCTAssertEqual(
            DisplaySanitizer.text("a\tb", limit: 64),
            DisplaySanitization(text: "a b", didSanitizeUnsafeScalars: true, didTruncateGraphemes: false)
        )
        XCTAssertEqual(
            DisplaySanitizer.text("abcdef", limit: 4),
            DisplaySanitization(text: "abc…", didSanitizeUnsafeScalars: false, didTruncateGraphemes: true)
        )
        XCTAssertEqual(
            DisplaySanitizer.text("a\tbcdef", limit: 4),
            DisplaySanitization(text: "a b…", didSanitizeUnsafeScalars: true, didTruncateGraphemes: true)
        )
    }

    func testTruncationKeepsExtendedGraphemeClustersWhole() {
        let cases = [
            ("e\u{0301}abc", "e\u{0301}…"),
            ("👍🏽abc", "👍🏽…"),
            ("🇺🇸abc", "🇺🇸…"),
            ("👩‍💻abc", "👩‍💻…"),
        ]

        for (input, expected) in cases {
            let result = DisplaySanitizer.text(input, limit: 2)
            XCTAssertEqual(result.text, expected)
            XCTAssertEqual(result.text.filter { $0 == "…" }.count, 1)
            XCTAssertEqual(result.text.count, 2)
            XCTAssertFalse(result.didSanitizeUnsafeScalars)
            XCTAssertTrue(result.didTruncateGraphemes)
            XCTAssertNoForbiddenScalar(result.text)
        }
    }

    func testReasonUsesExactFallbackForAbsentOrEmptyInput() {
        let cases: [(String?, Bool)] = [
            (nil, false),
            ("", false),
            (" \u{00A0}\u{2003} ", false),
            ("\u{001B}\r\n\t\u{202E}", true),
        ]

        for (input, didSanitizeUnsafeScalars) in cases {
            let result = DisplaySanitizer.reason(input, limit: 1)
            XCTAssertEqual(result.text, "No reason provided")
            XCTAssertEqual(result.didSanitizeUnsafeScalars, didSanitizeUnsafeScalars)
            XCTAssertFalse(result.didTruncateGraphemes)
            XCTAssertNoForbiddenScalar(result.text)
        }
    }

    func testReasonSanitizesAndTruncatesNonEmptyInput() {
        let result = DisplaySanitizer.reason("alpha\tbeta", limit: 6)

        XCTAssertEqual(result.text, "alpha…")
        XCTAssertTrue(result.didSanitizeUnsafeScalars)
        XCTAssertTrue(result.didTruncateGraphemes)
        XCTAssertNoForbiddenScalar(result.text)
    }

    private func XCTAssertNoForbiddenScalar(
        _ value: String,
        _ message: String = "",
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        for scalar in value.unicodeScalars {
            let isControl = (0x0000...0x001F).contains(scalar.value) || (0x007F...0x009F).contains(scalar.value)
            let isBidi = scalar.value == 0x061C
                || (0x200E...0x200F).contains(scalar.value)
                || (0x202A...0x202E).contains(scalar.value)
                || (0x2066...0x2069).contains(scalar.value)
            XCTAssertFalse(isControl || isBidi, "forbidden U+\(hex(Int(scalar.value))) \(message)", file: file, line: line)
        }
    }

    private func hex(_ value: Int) -> String {
        String(format: "%04X", value)
    }
}
