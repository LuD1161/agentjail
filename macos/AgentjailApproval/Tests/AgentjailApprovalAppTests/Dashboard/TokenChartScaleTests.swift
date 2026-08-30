import Foundation
import XCTest
@testable import AgentjailApprovalApp

final class TokenChartScaleTests: XCTestCase {
    private let locale = Locale(identifier: "en_US_POSIX")

    func testScaleTracksVisibleTokenMagnitude() {
        XCTAssertEqual(TokenChartScale.fitting(maximum: 2_000_000_000).label(for: 0, locale: locale), "0")
        XCTAssertEqual(TokenChartScale.fitting(maximum: 900).label(for: 900, locale: locale), "900")
        XCTAssertEqual(TokenChartScale.fitting(maximum: 90_000).label(for: 90_000, locale: locale), "90K")
        XCTAssertEqual(TokenChartScale.fitting(maximum: 2_000_000).label(for: 1_500_000, locale: locale), "1.5M")
        XCTAssertEqual(TokenChartScale.fitting(maximum: 2_000_000_000).label(for: 1_500_000_000, locale: locale), "1.5B")
    }

    func testScaleBoundaryChangesOnlyAtWholeUnit() {
        XCTAssertEqual(TokenChartScale.fitting(maximum: 999_499).label(for: 999_499, locale: locale), "999.5K")
        XCTAssertEqual(TokenChartScale.fitting(maximum: 999_500).label(for: 999_500, locale: locale), "1M")
        XCTAssertEqual(TokenChartScale.fitting(maximum: 1_000_000).label(for: 1_000_000, locale: locale), "1M")
    }
}
