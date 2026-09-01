import AgentjailApprovalCore
import Foundation
import XCTest
@testable import AgentjailApprovalApp

final class DashboardActivityReportTests: XCTestCase {
    private let locale = Locale(identifier: "en_US")

    func testEmptyActivityReportsNoRecordedHistory() throws {
        let report = DashboardActivityReport(
            activity: [],
            referenceDate: try date("2026-08-30"),
            locale: locale
        )

        XCTAssertEqual(report.headerDetail, "No recorded protection activity yet")
        XCTAssertEqual(report.cardDetail, "No audited activity recorded yet")
    }

    func testZeroCountDaysDoNotClaimActivity() throws {
        let report = DashboardActivityReport(
            activity: try activity([("2026-08-30", 0)]),
            referenceDate: try date("2026-08-30"),
            locale: locale
        )

        XCTAssertEqual(report.headerDetail, "No recorded protection activity yet")
        XCTAssertEqual(report.cardDetail, "No audited activity recorded yet")
    }

    func testSingleCurrentUTCDayReportsToday() throws {
        let report = DashboardActivityReport(
            activity: try activity([("2026-08-30", 2_754)]),
            referenceDate: try date("2026-08-30"),
            locale: locale
        )

        XCTAssertEqual(report.headerDetail, "Protection activity recorded today")
        XCTAssertEqual(report.cardDetail, "2,754 audited calls today")
    }

    func testSingleEarlierUTCDayReportsItsStartDate() throws {
        let report = DashboardActivityReport(
            activity: try activity([("2026-08-28", 42)]),
            referenceDate: try date("2026-08-30"),
            locale: locale
        )

        XCTAssertEqual(report.headerDetail, "Protection activity recorded on Aug 28, 2026")
        XCTAssertEqual(report.cardDetail, "42 audited calls on Aug 28, 2026")
    }

    func testMultipleDaysStateActiveCoverageAndObservedWindow() throws {
        let report = DashboardActivityReport(
            activity: try activity([
                ("2026-08-25", 100),
                ("2026-08-27", 250),
                ("2026-08-30", 650),
            ]),
            referenceDate: try date("2026-08-30"),
            locale: locale
        )

        XCTAssertEqual(report.headerDetail, "Protection activity recorded on 3 days")
        XCTAssertEqual(report.cardDetail, "1,000 audited calls on 3 days · Aug 25, 2026–Aug 30, 2026")
    }

    private func activity(_ values: [(String, Int64)]) throws -> [DashboardDay] {
        let objects = values.map { ["day": $0.0, "count": $0.1] as [String: Any] }
        let data = try JSONSerialization.data(withJSONObject: objects)
        return try JSONDecoder().decode([DashboardDay].self, from: data)
    }

    private func date(_ day: String) throws -> Date {
        let formatter = DateFormatter()
        formatter.calendar = Calendar(identifier: .iso8601)
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd"
        return try XCTUnwrap(formatter.date(from: day))
    }
}
