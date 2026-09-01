import Foundation
import Testing
@testable import AgentjailApprovalApp

struct TokenChartXAxisTests {
    @Test func selectsCalendarWeeksEvenWhenUsageDaysAreMissing() {
        let days = ["2026-08-01", "2026-08-02", "2026-08-15", "2026-08-30"]

        let labels = TokenChartXAxis.tickDates(from: days).map {
            TokenChartXAxis.label(for: $0, locale: Locale(identifier: "en_US_POSIX"))
        }
        #expect(labels == ["Aug 1", "Aug 8", "Aug 15", "Aug 22", "Aug 29"])
    }

    @Test func keepsTheRangeVisibleForShortSeries() {
        let dates = TokenChartXAxis.tickDates(from: ["2026-08-29", "2026-08-30"])
        #expect(dates.count == 1)
        #expect(TokenChartXAxis.tickDates(from: [], intervalDays: 7).isEmpty)
        #expect(TokenChartXAxis.tickDates(from: ["unknown"], intervalDays: 7).isEmpty)
    }

    @Test func formatsAnISODateForTheAxis() {
        #expect(TokenChartXAxis.label(for: "2026-08-30", locale: Locale(identifier: "en_US_POSIX")) == "Aug 30")
        #expect(TokenChartXAxis.label(for: "unknown", locale: Locale(identifier: "en_US_POSIX")) == "unknown")
    }
}
