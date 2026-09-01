import AgentjailApprovalCore
import Foundation
import Testing
@testable import AgentjailApprovalApp

struct TokenChartSeriesTests {
    @Test func fillsMissingCalendarDaysWithZero() throws {
        let points = try JSONDecoder().decode([DashboardTokenDay].self, from: Data(#"""
        [
          {"day":"2026-08-01","input_tokens":10,"output_tokens":5,"cache_tokens":2},
          {"day":"2026-08-03","input_tokens":20,"output_tokens":7,"cache_tokens":3}
        ]
        """#.utf8))

        let series = TokenChartSeries.daily(points: points)

        #expect(series.map(\.day) == ["2026-08-01", "2026-08-02", "2026-08-03"])
        #expect(series.map(\.totalTokens) == [17, 0, 30])
    }

    @Test func handlesEmptyAndOutOfOrderInput() throws {
        let points = try JSONDecoder().decode([DashboardTokenDay].self, from: Data(#"""
        [
          {"day":"2026-08-02","input_tokens":2,"output_tokens":0,"cache_tokens":0},
          {"day":"2026-08-01","input_tokens":1,"output_tokens":0,"cache_tokens":0}
        ]
        """#.utf8))

        #expect(TokenChartSeries.daily(points: []).isEmpty)
        #expect(TokenChartSeries.daily(points: points).map(\.totalTokens) == [1, 2])
    }
}
