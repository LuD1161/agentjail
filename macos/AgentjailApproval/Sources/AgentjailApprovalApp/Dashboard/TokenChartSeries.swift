import AgentjailApprovalCore
import Foundation

struct TokenChartPoint: Identifiable, Equatable {
    let day: String
    let date: Date
    let totalTokens: Int64

    var id: String { day }
}

enum TokenChartSeries {
    static func daily(points: [DashboardTokenDay]) -> [TokenChartPoint] {
        let observed = points.reduce(into: [Date: DashboardTokenDay]()) { result, point in
            guard let date = TokenChartXAxis.date(for: point.day) else { return }
            result[date] = point
        }
        guard let first = observed.keys.min(), let last = observed.keys.max() else { return [] }

        var series: [TokenChartPoint] = []
        var date = first
        while date <= last {
            let source = observed[date]
            series.append(TokenChartPoint(
                day: TokenChartXAxis.day(for: date),
                date: date,
                totalTokens: source?.totalTokens ?? 0
            ))
            guard let next = TokenChartXAxis.date(byAddingDays: 1, to: date) else { break }
            date = next
        }
        return series
    }
}
