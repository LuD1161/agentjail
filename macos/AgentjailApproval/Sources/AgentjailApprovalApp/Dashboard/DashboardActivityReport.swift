import AgentjailApprovalCore
import Foundation

struct DashboardActivityReport: Equatable {
    let headerDetail: String
    let cardDetail: String

    init(activity: [DashboardDay], referenceDate: Date, locale: Locale = .current) {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0)!
        let dateStyle = Date.FormatStyle(locale: locale, calendar: calendar, timeZone: calendar.timeZone)
            .month(.abbreviated)
            .day()
            .year()

        let activeDays = activity.compactMap { point -> (date: Date, count: Int64)? in
            guard point.count > 0, let date = Self.date(from: point.day, calendar: calendar) else { return nil }
            return (date, point.count)
        }
        .sorted { $0.date < $1.date }

        guard let first = activeDays.first, let last = activeDays.last else {
            headerDetail = "No recorded protection activity yet"
            cardDetail = "No audited activity recorded yet"
            return
        }

        let total = activeDays.reduce(Int64(0)) { partial, point in
            let (sum, overflow) = partial.addingReportingOverflow(point.count)
            return overflow ? Int64.max : sum
        }
        let totalText = total.formatted(.number.locale(locale))
        let firstDate = first.date.formatted(dateStyle)

        if activeDays.count == 1 {
            if calendar.isDate(first.date, inSameDayAs: referenceDate) {
                headerDetail = "Protection activity recorded today"
                cardDetail = "\(totalText) audited calls today"
            } else {
                headerDetail = "Protection activity recorded on \(firstDate)"
                cardDetail = "\(totalText) audited calls on \(firstDate)"
            }
            return
        }

        let dayCount = activeDays.count
        let lastDate = last.date.formatted(dateStyle)
        headerDetail = "Protection activity recorded on \(dayCount) days"
        cardDetail = "\(totalText) audited calls on \(dayCount) days · \(firstDate)–\(lastDate)"
    }

    private static func date(from day: String, calendar: Calendar) -> Date? {
        let fields = day.split(separator: "-", omittingEmptySubsequences: false)
        guard fields.count == 3,
              let year = Int(fields[0]),
              let month = Int(fields[1]),
              let day = Int(fields[2]) else {
            return nil
        }
        return calendar.date(from: DateComponents(
            calendar: calendar,
            timeZone: calendar.timeZone,
            year: year,
            month: month,
            day: day
        ))
    }
}
