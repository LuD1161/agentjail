import Foundation

enum TokenChartXAxis {
    static func tickDates(from days: [String], intervalDays: Int = 7) -> [Date] {
        guard intervalDays > 0 else { return [] }
        let dates = days.compactMap(date(for:)).sorted()
        guard let first = dates.first, let last = dates.last else { return [] }

        var ticks = [first]
        var cursor = first
        while let next = calendar.date(byAdding: .day, value: intervalDays, to: cursor), next <= last {
            ticks.append(next)
            cursor = next
        }
        return ticks
    }

    static func label(for day: String, locale: Locale = .current) -> String {
        guard let date = date(for: day) else { return day }
        return label(for: date, locale: locale)
    }

    static func label(for date: Date, locale: Locale = .current) -> String {
        let formatter = DateFormatter()
        formatter.calendar = calendar
        formatter.timeZone = calendar.timeZone
        formatter.locale = locale
        formatter.setLocalizedDateFormatFromTemplate("MMM d")
        return formatter.string(from: date)
    }

    static func date(for day: String) -> Date? {
        let parts = day.split(separator: "-", omittingEmptySubsequences: false)
        guard parts.count == 3,
              let year = Int(parts[0]),
              let month = Int(parts[1]),
              let dayOfMonth = Int(parts[2])
        else { return nil }
        return calendar.date(from: DateComponents(year: year, month: month, day: dayOfMonth))
    }

    static func day(for date: Date) -> String {
        let formatter = DateFormatter()
        formatter.calendar = calendar
        formatter.timeZone = calendar.timeZone
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd"
        return formatter.string(from: date)
    }

    static func date(byAddingDays days: Int, to date: Date) -> Date? {
        calendar.date(byAdding: .day, value: days, to: date)
    }

    private static var calendar: Calendar {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0)!
        return calendar
    }
}
