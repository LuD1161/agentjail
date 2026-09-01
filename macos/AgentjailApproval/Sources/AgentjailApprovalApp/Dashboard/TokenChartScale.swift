import Foundation

struct TokenChartScale: Equatable {
    private let divisor: Double
    private let suffix: String

    static func fitting(maximum: Int64) -> TokenChartScale {
        switch maximum {
        case 999_500_000...:
            TokenChartScale(divisor: 1_000_000_000, suffix: "B")
        case 999_500...:
            TokenChartScale(divisor: 1_000_000, suffix: "M")
        case 1_000...:
            TokenChartScale(divisor: 1_000, suffix: "K")
        default:
            TokenChartScale(divisor: 1, suffix: "")
        }
    }

    static func total<S: Sequence>(of values: S) -> Int64 where S.Element == Int64 {
        values.reduce(Int64(0)) { partial, value in
            let (sum, overflow) = partial.addingReportingOverflow(value)
            return overflow ? .max : sum
        }
    }

    func label(for value: Double, locale: Locale = .autoupdatingCurrent) -> String {
        guard value != 0 else { return "0" }
        let scaled = value / divisor
        let number = scaled.formatted(
            .number
                .precision(.fractionLength(0...1))
                .locale(locale)
        )
        return number + suffix
    }
}
