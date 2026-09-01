enum TokenChartTooltipPlacement: Equatable {
    case leading
    case center
    case trailing

    static func resolve(index: Int, count: Int) -> Self {
        guard count > 1 else { return .center }
        let progress = Double(index) / Double(count - 1)
        if progress < 0.25 { return .leading }
        if progress > 0.75 { return .trailing }
        return .center
    }
}
