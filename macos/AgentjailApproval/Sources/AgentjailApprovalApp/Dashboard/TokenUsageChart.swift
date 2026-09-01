import AgentjailApprovalCore
import Charts
import SwiftUI

struct TokenUsageChart: View {
    let points: [DashboardTokenDay]
    @State private var hoveredDay: String?

    private var plottedPoints: [TokenChartPoint] {
        TokenChartSeries.daily(points: points)
    }

    private var scale: TokenChartScale {
        .fitting(maximum: points.map(\.totalTokens).max() ?? 0)
    }

    private var hoveredPoint: TokenChartPoint? {
        plottedPoints.first { $0.day == hoveredDay }
    }

    private var domainMaximum: Double {
        let maximum = Double(points.map(\.totalTokens).max() ?? 0)
        return max(maximum * 1.15, 1)
    }

    private var xAxisDates: [Date] {
        TokenChartXAxis.tickDates(from: points.map(\.day))
    }

    var body: some View {
        Chart(plottedPoints) { plottedPoint in
            AreaMark(
                x: .value("Day", plottedPoint.date),
                yStart: .value("Baseline", 0),
                yEnd: .value("Tokens", plottedPoint.totalTokens)
            )
                .foregroundStyle(.blue.opacity(0.16))
                .interpolationMethod(.monotone)
            LineMark(x: .value("Day", plottedPoint.date), y: .value("Tokens", plottedPoint.totalTokens))
                .foregroundStyle(.blue)
                .interpolationMethod(.monotone)
            if plottedPoint.day == hoveredDay {
                RuleMark(x: .value("Selected day", plottedPoint.date))
                    .foregroundStyle(.secondary)
            }
        }
        .chartYScale(domain: 0...domainMaximum)
        .chartXAxis {
            AxisMarks(preset: .aligned, position: .bottom, values: xAxisDates) { value in
                AxisTick()
                AxisValueLabel(collisionResolution: .disabled) {
                    if let date = value.as(Date.self) {
                        Text(TokenChartXAxis.label(for: date))
                    }
                }
            }
        }
        .chartYAxis {
            AxisMarks(position: .trailing) { value in
                AxisGridLine()
                AxisValueLabel {
                    if let tokens = value.as(Double.self) {
                        Text(scale.label(for: tokens))
                    }
                }
            }
        }
        .chartOverlay { proxy in
            GeometryReader { geometry in
                ZStack {
                    Rectangle()
                        .fill(.clear)
                        .contentShape(Rectangle())
                        .onContinuousHover { phase in
                            updateHover(phase, proxy: proxy, geometry: geometry)
                        }
                    if let hoveredPoint {
                        TokenUsageHoverLabel(day: hoveredPoint.day, totalTokens: hoveredPoint.totalTokens)
                            .fixedSize()
                            .frame(
                                maxWidth: .infinity,
                                maxHeight: .infinity,
                                alignment: tooltipAlignment(for: hoveredPoint)
                            )
                            .padding(4)
                            .allowsHitTesting(false)
                    }
                }
            }
        }
        .frame(height: 130)
        .accessibilityLabel("Token usage over time")
        .accessibilityValue(hoveredPoint.map { TokenChartScale.fitting(maximum: $0.totalTokens).label(for: Double($0.totalTokens)) + " tokens on " + $0.day } ?? "Hover over the chart to inspect daily usage")
    }

    private func updateHover(_ phase: HoverPhase, proxy: ChartProxy, geometry: GeometryProxy) {
        switch phase {
        case let .active(location):
            let plotFrame = geometry[proxy.plotAreaFrame]
            guard plotFrame.contains(location) else {
                hoveredDay = nil
                return
            }
            guard let date = proxy.value(atX: location.x - plotFrame.origin.x, as: Date.self) else {
                hoveredDay = nil
                return
            }
            hoveredDay = plottedPoints.min {
                abs($0.date.timeIntervalSince(date)) < abs($1.date.timeIntervalSince(date))
            }?.day
        case .ended:
            hoveredDay = nil
        }
    }

    private func tooltipAlignment(for point: TokenChartPoint) -> Alignment {
        let index = plottedPoints.firstIndex(where: { $0.id == point.id }) ?? 0
        switch TokenChartTooltipPlacement.resolve(index: index, count: plottedPoints.count) {
        case .leading: return .topLeading
        case .center: return .top
        case .trailing: return .topTrailing
        }
    }
}
