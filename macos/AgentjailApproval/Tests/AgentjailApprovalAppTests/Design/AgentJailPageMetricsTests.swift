import Testing
@testable import AgentjailApprovalApp

struct AgentJailPageMetricsTests {
    @Test func sharedPageContractKeepsPrimaryScreensAligned() {
        #expect(AgentJailPageMetrics.maxContentWidth == 1180)
        #expect(AgentJailPageMetrics.horizontalPadding == 32)
        #expect(AgentJailPageMetrics.topPadding == 20)
        #expect(AgentJailPageMetrics.bottomPadding == 32)
        #expect(AgentJailPageMetrics.sectionSpacing == 24)
        #expect(AgentJailPageMetrics.cardSpacing == 16)
        #expect(AgentJailPageMetrics.cardCornerRadius == 16)
        #expect(AgentJailPageMetrics.settingsColumnMinimumWidth == 360)
        #expect(AgentJailPageMetrics.settingsPrimaryColumnCount == 2)
        #expect(
            AgentJailPageMetrics.settingsColumnMinimumWidth * 2 + AgentJailPageMetrics.cardSpacing
                <= AgentJailPageMetrics.maxContentWidth
        )
    }
}
