import Testing
@testable import AgentjailApprovalApp

struct ApprovalPanelLayoutTests {
    @Test func emptyMenuIsCompactWhileReviewMenuKeepsWorkingRoom() {
        #expect(ApprovalPanelLayout.width == 400)
        #expect(ApprovalPanelLayout.height(hasPendingReviews: false) == 304)
        #expect(ApprovalPanelLayout.height(hasPendingReviews: true) == 520)
        #expect(ApprovalPanelLayout.emptyHeight < ApprovalPanelLayout.reviewHeight)
    }
}
