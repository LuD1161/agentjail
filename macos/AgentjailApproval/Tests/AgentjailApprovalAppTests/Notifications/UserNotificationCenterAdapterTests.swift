import XCTest
import UserNotifications
@testable import AgentjailApprovalApp
@testable import AgentjailApprovalCore

@MainActor
final class UserNotificationCenterAdapterTests: XCTestCase {
    func testCategoryHasOnlyReviewAndAuthenticatedDestructiveDeny() {
        let category = UserNotificationCenterAdapter.approvalCategory
        XCTAssertEqual(category.identifier, ApprovalNotificationConfiguration.categoryIdentifier)
        XCTAssertEqual(category.actions.map(\.identifier), [
            ApprovalNotificationConfiguration.reviewActionIdentifier,
            ApprovalNotificationConfiguration.denyActionIdentifier,
        ])
        XCTAssertEqual(category.actions[0].options, [.foreground])
        XCTAssertEqual(category.actions[1].options, [.destructive, .authenticationRequired])
    }

    func testForegroundPresentationCompletesExactlyOnceWithBannerListAndSound() {
        var completionCount = 0
        var receivedOptions: UNNotificationPresentationOptions?

        ApprovalNotificationDelegate.presentForeground { options in
            completionCount += 1
            receivedOptions = options
        }

        XCTAssertEqual(completionCount, 1)
        XCTAssertEqual(receivedOptions, [.banner, .list, .sound])
    }

    func testResponseParsesOnlyTheSingleReviewIDPayload() throws {
        let reviewID = try ReviewID(rawValue: "review-response")
        let review = ApprovalNotificationDelegate.response(
            actionIdentifier: ApprovalNotificationConfiguration.reviewActionIdentifier,
            userInfo: [ApprovalNotificationConfiguration.reviewIDUserInfoKey: reviewID.rawValue]
        )
        XCTAssertEqual(review, ApprovalNotificationResponse(action: .review, reviewID: reviewID))

        let deny = ApprovalNotificationDelegate.response(
            actionIdentifier: ApprovalNotificationConfiguration.denyActionIdentifier,
            userInfo: [ApprovalNotificationConfiguration.reviewIDUserInfoKey: reviewID.rawValue]
        )
        XCTAssertEqual(deny, ApprovalNotificationResponse(action: .deny, reviewID: reviewID))

        let malformed = ApprovalNotificationDelegate.response(
            actionIdentifier: ApprovalNotificationConfiguration.denyActionIdentifier,
            userInfo: [ApprovalNotificationConfiguration.reviewIDUserInfoKey: reviewID.rawValue, "extra": "forbidden"]
        )
        XCTAssertEqual(malformed, ApprovalNotificationResponse(action: .other, reviewID: nil))

        let unknown = ApprovalNotificationDelegate.response(
            actionIdentifier: "unknown",
            userInfo: [ApprovalNotificationConfiguration.reviewIDUserInfoKey: reviewID.rawValue]
        )
        XCTAssertEqual(unknown, ApprovalNotificationResponse(action: .other, reviewID: reviewID))
    }

    func testResponseCompletionRunsExactlyOnceOnSuccess() async throws {
        let reviewID = try ReviewID(rawValue: "review-success")
        let recorder = ResponseRecorder()
        let delegate = ApprovalNotificationDelegate { response in
            recorder.responses.append(response)
        }
        let completion = expectation(description: "completion")
        completion.expectedFulfillmentCount = 1
        delegate.receiveResponse(
            actionIdentifier: ApprovalNotificationConfiguration.reviewActionIdentifier,
            userInfo: [ApprovalNotificationConfiguration.reviewIDUserInfoKey: reviewID.rawValue],
            completionHandler: { completion.fulfill() }
        )

        await fulfillment(of: [completion], timeout: 1)
        XCTAssertEqual(recorder.responses, [ApprovalNotificationResponse(action: .review, reviewID: reviewID)])
    }

    func testResponseCompletionRunsExactlyOnceOnHandlerFailure() async throws {
        let reviewID = try ReviewID(rawValue: "review-failure")
        let delegate = ApprovalNotificationDelegate { _ in throw HandlerError.failed }
        let completion = expectation(description: "completion")
        completion.expectedFulfillmentCount = 1
        delegate.receiveResponse(
            actionIdentifier: ApprovalNotificationConfiguration.denyActionIdentifier,
            userInfo: [ApprovalNotificationConfiguration.reviewIDUserInfoKey: reviewID.rawValue],
            completionHandler: { completion.fulfill() }
        )

        await fulfillment(of: [completion], timeout: 1)
    }
}

@MainActor
private final class ResponseRecorder {
    var responses: [ApprovalNotificationResponse] = []
}

private enum HandlerError: Error {
    case failed
}
