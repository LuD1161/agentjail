import XCTest
@testable import AgentjailApprovalCore

final class ApprovalPresentationTests: XCTestCase {
    private let now = UnixMilliseconds(rawValue: 2_000)

    func testPanelStateMatrixHasTruthfulStatusRetryAndStaleActions() {
        let review = makeReview()
        let authoritative = snapshot([review])
        let stale = StaleApprovalSnapshot(authoritative)
        let cases: [(ApprovalStoreState, ApprovalPanelStatusKind, Bool, Bool)] = [
            (.starting, .starting, false, false),
            (.connecting, .connecting, false, false),
            (.ready(snapshot([])), .ready, false, false),
            (.ready(authoritative), .ready, false, false),
            (.disconnected(stale, .unavailable), .disconnected, true, true),
            (.unauthorized(stale), .unauthorized, true, true),
            (.unsupportedProtocol(stale), .unsupportedProtocol, true, true),
        ]

        for (state, expectedKind, expectedRetry, expectedStale) in cases {
            let presentation = PanelPresentation(
                state: state,
                actionStates: [:],
                now: now
            )

            XCTAssertEqual(presentation.status.kind, expectedKind)
            XCTAssertEqual(presentation.status.canRetry, expectedRetry)
            XCTAssertFalse(presentation.status.title.isEmpty)
            XCTAssertTrue(presentation.status.accessibilityText.contains(presentation.status.title))
            XCTAssertTrue(presentation.cards.allSatisfy { $0.isStale == expectedStale })
            if expectedStale {
                XCTAssertTrue(presentation.cards.allSatisfy { !$0.canApprove && !$0.canDeny })
            }
        }
    }

    func testVerifiedReviewUsesExactFutureSessionCopyAndIDOnlyPresentation() {
        let review = makeReview(
            host: "api.example.com",
            projectPath: "/Users/agent/My Project",
            reason: "Dependency download"
        )
        let card = card(for: review)

        XCTAssertEqual(
            card.context,
            .verified(
                host: "api.example.com",
                projectName: "My Project",
                projectPath: "/Users/agent/My Project"
            )
        )
        XCTAssertEqual(
            card.effect,
            "Adds this host to the project policy for future sessions. The current session is unchanged."
        )
        XCTAssertEqual(ReviewCardPresentation.approvalButtonTitle, "Approve for future sessions")
        XCTAssertEqual(ReviewCardPresentation.denyButtonTitle, "Deny")
        XCTAssertEqual(card.id, review.id)
        XCTAssertTrue(card.showsApproveAction)
        XCTAssertTrue(card.canApprove)
        XCTAssertTrue(card.canDeny)
    }

    func testUnavailableContextsOmitPartialAuthorityAndRemainDenyOnly() {
        let cases: [(Review, ApprovalContextUnavailableReason)] = [
            (
                makeReview(
                    host: "api.example.com",
                    projectPath: nil,
                    contextState: .unbound,
                    canApprove: false
                ),
                .unbound
            ),
            (
                makeReview(
                    host: nil,
                    projectPath: nil,
                    contextState: .unrepresentable,
                    canApprove: false
                ),
                .unrepresentable
            ),
        ]

        for (review, expectedReason) in cases {
            let result = card(for: review)
            XCTAssertEqual(result.context, .unavailable(expectedReason))
            XCTAssertNil(result.effect)
            XCTAssertFalse(result.showsApproveAction)
            XCTAssertFalse(result.canApprove)
            XCTAssertTrue(result.canDeny)
        }
    }

    func testUnsafeAuthorityDisplayDowngradesVerifiedReviewWithoutShowingPartialFields() {
        let review = makeReview(projectPath: "/tmp/safe\u{202E}spoof")
        let result = card(for: review)

        XCTAssertEqual(result.context, .unavailable(.unsafeAuthorityDisplay))
        XCTAssertNil(result.effect)
        XCTAssertFalse(result.showsApproveAction)
        XCTAssertFalse(result.canApprove)
        XCTAssertTrue(result.canDeny)
    }

    func testReasonProjectionUsesSanitizerAndReportsBothKindsOfBounding() {
        let review = makeReview(reason: "alpha\tbeta", reasonTruncated: true)
        let result = card(for: review)

        XCTAssertEqual(result.reason, "alpha beta")
        XCTAssertTrue(result.reasonWasSanitized)
        XCTAssertTrue(result.reasonWasTruncated)

        let longReason = String(repeating: "a", count: 200)
        let locallyBounded = card(for: makeReview(id: "long-reason", reason: longReason))
        XCTAssertEqual(locallyBounded.reason.count, 160)
        XCTAssertTrue(locallyBounded.reason.hasSuffix("…"))
        XCTAssertTrue(locallyBounded.reasonWasTruncated)
    }

    func testStaleExpiredAndInflightRowsDisableBothActions() {
        let review = makeReview(expiresAt: 2_000)
        let authoritative = snapshot([review])

        let expired = PanelPresentation(
            state: .ready(authoritative),
            actionStates: [:],
            now: now
        ).cards[0]
        XCTAssertTrue(expired.isExpired)
        XCTAssertFalse(expired.canApprove)
        XCTAssertFalse(expired.canDeny)

        let futureReview = makeReview(expiresAt: 3_000)
        let futureSnapshot = snapshot([futureReview])
        let stale = PanelPresentation(
            state: .disconnected(StaleApprovalSnapshot(futureSnapshot), .timeout),
            actionStates: [:],
            now: now
        ).cards[0]
        XCTAssertTrue(stale.isStale)
        XCTAssertFalse(stale.canApprove)
        XCTAssertFalse(stale.canDeny)

        for action in [ReviewActionState.approving, .denying] {
            let inFlight = PanelPresentation(
                state: .ready(futureSnapshot),
                actionStates: [futureReview.id: action],
                now: now
            ).cards[0]
            XCTAssertTrue(inFlight.action.isInFlight)
            XCTAssertFalse(inFlight.canApprove)
            XCTAssertFalse(inFlight.canDeny)
        }
    }

    func testFailureStaysVisibleAndDoesNotOptimisticallyRemoveRow() {
        let review = makeReview()
        let panel = PanelPresentation(
            state: .ready(snapshot([review])),
            actionStates: [review.id: .failed(.refused)],
            now: now
        )

        XCTAssertEqual(panel.cards.map(\.id), [review.id])
        guard case let .failed(failure) = panel.cards[0].action else {
            return XCTFail("expected attached action failure")
        }
        XCTAssertEqual(failure.title, "Action failed")
        XCTAssertTrue(failure.detail.contains("refused"))
        XCTAssertTrue(panel.cards[0].canApprove)
        XCTAssertTrue(panel.cards[0].canDeny)
    }

    func testEveryFailureMapsToBoundedNonSensitiveFeedback() {
        let failures: [ApprovalActionFailure] = [
            .refused,
            .unavailable,
            .timeout,
            .unauthorized,
            .unsupportedProtocol,
            .malformedReply,
            .oversizedReply,
            .tokenUnavailable,
            .invalidSocketPath,
        ]

        for (index, failure) in failures.enumerated() {
            let review = makeReview(id: "failure-\(index)")
            let panel = PanelPresentation(
                state: .ready(snapshot([review])),
                actionStates: [review.id: .failed(failure)],
                now: now
            )
            guard case let .failed(message) = panel.cards[0].action else {
                return XCTFail("expected failure presentation")
            }
            XCTAssertFalse(message.detail.isEmpty)
            XCTAssertLessThan(message.detail.count, 160)
            XCTAssertFalse(message.detail.contains(review.id.rawValue))
        }
    }

    func testFocusGenerationTargetsOnlyFreshAuthoritativeRows() {
        let review = makeReview()
        let requestOne = ReviewFocusRequest(reviewID: review.id, generation: 1)
        let requestTwo = ReviewFocusRequest(reviewID: review.id, generation: 2)
        let authoritative = snapshot([review])

        let first = PanelPresentation(
            state: .ready(authoritative),
            actionStates: [:],
            now: now,
            focusRequest: requestOne
        )
        let repeated = PanelPresentation(
            state: .ready(authoritative),
            actionStates: [:],
            now: now,
            focusRequest: requestTwo
        )
        XCTAssertEqual(first.focus, .target(requestOne))
        XCTAssertEqual(repeated.focus, .target(requestTwo))
        XCTAssertNotEqual(first.focus.generation, repeated.focus.generation)

        let missingID = try! ReviewID(rawValue: "missing")
        let missingRequest = ReviewFocusRequest(reviewID: missingID, generation: 3)
        let missing = PanelPresentation(
            state: .ready(authoritative),
            actionStates: [:],
            now: now,
            focusRequest: missingRequest
        )
        XCTAssertEqual(missing.focus, .unavailable(missingRequest, .noLongerPending))

        let stale = PanelPresentation(
            state: .disconnected(StaleApprovalSnapshot(authoritative), .unavailable),
            actionStates: [:],
            now: now,
            focusRequest: requestOne
        )
        XCTAssertEqual(stale.focus, .unavailable(requestOne, .snapshotNotAuthoritative))
    }

    func testFocusRejectsInclusiveExpiryBoundary() {
        let review = makeReview(expiresAt: now.rawValue)
        let request = ReviewFocusRequest(reviewID: review.id, generation: 9)
        let panel = PanelPresentation(
            state: .ready(snapshot([review])),
            actionStates: [:],
            now: now,
            focusRequest: request
        )

        XCTAssertEqual(panel.focus, .unavailable(request, .expired))
        XCTAssertFalse(panel.cards[0].canApprove)
        XCTAssertFalse(panel.cards[0].canDeny)
    }

    func testFocusUnavailableToTargetTransitionIsObservableWithoutNewGeneration() {
        let review = makeReview()
        let request = ReviewFocusRequest(reviewID: review.id, generation: 11)
        let unavailable = PanelPresentation(
            state: .connecting,
            actionStates: [:],
            now: now,
            focusRequest: request
        )
        let target = PanelPresentation(
            state: .ready(snapshot([review])),
            actionStates: [:],
            now: now,
            focusRequest: request
        )

        XCTAssertEqual(unavailable.focus.generation, target.focus.generation)
        XCTAssertEqual(unavailable.focus, .unavailable(request, .snapshotNotAuthoritative))
        XCTAssertEqual(target.focus, .target(request))
        XCTAssertNotEqual(unavailable.focus, target.focus)
    }

    func testFocusConsumptionPolicyWaitsForAuthorityAndConsumesTerminalResults() {
        let request = ReviewFocusRequest(
            reviewID: try! ReviewID(rawValue: "focus-policy"),
            generation: 12
        )

        XCTAssertNil(ReviewFocusPresentation.none.consumableRequest)
        XCTAssertNil(
            ReviewFocusPresentation
                .unavailable(request, .snapshotNotAuthoritative)
                .consumableRequest
        )
        XCTAssertEqual(ReviewFocusPresentation.target(request).consumableRequest, request)
        XCTAssertEqual(
            ReviewFocusPresentation.unavailable(request, .noLongerPending).consumableRequest,
            request
        )
        XCTAssertEqual(
            ReviewFocusPresentation.unavailable(request, .expired).consumableRequest,
            request
        )
    }

    func testCardsPreserveCanonicalServerOrderForTimestampTies() {
        let old = makeReview(id: "old", createdAt: 10)
        let tiedA = makeReview(id: "tie-a", createdAt: 20)
        let tiedB = makeReview(id: "tie-b", createdAt: 20)
        let panel = PanelPresentation(
            state: .ready(snapshot([tiedA, tiedB, old])),
            actionStates: [:],
            now: UnixMilliseconds(rawValue: 0)
        )

        XCTAssertEqual(panel.cards.map { $0.id.rawValue }, ["tie-a", "tie-b", "old"])
    }

    func testTruncationCopyReportsNewestVisibleAndTotalCounts() {
        let reviews = [
            makeReview(id: "one"),
            makeReview(id: "two"),
            makeReview(id: "three"),
        ]
        let panel = PanelPresentation(
            state: .ready(snapshot(reviews, totalPending: 7, truncated: true)),
            actionStates: [:],
            now: now
        )

        XCTAssertEqual(panel.pendingCountText, "7 pending")
        XCTAssertEqual(panel.truncationText, "Showing the 3 newest of 7 pending requests.")
    }

    func testMenuLabelStatesExposeExactPendingAndCachedCounts() {
        let review = makeReview()
        let ready = snapshot([review], totalPending: 2, truncated: true)
        let stale = StaleApprovalSnapshot(ready)
        let cases: [(ApprovalStoreState, ApprovalMenuLabelState, String?, String)] = [
            (.starting, .starting, nil, "Starting"),
            (.connecting, .connecting, nil, "Connecting"),
            (.ready(snapshot([])), .ready, nil, "No pending approvals"),
            (.ready(ready), .ready, "2", "2 pending approvals"),
            (.disconnected(stale, .unavailable), .disconnected, "2", "Disconnected; cached. 2 pending approvals; actions disabled"),
            (.unauthorized(stale), .unauthorized, "2", "Authorization required; cached. 2 pending approvals; actions disabled"),
            (.unsupportedProtocol(stale), .unsupportedProtocol, "2", "Unsupported protocol; cached. 2 pending approvals; actions disabled"),
        ]

        for (state, expectedState, badge, accessibilityValue) in cases {
            let presentation = ApprovalMenuLabelPresentation(state: state)
            XCTAssertEqual(presentation.state, expectedState)
            XCTAssertEqual(presentation.badgeText, badge)
            XCTAssertEqual(presentation.accessibilityValue, accessibilityValue)
            XCTAssertEqual(presentation.accessibilityLabel, "AgentJail approvals")
        }
    }

    private func card(for review: Review) -> ReviewCardPresentation {
        PanelPresentation(
            state: .ready(snapshot([review])),
            actionStates: [:],
            now: now
        ).cards[0]
    }

    private func snapshot(
        _ reviews: [Review],
        totalPending: Int? = nil,
        truncated: Bool? = nil
    ) -> AuthoritativeApprovalSnapshot {
        let total = totalPending ?? reviews.count
        return AuthoritativeApprovalSnapshot(
            generatedAt: UnixMilliseconds(rawValue: 1_000),
            totalPending: total,
            truncated: truncated ?? (total > reviews.count),
            reviews: reviews
        )
    }

    private func makeReview(
        id: String = "review-1",
        host: String? = "api.example.com",
        projectPath: String? = "/Users/agent/project",
        reason: String = "Needs package access",
        reasonTruncated: Bool = false,
        contextState: ReviewContextState = .verified,
        createdAt: Int64 = 1_000,
        expiresAt: Int64 = 3_000,
        canApprove: Bool = true
    ) -> Review {
        try! Review(
            id: ReviewID(rawValue: id),
            kind: .projectHost,
            host: host,
            projectPath: projectPath,
            reason: reason,
            reasonTruncated: reasonTruncated,
            contextState: contextState,
            createdAt: UnixMilliseconds(rawValue: createdAt),
            expiresAt: UnixMilliseconds(rawValue: expiresAt),
            approvalScope: .futureProjectSessions,
            canApprove: canApprove,
            canDeny: true
        )
    }
}
