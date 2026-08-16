import XCTest
@testable import AgentjailApprovalCore

@MainActor
final class ApprovalStoreActionTests: XCTestCase {
    func testSameReviewIsSingleFlightAndMutationRefreshesSnapshot() async throws {
        let review = try stateReview(id: "single-flight", context: .verified, canApprove: true)
        let initial = try stateSnapshot(reviews: [review])
        let afterApproval = try stateSnapshot(reviews: [])
        let client = StateBlockingApprovalClient(fetches: [initial, afterApproval])
        let store = ApprovalStore(client: client, clock: StateFixedClock(now: 1), sleeper: StateThrowingSleeper())
        _ = await store.refreshNow()

        let first = Task { await store.approve(review.id) }
        await stateWaitFor { client.approveCalls == 1 }
        XCTAssertEqual(store.actionState(for: review.id), .approving)
        let secondApproval = await store.approve(review.id)
        XCTAssertEqual(secondApproval, .notActionable)
        XCTAssertEqual(client.approveCalls, 1)

        client.finishApproval()
        let firstResult = await first.value
        XCTAssertEqual(firstResult, .completed)
        guard case let .ready(snapshot) = store.state else { return XCTFail("state = \(store.state)") }
        XCTAssertTrue(snapshot.reviews.isEmpty)
    }

    func testSameReviewStaysInFlightUntilItsFreshSnapshotCompletes() async throws {
        let review = try stateReview(id: "refresh-window", context: .verified, canApprove: true)
        let initial = try stateSnapshot(reviews: [review])
        let refreshed = try stateSnapshot(reviews: [])
        let client = StateMutationThenRefreshClient(initial: initial, refreshed: refreshed)
        let store = ApprovalStore(client: client, clock: StateFixedClock(now: 1), sleeper: StateThrowingSleeper())
        _ = await store.refreshNow()

        let first = Task { await store.approve(review.id) }
        await stateWaitFor { client.approveCalls == 1 }
        client.finishApproval()
        await stateWaitFor { client.refreshStarted }

        XCTAssertEqual(store.actionState(for: review.id), .approving)
        let second = await store.approve(review.id)
        XCTAssertEqual(second, .notActionable)
        XCTAssertEqual(client.approveCalls, 1)

        client.finishRefresh()
        let firstResult = await first.value
        XCTAssertEqual(firstResult, .completed)
    }

    func testConcurrentRefreshCannotReplaceNewerAuthorityAfterAnAction() async throws {
        let pending = try stateReview(id: "action-race", context: .verified, canApprove: true)
        let initial = try stateSnapshot(reviews: [pending])
        let actionRefresh = try stateSnapshot(reviews: [])
        let manualRefresh = try stateSnapshot(reviews: [stateReview(id: "newer", context: .verified, canApprove: true)])
        let client = StateMutationThenRefreshClient(initial: initial, refreshed: actionRefresh, concurrent: manualRefresh)
        let store = ApprovalStore(client: client, clock: StateFixedClock(now: 1), sleeper: StateThrowingSleeper())
        _ = await store.refreshNow()

        let action = Task { await store.approve(pending.id) }
        await stateWaitFor { client.approveCalls == 1 }
        client.finishApproval()
        await stateWaitFor { client.refreshStarted }

        let manualResult = await store.refreshNow()
        XCTAssertEqual(manualResult, .authoritative(AuthoritativeApprovalSnapshot(manualRefresh)))
        client.finishRefresh()
        let actionResult = await action.value
        XCTAssertEqual(actionResult, .completed)
        guard case let .ready(snapshot) = store.state else { return XCTFail("state = \(store.state)") }
        XCTAssertEqual(snapshot.reviews.map(\.id.rawValue), ["newer"])
        XCTAssertEqual(client.approveCalls, 1)
    }

    func testDifferentReviewIDsCanProgressIndependently() async throws {
        let first = try stateReview(id: "first", context: .verified, canApprove: true)
        let second = try stateReview(id: "second", context: .verified, canApprove: true)
        let snapshot = try stateSnapshot(reviews: [first, second])
        let client = StateConcurrentApprovalClient(snapshot: snapshot)
        let store = ApprovalStore(client: client, clock: StateFixedClock(now: 1), sleeper: StateThrowingSleeper())
        _ = await store.refreshNow()

        let firstTask = Task { await store.approve(first.id) }
        let secondTask = Task { await store.approve(second.id) }
        await stateWaitFor { client.approvalCount == 2 }
        XCTAssertEqual(store.actionState(for: first.id), .approving)
        XCTAssertEqual(store.actionState(for: second.id), .approving)

        client.finishApproval(for: first.id)
        client.finishApproval(for: second.id)
        let firstResult = await firstTask.value
        let secondResult = await secondTask.value
        XCTAssertEqual(firstResult, .completed)
        XCTAssertEqual(secondResult, .completed)
    }

    func testDenySuccessAndFailuresAreSingleShot() async throws {
        let review = try stateReview(id: "deny", context: .verified, canApprove: true)
        let snapshot = try stateSnapshot(reviews: [review])
        let empty = try stateSnapshot(reviews: [])
        let successClient = StateScriptedReviewClient(fetches: [.success(snapshot), .success(empty)])
        let successStore = ApprovalStore(client: successClient, clock: StateFixedClock(now: 1), sleeper: StateThrowingSleeper())
        _ = await successStore.refreshNow()
        let success = await successStore.deny(review.id)
        XCTAssertEqual(success, .completed)
        XCTAssertEqual(successClient.denyCalls, 1)

        let refusalClient = StateScriptedReviewClient(fetches: [.success(snapshot), .success(snapshot)], deny: [.failure(.serverRefused("refused"))])
        let refusalStore = ApprovalStore(client: refusalClient, clock: StateFixedClock(now: 1), sleeper: StateThrowingSleeper())
        _ = await refusalStore.refreshNow()
        let refusal = await refusalStore.deny(review.id)
        XCTAssertEqual(refusal, .failed(.refused))
        XCTAssertEqual(refusalClient.denyCalls, 1)
        XCTAssertEqual(refusalStore.actionState(for: review.id), .failed(.refused))

        let timeoutClient = StateScriptedReviewClient(fetches: [.success(snapshot), .success(snapshot)], deny: [.failure(.timeout)])
        let timeoutStore = ApprovalStore(client: timeoutClient, clock: StateFixedClock(now: 1), sleeper: StateThrowingSleeper())
        _ = await timeoutStore.refreshNow()
        let timeout = await timeoutStore.deny(review.id)
        XCTAssertEqual(timeout, .failed(.timeout))
        XCTAssertEqual(timeoutClient.denyCalls, 1)
    }

    func testCancelledMutationHasNoRetryAndKeepsRowFailureVisible() async throws {
        let review = try stateReview(id: "cancel", context: .verified, canApprove: true)
        let snapshot = try stateSnapshot(reviews: [review])
        let client = StateCancellationAwareApprovalClient(snapshot: snapshot)
        let store = ApprovalStore(client: client, clock: StateFixedClock(now: 1), sleeper: StateThrowingSleeper())
        _ = await store.refreshNow()

        let mutation = Task { await store.approve(review.id) }
        await stateWaitFor { client.approveStarted }
        mutation.cancel()
        let result = await mutation.value
        XCTAssertEqual(result, .cancelled)
        XCTAssertEqual(client.approveCalls, 1)
        XCTAssertEqual(store.actionState(for: review.id), .failed(.unavailable))
    }

    func testAmbiguousMutationFailureDoesNotRetryAndLeavesFailureState() async throws {
        let review = try stateReview(id: "lost-reply", context: .verified, canApprove: true)
        let snapshot = try stateSnapshot(reviews: [review])
        let client = StateScriptedReviewClient(fetches: [.success(snapshot), .success(snapshot), .success(snapshot)], approve: [.failure(.timeout), .success])
        let store = ApprovalStore(client: client, clock: StateFixedClock(now: 1), sleeper: StateThrowingSleeper())
        _ = await store.refreshNow()

        let approvalResult = await store.approve(review.id)
        XCTAssertEqual(approvalResult, .failed(.timeout))
        XCTAssertEqual(client.approveCalls, 1)
        XCTAssertEqual(store.actionState(for: review.id), .failed(.timeout))

        let retryResult = await store.approve(review.id)
        XCTAssertEqual(retryResult, .completed)
        XCTAssertEqual(client.approveCalls, 2)
        XCTAssertEqual(store.actionState(for: review.id), .idle)
    }

    func testRefreshSupersededByNewerResultCannotRestoreOldAuthority() async throws {
        let old = try stateSnapshot(reviews: [stateReview(id: "old", context: .verified, canApprove: true)])
        let current = try stateSnapshot(reviews: [stateReview(id: "current", context: .verified, canApprove: true)])
        let client = StateOrderedReviewClient(first: old, second: current)
        let store = ApprovalStore(client: client, clock: StateFixedClock(now: 1), sleeper: StateThrowingSleeper())

        let first = Task { await store.refreshNow() }
        await stateWaitFor { client.firstStarted }
        let currentRefresh = await store.refreshNow()
        XCTAssertEqual(currentRefresh, .authoritative(AuthoritativeApprovalSnapshot(current)))
        client.finishFirst()
        let firstRefresh = await first.value
        XCTAssertEqual(firstRefresh, .superseded)
        guard case let .ready(snapshot) = store.state else { return XCTFail("state = \(store.state)") }
        XCTAssertEqual(snapshot.reviews.map(\.id.rawValue), ["current"])
    }
}
