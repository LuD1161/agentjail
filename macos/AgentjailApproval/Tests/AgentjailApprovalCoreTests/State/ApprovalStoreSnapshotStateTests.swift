import XCTest
@testable import AgentjailApprovalCore

@MainActor
final class ApprovalStoreSnapshotStateTests: XCTestCase {
    func testAuthoritativeAndStaleStatesKeepActionsSafe() async throws {
        let verified = try stateReview(id: "verified", context: .verified, canApprove: true)
        let unbound = try stateReview(id: "unbound", context: .unbound, canApprove: false)
        let snapshot = try stateSnapshot(reviews: [verified, unbound])
        let client = StateScriptedReviewClient(fetches: [.success(snapshot), .failure(.daemonUnavailable)])
        let store = ApprovalStore(client: client, clock: StateFixedClock(now: 1_000), sleeper: StateThrowingSleeper())

        let firstRefresh = await store.refreshNow()
        XCTAssertEqual(firstRefresh, .authoritative(AuthoritativeApprovalSnapshot(snapshot)))
        let unboundApproval = await store.approve(unbound.id)
        XCTAssertEqual(unboundApproval, .notActionable)
        XCTAssertEqual(client.approveCalls, 0)

        let disconnectedRefresh = await store.refreshNow()
        XCTAssertEqual(disconnectedRefresh, .disconnected(.unavailable))
        guard case let .disconnected(stale?, .unavailable) = store.state else {
            return XCTFail("state = \(store.state)")
        }
        XCTAssertEqual(stale.reviews.map(\.id), [verified.id, unbound.id])
        let staleApproval = await store.approve(verified.id)
        let staleDenial = await store.deny(verified.id)
        XCTAssertEqual(staleApproval, .notActionable)
        XCTAssertEqual(staleDenial, .notActionable)
        XCTAssertEqual(client.approveCalls, 0)
        XCTAssertEqual(client.denyCalls, 0)
    }

    func testInclusiveLocalExpiryDisablesBothActions() async throws {
        let expired = try stateReview(id: "expired", context: .verified, canApprove: true, expiresAt: 1_000)
        let snapshot = try stateSnapshot(reviews: [expired])
        let client = StateScriptedReviewClient(fetches: [.success(snapshot)])
        let store = ApprovalStore(client: client, clock: StateFixedClock(now: 1_000), sleeper: StateThrowingSleeper())

        _ = await store.refreshNow()
        let expiredApproval = await store.approve(expired.id)
        let expiredDenial = await store.deny(expired.id)
        XCTAssertEqual(expiredApproval, .notActionable)
        XCTAssertEqual(expiredDenial, .notActionable)
        XCTAssertEqual(client.approveCalls, 0)
        XCTAssertEqual(client.denyCalls, 0)
    }

    func testUnauthorizedAndUnsupportedAreStableStates() async throws {
        let unauthorized = ApprovalStore(client: StateScriptedReviewClient(fetches: [.failure(.unauthorized)]), clock: StateFixedClock(now: 1), sleeper: StateThrowingSleeper())
        let unauthorizedResult = await unauthorized.refreshNow()
        XCTAssertEqual(unauthorizedResult, .unauthorized)
        XCTAssertEqual(unauthorized.state, .unauthorized(nil))

        let unsupported = ApprovalStore(client: StateScriptedReviewClient(fetches: [.failure(.protocolMismatch)]), clock: StateFixedClock(now: 1), sleeper: StateThrowingSleeper())
        let unsupportedResult = await unsupported.refreshNow()
        XCTAssertEqual(unsupportedResult, .unsupportedProtocol)
        XCTAssertEqual(unsupported.state, .unsupportedProtocol(nil))

        let reviewID = try ReviewID(rawValue: "unsupported")
        let unsupportedApproval = await unsupported.approve(reviewID)
        let unsupportedDenial = await unsupported.deny(reviewID)
        XCTAssertEqual(unsupportedApproval, .notActionable)
        XCTAssertEqual(unsupportedDenial, .notActionable)
    }

    func testWireModelRejectsReviewWithoutDenyAuthority() {
        XCTAssertThrowsError(try stateReview(id: "no-deny", context: .verified, canApprove: true, canDeny: false))
    }

    func testFreshSnapshotsPreserveOrderRemoveRowsAndKeepTruncationMetadata() async throws {
        let first = try stateReview(id: "first", context: .verified, canApprove: true)
        let second = try stateReview(id: "second", context: .verified, canApprove: true)
        let initial = try stateSnapshot(reviews: [first, second], totalPending: 4)
        let current = try stateSnapshot(reviews: [second], totalPending: 1)
        let client = StateScriptedReviewClient(fetches: [.success(initial), .success(current)])
        let store = ApprovalStore(client: client, clock: StateFixedClock(now: 1), sleeper: StateThrowingSleeper())

        _ = await store.refreshNow()
        guard case let .ready(initialState) = store.state else { return XCTFail("state = \(store.state)") }
        XCTAssertEqual(initialState.reviews.map(\.id), [first.id, second.id])
        XCTAssertEqual(initialState.totalPending, 4)
        XCTAssertTrue(initialState.truncated)

        _ = await store.refreshNow()
        guard case let .ready(currentState) = store.state else { return XCTFail("state = \(store.state)") }
        XCTAssertEqual(currentState.reviews.map(\.id), [second.id])
        XCTAssertEqual(currentState.totalPending, 1)
        XCTAssertFalse(currentState.truncated)
    }

    func testAuthoritativeSnapshotDefensivelyDedupesReviewIDs() throws {
        let first = try stateReview(id: "first", context: .verified, canApprove: true)
        let second = try stateReview(id: "second", context: .verified, canApprove: true)
        let snapshot = AuthoritativeApprovalSnapshot(generatedAt: UnixMilliseconds(rawValue: 100), totalPending: 3, truncated: false, reviews: [first, second, first])

        XCTAssertEqual(snapshot.reviews.map(\.id), [first.id, second.id])
    }
}
