import XCTest
@testable import AgentjailApprovalCore

@MainActor
final class ApprovalStorePollingTests: XCTestCase {
    func testStableFailuresStopPollingWithoutSleeping() async {
        let client = StateScriptedReviewClient(fetches: [.failure(.unauthorized)])
        let sleeper = StateRecordingSleeper(stopAfter: 1)
        let store = ApprovalStore(client: client, clock: StateFixedClock(now: 1), sleeper: sleeper)

        store.start()
        await stateWaitFor { client.fetchCalls == 1 }
        for _ in 0..<10 { await Task.yield() }

        XCTAssertEqual(client.fetchCalls, 1)
        XCTAssertTrue(sleeper.durations.isEmpty)
        XCTAssertEqual(store.state, .unauthorized(nil))
    }

    func testActivationResumesTwoSecondPollingAfterAuthorizationRecovers() async throws {
        let snapshot = try stateSnapshot(reviews: [])
        let client = StateScriptedReviewClient(fetches: [.failure(.unauthorized), .success(snapshot)])
        let sleeper = StateRecordingSleeper(stopAfter: 1)
        let store = ApprovalStore(client: client, clock: StateFixedClock(now: 1), sleeper: sleeper)

        store.start()
        await stateWaitFor { client.fetchCalls == 1 }
        store.applicationDidBecomeActive()
        await stateWaitFor { sleeper.durations == [2] }

        XCTAssertEqual(client.fetchCalls, 2)
        XCTAssertEqual(store.state, .ready(AuthoritativeApprovalSnapshot(snapshot)))
    }

    func testManualRetryResumesTwoSecondPollingAfterAuthorizationRecovers() async throws {
        let snapshot = try stateSnapshot(reviews: [])
        let client = StateScriptedReviewClient(fetches: [.failure(.unauthorized), .success(snapshot)])
        let sleeper = StateRecordingSleeper(stopAfter: 1)
        let store = ApprovalStore(client: client, clock: StateFixedClock(now: 1), sleeper: sleeper)

        store.start()
        await stateWaitFor { client.fetchCalls == 1 }
        let retry = await store.refreshNow()
        XCTAssertEqual(retry, .authoritative(AuthoritativeApprovalSnapshot(snapshot)))
        await stateWaitFor { sleeper.durations == [2] }

        XCTAssertEqual(client.fetchCalls, 2)
        XCTAssertEqual(store.state, .ready(AuthoritativeApprovalSnapshot(snapshot)))
    }

    func testManualRetrySchedulesReconnectAfterStableAuthorizationFailure() async {
        let client = StateScriptedReviewClient(fetches: [.failure(.unauthorized), .failure(.daemonUnavailable)])
        let sleeper = StateRecordingSleeper(stopAfter: 1)
        let store = ApprovalStore(client: client, clock: StateFixedClock(now: 1), sleeper: sleeper)

        store.start()
        await stateWaitFor { client.fetchCalls == 1 }
        let retry = await store.refreshNow()
        XCTAssertEqual(retry, .disconnected(.unavailable))
        await stateWaitFor { sleeper.durations == [2] }

        XCTAssertEqual(store.state, .disconnected(nil, .unavailable))
    }

    func testPollingUsesBackoffCapAndStartDoesNotCreateSecondLoop() async {
        let client = StateScriptedReviewClient(fetches: Array(repeating: .failure(.daemonUnavailable), count: 5))
        let sleeper = StateRecordingSleeper(stopAfter: 5)
        let store = ApprovalStore(client: client, clock: StateFixedClock(now: 1), sleeper: sleeper)

        store.start()
        store.start()
        await stateWaitFor { sleeper.durations.count == 5 }

        XCTAssertEqual(sleeper.durations, [2, 4, 8, 16, 30])
        XCTAssertEqual(client.fetchCalls, 5)
        store.stop()
    }

    func testSuccessResetsBackoffAndEmptySnapshotIsReady() async throws {
        let empty = try stateSnapshot(reviews: [])
        let client = StateScriptedReviewClient(fetches: [.failure(.timeout), .success(empty), .success(empty)])
        let sleeper = StateRecordingSleeper(stopAfter: 3)
        let store = ApprovalStore(client: client, clock: StateFixedClock(now: 1), sleeper: sleeper)

        store.start()
        await stateWaitFor { sleeper.durations.count == 3 }

        XCTAssertEqual(sleeper.durations, [2, 2, 2])
        guard case let .ready(snapshot) = store.state else { return XCTFail("state = \(store.state)") }
        XCTAssertEqual(snapshot.totalPending, 0)
        XCTAssertTrue(snapshot.reviews.isEmpty)
        store.stop()
    }

    func testStopCancelsTheOnlyPollLoopWithoutAnotherFetch() async {
        let client = StateScriptedReviewClient(fetches: [.failure(.daemonUnavailable)])
        let sleeper = StateCancellationObservingSleeper()
        let store = ApprovalStore(client: client, clock: StateFixedClock(now: 1), sleeper: sleeper)

        store.start()
        await stateWaitFor { sleeper.hasStarted }
        store.stop()
        await stateWaitFor { sleeper.observedCancellation }
        let fetchesAtStop = client.fetchCalls
        for _ in 0..<10 { await Task.yield() }

        XCTAssertEqual(fetchesAtStop, 1)
        XCTAssertEqual(client.fetchCalls, 1)
    }

    func testStoppedPollReleasesTheStore() async {
        let sleeper = StateCancellationObservingSleeper()
        weak var releasedStore: ApprovalStore?
        var store: ApprovalStore? = ApprovalStore(client: StateScriptedReviewClient(fetches: [.failure(.daemonUnavailable)]), clock: StateFixedClock(now: 1), sleeper: sleeper)
        releasedStore = store

        store?.start()
        await stateWaitFor { sleeper.hasStarted }
        store?.stop()
        await stateWaitFor { sleeper.observedCancellation }
        store = nil
        for _ in 0..<10 { await Task.yield() }

        XCTAssertNil(releasedStore)
    }

    func testStopInvalidatesBlockedSuccessAndErrorBeforeTheyCanChangeState() async throws {
        let snapshot = try stateSnapshot(reviews: [])
        let successClient = StateDeferredFetchClient()
        let successStore = ApprovalStore(client: successClient, clock: StateFixedClock(now: 1), sleeper: StateThrowingSleeper())
        successStore.start()
        await stateWaitFor { successClient.isWaiting }
        successStore.stop()
        successClient.finish(.success(snapshot))
        await stateWaitFor { successClient.didFinish }
        XCTAssertEqual(successStore.state, .connecting)

        let errorClient = StateDeferredFetchClient()
        let errorStore = ApprovalStore(client: errorClient, clock: StateFixedClock(now: 1), sleeper: StateThrowingSleeper())
        errorStore.start()
        await stateWaitFor { errorClient.isWaiting }
        errorStore.stop()
        errorClient.finish(.failure(.daemonUnavailable))
        await stateWaitFor { errorClient.didFinish }
        XCTAssertEqual(errorStore.state, .connecting)
    }

    func testApplicationActivationPerformsAnImmediateRefresh() async throws {
        let initial = try stateSnapshot(reviews: [])
        let active = try stateSnapshot(reviews: [stateReview(id: "active", context: .verified, canApprove: true)])
        let client = StateScriptedReviewClient(fetches: [.success(initial), .success(active)])
        let store = ApprovalStore(client: client, clock: StateFixedClock(now: 1), sleeper: StateThrowingSleeper())
        _ = await store.refreshNow()

        store.applicationDidBecomeActive()
        await stateWaitFor { client.fetchCalls == 2 }

        guard case let .ready(snapshot) = store.state else { return XCTFail("state = \(store.state)") }
        XCTAssertEqual(snapshot.reviews.map(\.id.rawValue), ["active"])
    }
}
