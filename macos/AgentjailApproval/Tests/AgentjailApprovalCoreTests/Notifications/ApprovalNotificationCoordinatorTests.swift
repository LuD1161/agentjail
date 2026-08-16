import Foundation
import XCTest
@testable import AgentjailApprovalCore

@MainActor
final class ApprovalNotificationCoordinatorTests: XCTestCase {
    func testRegistrationAndAuthorizationAreExplicit() async throws {
        let center = FakeNotificationCenter(authorization: .notDetermined)
        let storage = FakeDedupeStorage()
        let store = ApprovalStore(client: ScriptedReviewClient(fetches: []), clock: FixedClock())
        let coordinator = ApprovalNotificationCoordinator(center: center, storage: storage, store: store)
        let snapshot = try makeSnapshot(reviews: [])

        await coordinator.synchronize(snapshot: AuthoritativeApprovalSnapshot(snapshot))
        XCTAssertEqual(center.categoryRegistrations, 0)
        XCTAssertEqual(center.authorizationRequests, 0)
        let initialAuthorization = await coordinator.notificationAuthorizationStatus()
        XCTAssertEqual(initialAuthorization, .notDetermined)
        XCTAssertEqual(center.authorizationRequests, 0)

        coordinator.registerCategories()
        coordinator.registerCategories()
        XCTAssertEqual(center.categoryRegistrations, 1)

        center.authorization = .authorized
        let authorization = await coordinator.enableNotificationsFromUserAction()
        XCTAssertEqual(authorization, .authorized)
        XCTAssertEqual(center.authorizationRequests, 1)
    }

    func testGenericDigestRequestsDeduplicateAndPrune() async throws {
        let first = try ReviewID(rawValue: "review-first")
        let second = try ReviewID(rawValue: "review-second")
        let center = FakeNotificationCenter(authorization: .authorized)
        let storage = FakeDedupeStorage()
        let store = ApprovalStore(client: ScriptedReviewClient(fetches: []), clock: FixedClock())
        let coordinator = ApprovalNotificationCoordinator(center: center, storage: storage, store: store)
        let initial = try makeSnapshot(reviews: [try review(first), try review(second)])

        await coordinator.synchronize(snapshot: AuthoritativeApprovalSnapshot(initial))
        XCTAssertEqual(center.requests.count, 2)
        for request in center.requests {
            XCTAssertEqual(request.title, ApprovalNotificationConfiguration.title)
            XCTAssertEqual(request.body, ApprovalNotificationConfiguration.body)
            XCTAssertEqual(request.categoryIdentifier, ApprovalNotificationConfiguration.categoryIdentifier)
            XCTAssertTrue(request.identifier.hasPrefix(ApprovalNotificationConfiguration.requestIdentifierPrefix))
            XCTAssertFalse(request.identifier.contains(first.rawValue))
            XCTAssertFalse(request.identifier.contains(second.rawValue))
            XCTAssertEqual(Set(request.userInfo.keys), [ApprovalNotificationConfiguration.reviewIDUserInfoKey])
        }
        XCTAssertEqual(storage.reviewIDs, Set([first, second]))

        await coordinator.synchronize(snapshot: AuthoritativeApprovalSnapshot(initial))
        XCTAssertEqual(center.requests.count, 2)

        let current = try makeSnapshot(reviews: [try review(second)])
        await coordinator.synchronize(snapshot: AuthoritativeApprovalSnapshot(current))
        XCTAssertEqual(storage.reviewIDs, Set([second]))
        XCTAssertEqual(center.removedIdentifiers, Set([ApprovalNotificationConfiguration.requestIdentifier(for: first)]))
    }

    func testStoredIDsAndNativeRequestsPreventRestartDuplicateAndBoundStorage() async throws {
        let retained = try ReviewID(rawValue: "review-retained")
        let stale = Set((0..<70).compactMap { try? ReviewID(rawValue: "stale-\($0)") })
        let center = FakeNotificationCenter(authorization: .authorized)
        let storage = FakeDedupeStorage(reviewIDs: stale.union([retained]))
        let store = ApprovalStore(client: ScriptedReviewClient(fetches: []), clock: FixedClock())
        let coordinator = ApprovalNotificationCoordinator(center: center, storage: storage, store: store)
        let snapshot = try makeSnapshot(reviews: [try review(retained)])

        await coordinator.synchronize(snapshot: AuthoritativeApprovalSnapshot(snapshot))
        XCTAssertTrue(center.requests.isEmpty)
        XCTAssertEqual(storage.reviewIDs, Set([retained]))
        XCTAssertLessThanOrEqual(storage.reviewIDs.count, ApprovalNotificationConfiguration.maximumRememberedReviewIDs)

        storage.reviewIDs = []
        center.existing = [ApprovalNotificationConfiguration.requestIdentifier(for: retained)]
        await coordinator.synchronize(snapshot: AuthoritativeApprovalSnapshot(snapshot))
        XCTAssertTrue(center.requests.isEmpty)
        XCTAssertEqual(storage.reviewIDs, Set([retained]))
    }

    func testDeniedAuthorizationPrunesButDoesNotSchedule() async throws {
        let current = try ReviewID(rawValue: "review-current")
        let stale = try ReviewID(rawValue: "review-stale")
        let center = FakeNotificationCenter(
            authorization: .denied,
            existing: [ApprovalNotificationConfiguration.requestIdentifier(for: stale)]
        )
        let storage = FakeDedupeStorage(reviewIDs: [current, stale])
        let store = ApprovalStore(client: ScriptedReviewClient(fetches: []), clock: FixedClock())
        let coordinator = ApprovalNotificationCoordinator(center: center, storage: storage, store: store)
        let snapshot = try makeSnapshot(reviews: [try review(current)])

        await coordinator.synchronize(snapshot: AuthoritativeApprovalSnapshot(snapshot))
        XCTAssertTrue(center.requests.isEmpty)
        XCTAssertEqual(center.removedIdentifiers, Set([ApprovalNotificationConfiguration.requestIdentifier(for: stale)]))
        XCTAssertEqual(storage.reviewIDs, Set([current]))
    }

    func testReviewRoutesWithGenerationAndNeverMutates() async throws {
        let reviewID = try ReviewID(rawValue: "review-route")
        let client = ScriptedReviewClient(fetches: [])
        let store = ApprovalStore(client: client, clock: FixedClock())
        let coordinator = ApprovalNotificationCoordinator(center: FakeNotificationCenter(), storage: FakeDedupeStorage(), store: store)
        var routes: [ApprovalNotificationReviewRoute] = []
        coordinator.reviewRouteHandler = { routes.append($0) }

        await coordinator.handleNotificationResponse(ApprovalNotificationResponse(action: .review, reviewID: reviewID))
        await coordinator.handleNotificationResponse(ApprovalNotificationResponse(action: .review, reviewID: reviewID))
        await coordinator.handleNotificationResponse(ApprovalNotificationResponse(action: .other, reviewID: reviewID))
        await coordinator.handleNotificationResponse(ApprovalNotificationResponse(action: .other, reviewID: nil))

        XCTAssertEqual(routes.map(\.reviewID), [reviewID, reviewID])
        XCTAssertEqual(routes.map(\.generation), [1, 2])
        XCTAssertEqual(client.denyCalls, 0)
        XCTAssertEqual(client.approveCalls, 0)
        XCTAssertEqual(client.fetchCalls, 0)
    }

    func testDenyFreshlyRevalidatesThenMutatesOnce() async throws {
        let reviewID = try ReviewID(rawValue: "review-deny")
        let pending = try makeSnapshot(reviews: [try review(reviewID)])
        let empty = try makeSnapshot(reviews: [])
        let client = ScriptedReviewClient(fetches: [.success(pending), .success(pending), .success(empty)])
        let store = ApprovalStore(client: client, clock: FixedClock())
        _ = await store.refreshNow()
        let coordinator = ApprovalNotificationCoordinator(center: FakeNotificationCenter(), storage: FakeDedupeStorage(), store: store)

        await coordinator.handleNotificationResponse(ApprovalNotificationResponse(action: .deny, reviewID: reviewID))
        await coordinator.handleNotificationResponse(ApprovalNotificationResponse(action: .deny, reviewID: reviewID))

        XCTAssertEqual(client.denyCalls, 1)
        XCTAssertEqual(client.fetchCalls, 3)
    }

    func testDenyDoesNothingWhenFreshSnapshotIsStaleOrUnavailable() async throws {
        let reviewID = try ReviewID(rawValue: "review-stale")
        let pending = try makeSnapshot(reviews: [try review(reviewID)])
        let empty = try makeSnapshot(reviews: [])
        let staleClient = ScriptedReviewClient(fetches: [.success(pending), .success(empty)])
        let staleStore = ApprovalStore(client: staleClient, clock: FixedClock())
        _ = await staleStore.refreshNow()
        let staleCoordinator = ApprovalNotificationCoordinator(center: FakeNotificationCenter(), storage: FakeDedupeStorage(), store: staleStore)
        await staleCoordinator.handleNotificationResponse(ApprovalNotificationResponse(action: .deny, reviewID: reviewID))
        XCTAssertEqual(staleClient.denyCalls, 0)

        let unavailableClient = ScriptedReviewClient(fetches: [.success(pending), .failure(.daemonUnavailable)])
        let unavailableStore = ApprovalStore(client: unavailableClient, clock: FixedClock())
        _ = await unavailableStore.refreshNow()
        let unavailableCoordinator = ApprovalNotificationCoordinator(center: FakeNotificationCenter(), storage: FakeDedupeStorage(), store: unavailableStore)
        await unavailableCoordinator.handleNotificationResponse(ApprovalNotificationResponse(action: .deny, reviewID: reviewID))
        XCTAssertEqual(unavailableClient.denyCalls, 0)
    }

    func testDenySaturationNeverReenablesOldOrNewNotificationIDs() async throws {
        let empty = try makeSnapshot(reviews: [])
        let maximum = ApprovalNotificationConfiguration.maximumRememberedReviewIDs
        let client = ScriptedReviewClient(fetches: Array(repeating: .success(empty), count: maximum))
        let store = ApprovalStore(client: client, clock: FixedClock())
        let coordinator = ApprovalNotificationCoordinator(center: FakeNotificationCenter(), storage: FakeDedupeStorage(), store: store)
        let firstReviewID = try ReviewID(rawValue: "review-deny-0")

        for index in 0 ..< maximum {
            let reviewID = try ReviewID(rawValue: "review-deny-\(index)")
            await coordinator.handleNotificationResponse(ApprovalNotificationResponse(action: .deny, reviewID: reviewID))
        }

        XCTAssertEqual(client.fetchCalls, maximum)
        await coordinator.handleNotificationResponse(ApprovalNotificationResponse(action: .deny, reviewID: firstReviewID))
        await coordinator.handleNotificationResponse(
            ApprovalNotificationResponse(action: .deny, reviewID: try ReviewID(rawValue: "review-deny-overflow"))
        )
        XCTAssertEqual(client.fetchCalls, maximum)
        XCTAssertEqual(client.denyCalls, 0)
    }

    func testInvalidReviewIDsCannotBecomeNotificationIdentifiers() {
        XCTAssertNil(try? ReviewID(rawValue: "bidi\u{202E}review"))
        XCTAssertNil(try? ReviewID(rawValue: String(repeating: "a", count: 513)))
    }

    private func review(_ id: ReviewID) throws -> Review {
        try Review(
            id: id,
            kind: .projectHost,
            host: "example.test",
            projectPath: "/private/tmp/project",
            reason: "reason",
            reasonTruncated: false,
            contextState: .verified,
            createdAt: UnixMilliseconds(rawValue: 1),
            expiresAt: UnixMilliseconds(rawValue: 2_000),
            approvalScope: .futureProjectSessions,
            canApprove: true,
            canDeny: true
        )
    }

    private func makeSnapshot(reviews: [Review]) throws -> ReviewSnapshotV1 {
        try ReviewSnapshotV1(
            version: ReviewSnapshotV1.protocolVersion,
            generatedAt: UnixMilliseconds(rawValue: 1),
            totalPending: reviews.count,
            truncated: false,
            reviews: reviews
        )
    }
}

@MainActor
private final class FakeNotificationCenter: ApprovalNotificationCenter {
    var authorization: ApprovalNotificationAuthorization
    var categoryRegistrations = 0
    var authorizationRequests = 0
    var requests: [ApprovalNotificationRequest] = []
    var existing: Set<String>
    var removedIdentifiers: Set<String> = []

    init(authorization: ApprovalNotificationAuthorization = .authorized, existing: Set<String> = []) {
        self.authorization = authorization
        self.existing = existing
    }

    func registerApprovalCategory() { categoryRegistrations += 1 }
    func authorizationStatus() async -> ApprovalNotificationAuthorization { authorization }
    func requestAuthorizationFromUser() async throws -> Bool {
        authorizationRequests += 1
        return authorization == .authorized
    }
    func schedule(_ request: ApprovalNotificationRequest) async throws {
        requests.append(request)
        existing.insert(request.identifier)
    }
    func existingRequestIdentifiers() async -> Set<String> { existing }
    func removeRequests(identifiers: Set<String>) {
        removedIdentifiers.formUnion(identifiers)
        existing.subtract(identifiers)
    }
}

@MainActor
private final class FakeDedupeStorage: ApprovalNotificationDedupeStoring {
    var reviewIDs: Set<ReviewID>
    init(reviewIDs: Set<ReviewID> = []) { self.reviewIDs = reviewIDs }
    func loadRememberedReviewIDs() -> Set<ReviewID> { reviewIDs }
    func saveRememberedReviewIDs(_ reviewIDs: Set<ReviewID>) { self.reviewIDs = reviewIDs }
}

private struct FixedClock: ApprovalClock {
    func now() -> UnixMilliseconds { UnixMilliseconds(rawValue: 1) }
}

private enum FetchResult {
    case success(ReviewSnapshotV1)
    case failure(ApprovalControlError)
}

private final class ScriptedReviewClient: ReviewControlling, @unchecked Sendable {
    private let lock = NSLock()
    private var fetchResults: [FetchResult]
    private var fetchCount = 0
    private var approveCount = 0
    private var denyCount = 0

    init(fetches: [FetchResult]) { fetchResults = fetches }
    var fetchCalls: Int { lock.withLock { fetchCount } }
    var approveCalls: Int { lock.withLock { approveCount } }
    var denyCalls: Int { lock.withLock { denyCount } }

    func fetchSnapshot() async throws -> ReviewSnapshotV1 {
        let result = lock.withLock { () -> FetchResult in
            fetchCount += 1
            return fetchResults.isEmpty ? .failure(.daemonUnavailable) : fetchResults.removeFirst()
        }
        switch result {
        case let .success(snapshot): return snapshot
        case let .failure(error): throw error
        }
    }

    func approve(_ reviewID: ReviewID) async throws { lock.withLock { approveCount += 1 } }
    func deny(_ reviewID: ReviewID) async throws { lock.withLock { denyCount += 1 } }
}
