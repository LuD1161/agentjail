import XCTest
@testable import AgentjailApprovalApp
@testable import AgentjailApprovalCore

@MainActor
final class ApprovalAppCompositionTests: XCTestCase {
    func testLaunchPreparesDelegateAndCategoriesBeforeOnePollingStartWithoutPermissionOrLoginMutation() async {
        let events = CompositionEventRecorder()
        let client = CompositionReviewClient(snapshotResult: .failure(.daemonUnavailable), events: events)
        let notificationCenter = CompositionNotificationCenter(events: events)
        let delegateInstaller = CompositionDelegateInstaller(events: events)
        let loginService = CompositionLoginService()
        let application = CompositionApplication()
        let composition = makeComposition(
            client: client,
            notificationCenter: notificationCenter,
            delegateInstaller: delegateInstaller,
            loginService: loginService,
            application: application
        )

        composition.prepareForLaunch()
        composition.start()
        composition.start()

        await eventually { client.fetchCount == 1 }
        XCTAssertEqual(Array(events.values.prefix(3)), ["delegate", "category", "fetch"])
        XCTAssertEqual(delegateInstaller.delegates.count, 1)
        XCTAssertEqual(notificationCenter.categoryRegistrationCount, 1)
        XCTAssertEqual(notificationCenter.authorizationRequestCount, 0)
        XCTAssertEqual(loginService.registerCount, 0)
        XCTAssertEqual(loginService.unregisterCount, 0)

        composition.stop()
    }

    func testNotificationReviewRefreshesBeforeOpeningSingletonWindowAndClearsOnlyAfterPanelConsumesFocus() async throws {
        let reviewID = try ReviewID(rawValue: "review-route")
        let client = CompositionReviewClient(snapshotResult: .success(snapshot(reviewID: reviewID)))
        let notificationCenter = CompositionNotificationCenter()
        let delegateInstaller = CompositionDelegateInstaller()
        let application = CompositionApplication()
        let composition = makeComposition(
            client: client,
            notificationCenter: notificationCenter,
            delegateInstaller: delegateInstaller,
            loginService: CompositionLoginService(),
            application: application
        )
        composition.prepareForLaunch()

        let completion = expectation(description: "notification response completion")
        delegateInstaller.delegates[0].receiveResponse(
            actionIdentifier: ApprovalNotificationConfiguration.reviewActionIdentifier,
            userInfo: [ApprovalNotificationConfiguration.reviewIDUserInfoKey: reviewID.rawValue],
            completionHandler: { completion.fulfill() }
        )
        await fulfillment(of: [completion], timeout: 1)
        await eventually { composition.reviewRoute?.reviewID == reviewID }

        var windowOpenCount = 0
        guard let route = composition.reviewRoute else {
            return XCTFail("expected a notification review route")
        }
        await composition.dispatchReviewRoute(route) {
            windowOpenCount += 1
        }
        await composition.dispatchReviewRoute(route) {
            windowOpenCount += 1
        }

        XCTAssertEqual(client.fetchCount, 1)
        XCTAssertEqual(application.activationCount, 1)
        XCTAssertEqual(windowOpenCount, 1)
        XCTAssertEqual(composition.focusRequest, ReviewFocusRequest(reviewID: reviewID, generation: route.generation))
        XCTAssertEqual(client.approveCount, 0)
        XCTAssertEqual(client.denyCount, 0)

        composition.consumeFocus(ReviewFocusRequest(reviewID: reviewID, generation: route.generation))
        XCTAssertNil(composition.reviewRoute)
        XCTAssertNil(composition.focusRequest)
    }

    func testRoutesPresentBeforeLabelMountDispatchEachGenerationOnceInRefreshFocusOpenOrder() async throws {
        let reviewID = try ReviewID(rawValue: "review-cold-route")
        let events = CompositionEventRecorder()
        let client = CompositionReviewClient(
            snapshotResults: [.success(snapshot(reviewID: reviewID)), .success(snapshot(reviewID: reviewID))],
            events: events
        )
        let application = CompositionApplication(events: events)
        let composition = makeComposition(
            client: client,
            notificationCenter: CompositionNotificationCenter(),
            delegateInstaller: CompositionDelegateInstaller(),
            loginService: CompositionLoginService(),
            application: application
        )

        let first = ApprovalNotificationReviewRoute(reviewID: reviewID, generation: 1)
        composition.receiveReviewRoute(first)
        var openedRoutes: [ApprovalNotificationReviewRoute] = []
        await composition.dispatchReviewRoute(first) {
            XCTAssertEqual(composition.focusRequest?.generation, first.generation)
            openedRoutes.append(first)
            events.record("open")
        }
        await composition.dispatchReviewRoute(first) {
            openedRoutes.append(first)
        }

        let second = ApprovalNotificationReviewRoute(reviewID: reviewID, generation: 2)
        composition.receiveReviewRoute(second)
        await composition.dispatchReviewRoute(second) {
            XCTAssertEqual(composition.focusRequest?.generation, second.generation)
            openedRoutes.append(second)
            events.record("open")
        }

        XCTAssertEqual(openedRoutes, [first, second])
        XCTAssertEqual(events.values, ["activate", "fetch", "open", "activate", "fetch", "open"])
        XCTAssertEqual(composition.panelPresentation().focus, .none)
        XCTAssertEqual(
            composition.panelPresentation(focusRequest: composition.focusRequest).focus,
            .target(ReviewFocusRequest(reviewID: reviewID, generation: second.generation))
        )
        XCTAssertEqual(client.approveCount, 0)
        XCTAssertEqual(client.denyCount, 0)
    }

    func testMissingReviewRouteIsNonActionableAndConsumesOnlyFromSupplementalWindow() async throws {
        let reviewID = try ReviewID(rawValue: "review-missing-route")
        let client = CompositionReviewClient(snapshotResult: .success(snapshot(reviews: [])))
        let composition = makeComposition(
            client: client,
            notificationCenter: CompositionNotificationCenter(),
            delegateInstaller: CompositionDelegateInstaller(),
            loginService: CompositionLoginService(),
            application: CompositionApplication()
        )
        let route = ApprovalNotificationReviewRoute(reviewID: reviewID, generation: 1)
        composition.receiveReviewRoute(route)
        await composition.dispatchReviewRoute(route) {}

        XCTAssertEqual(composition.panelPresentation().focus, .none)
        guard case .unavailable = composition.panelPresentation(focusRequest: composition.focusRequest).focus else {
            return XCTFail("expected missing review feedback in the supplemental window")
        }
        XCTAssertNotNil(composition.reviewRoute)
        XCTAssertEqual(client.approveCount, 0)
        XCTAssertEqual(client.denyCount, 0)
        composition.consumeFocus(ReviewFocusRequest(reviewID: reviewID, generation: route.generation))
        XCTAssertNil(composition.reviewRoute)
    }

    func testLoginAndNotificationMutationsRequireExplicitUserActions() async {
        let notificationCenter = CompositionNotificationCenter()
        let loginService = CompositionLoginService()
        let composition = makeComposition(
            client: CompositionReviewClient(snapshotResult: .failure(.daemonUnavailable)),
            notificationCenter: notificationCenter,
            delegateInstaller: CompositionDelegateInstaller(),
            loginService: loginService,
            application: CompositionApplication()
        )

        await composition.refreshSettingsStatus()
        XCTAssertEqual(notificationCenter.authorizationRequestCount, 0)
        XCTAssertEqual(loginService.registerCount, 0)

        await composition.enableNotificationsFromUserAction()
        await composition.setLoginItemEnabledFromUserAction(true)
        XCTAssertEqual(notificationCenter.authorizationRequestCount, 1)
        XCTAssertEqual(loginService.registerCount, 1)
        XCTAssertEqual(composition.loginStatus, .enabled)

        await composition.setLoginItemEnabledFromUserAction(false)
        XCTAssertEqual(loginService.unregisterCount, 1)
        XCTAssertEqual(composition.loginStatus, .notRegistered)

        loginService.registerFailure = true
        await composition.setLoginItemEnabledFromUserAction(true)
        XCTAssertEqual(loginService.registerCount, 2)
        XCTAssertEqual(composition.loginStatus, .notRegistered)
        XCTAssertNotNil(composition.settingsError)

        composition.openLoginItemsSettings()
        XCTAssertEqual(loginService.openSettingsCount, 1)
        XCTAssertGreaterThanOrEqual(loginService.statusCount, 3)
    }

    func testTelemetryMutationUsesTypedServiceAndHonorsExternalOverrides() async {
        let telemetryService = CompositionTelemetryService(status: .enabled(.config))
        let composition = makeComposition(
            client: CompositionReviewClient(snapshotResult: .failure(.daemonUnavailable)),
            notificationCenter: CompositionNotificationCenter(),
            delegateInstaller: CompositionDelegateInstaller(),
            loginService: CompositionLoginService(),
            application: CompositionApplication(),
            telemetryService: telemetryService
        )

        await composition.refreshSettingsStatus()
        XCTAssertEqual(composition.telemetryStatus, .enabled(.config))
        await composition.setTelemetryEnabledFromUserAction(false)
        XCTAssertEqual(composition.telemetryStatus, .disabled(.config))
        var mutationCount = await telemetryService.setCount()
        XCTAssertEqual(mutationCount, 1)

        await telemetryService.replaceStatus(.disabled(.environment))
        await composition.refreshSettingsStatus()
        await composition.setTelemetryEnabledFromUserAction(true)
        XCTAssertEqual(composition.telemetryStatus, .disabled(.environment))
        mutationCount = await telemetryService.setCount()
        XCTAssertEqual(mutationCount, 1)
    }

    func testRemovingMenuExtraStopsStoreAndTerminatesWithoutChangingLoginRegistration() async {
        let client = CompositionReviewClient(snapshotResult: .failure(.daemonUnavailable))
        let loginService = CompositionLoginService()
        let application = CompositionApplication()
        let composition = makeComposition(
            client: client,
            notificationCenter: CompositionNotificationCenter(),
            delegateInstaller: CompositionDelegateInstaller(),
            loginService: loginService,
            application: application
        )
        composition.start()
        await eventually { client.fetchCount == 1 }

        composition.menuBarExtraInsertionChanged(false)
        composition.menuBarExtraInsertionChanged(false)
        XCTAssertEqual(application.terminationCount, 1)
        XCTAssertEqual(loginService.registerCount, 0)
        XCTAssertEqual(loginService.unregisterCount, 0)
    }

    func testQuitIsIdempotentAndTerminatesTheApplication() async {
        let application = CompositionApplication()
        let composition = makeComposition(
            client: CompositionReviewClient(snapshotResult: .failure(.daemonUnavailable)),
            notificationCenter: CompositionNotificationCenter(),
            delegateInstaller: CompositionDelegateInstaller(),
            loginService: CompositionLoginService(),
            application: application
        )
        composition.start()
        composition.quit()
        composition.quit()
        composition.stop()

        XCTAssertEqual(application.terminationCount, 1)
    }

    func testMenuOpeningAndActivationRefreshAndPresentationKeepsStaleAndUnsupportedRowsNonActionable() async throws {
        let reviewID = try ReviewID(rawValue: "review-transitions")
        let client = CompositionReviewClient(snapshotResults: [
            .success(snapshot(reviews: [])),
            .success(snapshot(reviews: [review(reviewID: reviewID)])),
            .failure(.daemonUnavailable),
            .failure(.protocolMismatch),
            .success(snapshot(reviews: [review(reviewID: reviewID)])),
        ])
        let composition = makeComposition(
            client: client,
            notificationCenter: CompositionNotificationCenter(),
            delegateInstaller: CompositionDelegateInstaller(),
            loginService: CompositionLoginService(),
            application: CompositionApplication()
        )

        composition.start()
        await eventually { client.fetchCount == 1 }
        XCTAssertEqual(composition.panelPresentation().cards.count, 0)

        composition.refreshFromMenuOpening()
        await eventually { client.fetchCount == 2 }
        XCTAssertEqual(composition.panelPresentation().cards.first?.canApprove, true)

        composition.applicationDidBecomeActive()
        await eventually { client.fetchCount == 3 }
        let disconnected = composition.panelPresentation()
        XCTAssertEqual(disconnected.status.kind, .disconnected)
        XCTAssertEqual(disconnected.cards.first?.canApprove, false)
        XCTAssertEqual(disconnected.cards.first?.canDeny, false)

        _ = await composition.store.refreshNow()
        let unsupported = composition.panelPresentation()
        XCTAssertEqual(unsupported.status.kind, .unsupportedProtocol)
        XCTAssertEqual(unsupported.cards.first?.canApprove, false)
        XCTAssertEqual(unsupported.cards.first?.canDeny, false)

        _ = await composition.store.refreshNow()
        XCTAssertEqual(composition.panelPresentation().cards.first?.canApprove, true)
    }

    func testApproveRefusalKeepsTheRowVisibleUntilAnExplicitRecoveryAttempt() async throws {
        let reviewID = try ReviewID(rawValue: "review-approve-refusal")
        let client = CompositionReviewClient(
            snapshotResults: [.success(snapshot(reviewID: reviewID)), .success(snapshot(reviewID: reviewID)), .success(snapshot(reviews: []))],
            approveResults: [.failure(.serverRefused("refused")), .success(())]
        )
        let composition = makeComposition(
            client: client,
            notificationCenter: CompositionNotificationCenter(),
            delegateInstaller: CompositionDelegateInstaller(),
            loginService: CompositionLoginService(),
            application: CompositionApplication()
        )
        _ = await composition.store.refreshNow()

        composition.approve(reviewID)
        await eventually { client.approveCount == 1 && composition.store.actionState(for: reviewID) != .approving }
        XCTAssertEqual(client.approvedIDs, [reviewID])
        XCTAssertEqual(composition.panelPresentation().cards.first?.id, reviewID)
        guard case .failed = composition.store.actionState(for: reviewID) else {
            return XCTFail("expected refusal to remain visible on the row")
        }

        composition.approve(reviewID)
        await eventually { client.approveCount == 2 && composition.panelPresentation().cards.isEmpty }
    }

    func testDenyRaceKeepsTheRowVisibleUntilAnExplicitRecoveryAttempt() async throws {
        let reviewID = try ReviewID(rawValue: "review-deny-race")
        let client = CompositionReviewClient(
            snapshotResults: [.success(snapshot(reviewID: reviewID)), .success(snapshot(reviewID: reviewID)), .success(snapshot(reviews: []))],
            denyResults: [.failure(.serverRefused("already resolved")), .success(())]
        )
        let composition = makeComposition(
            client: client,
            notificationCenter: CompositionNotificationCenter(),
            delegateInstaller: CompositionDelegateInstaller(),
            loginService: CompositionLoginService(),
            application: CompositionApplication()
        )
        _ = await composition.store.refreshNow()

        composition.deny(reviewID)
        await eventually { client.denyCount == 1 && composition.store.actionState(for: reviewID) != .denying }
        XCTAssertEqual(client.deniedIDs, [reviewID])
        XCTAssertEqual(composition.panelPresentation().cards.first?.id, reviewID)

        composition.deny(reviewID)
        await eventually { client.denyCount == 2 && composition.panelPresentation().cards.isEmpty }
    }

    func testSerialNotificationSynchronizationLeavesTheNewestSnapshotLastAfterAnOlderBlockedSync() async throws {
        let oldID = try ReviewID(rawValue: "review-old")
        let newID = try ReviewID(rawValue: "review-new")
        let notificationCenter = BlockingCompositionNotificationCenter()
        let composition = makeComposition(
            client: CompositionReviewClient(snapshotResults: [
                .success(snapshot(reviewID: oldID)),
                .success(snapshot(reviewID: newID)),
            ]),
            notificationCenter: notificationCenter,
            delegateInstaller: CompositionDelegateInstaller(),
            loginService: CompositionLoginService(),
            application: CompositionApplication()
        )

        _ = await composition.store.refreshNow()
        await notificationCenter.waitUntilFirstExistingRequest()
        _ = await composition.store.refreshNow()
        notificationCenter.releaseFirstExistingRequest()
        await eventually { notificationCenter.pendingReviewIDs == [newID] }
        XCTAssertEqual(notificationCenter.scheduledReviewIDs, [oldID, newID])
    }

    private func makeComposition(
        client: CompositionReviewClient,
        notificationCenter: any ApprovalNotificationCenter,
        delegateInstaller: CompositionDelegateInstaller,
        loginService: CompositionLoginService,
        application: CompositionApplication,
        telemetryService: any ApprovalTelemetryServicing = CompositionTelemetryService()
    ) -> ApprovalAppComposition {
        ApprovalAppComposition(
            client: client,
            notificationCenter: notificationCenter,
            notificationStorage: CompositionNotificationStorage(),
            notificationDelegateInstaller: delegateInstaller,
            loginService: loginService,
            application: application,
            telemetryService: telemetryService,
            sleeper: CompositionSleeper()
        )
    }

    private func snapshot(reviewID: ReviewID) -> ReviewSnapshotV1 {
        snapshot(reviews: [review(reviewID: reviewID)])
    }

    private func snapshot(reviews: [Review]) -> ReviewSnapshotV1 {
        try! ReviewSnapshotV1(
            version: ReviewSnapshotV1.protocolVersion,
            generatedAt: UnixMilliseconds(rawValue: 1),
            totalPending: reviews.count,
            truncated: false,
            reviews: reviews
        )
    }

    private func review(reviewID: ReviewID) -> Review {
        try! Review(
            id: reviewID,
            kind: .projectHost,
            host: "example.test",
            projectPath: "/tmp/project",
            reason: "request",
            reasonTruncated: false,
            contextState: .verified,
            createdAt: UnixMilliseconds(rawValue: 1),
            expiresAt: UnixMilliseconds(rawValue: Int64.max),
            approvalScope: .futureProjectSessions,
            canApprove: true,
            canDeny: true
        )
    }

    private func eventually(
        timeout: Duration = .seconds(1),
        condition: @escaping @MainActor () -> Bool
    ) async {
        let clock = ContinuousClock()
        let deadline = clock.now + timeout
        while !condition(), clock.now < deadline {
            await Task.yield()
        }
        XCTAssertTrue(condition())
    }
}

@MainActor
private final class CompositionReviewClient: ReviewControlling, @unchecked Sendable {
    private var snapshotResults: [Result<ReviewSnapshotV1, ApprovalControlError>]
    private var approveResults: [Result<Void, ApprovalControlError>]
    private var denyResults: [Result<Void, ApprovalControlError>]
    private let events: CompositionEventRecorder?
    private(set) var fetchCount = 0
    private(set) var approveCount = 0
    private(set) var denyCount = 0
    private(set) var approvedIDs: [ReviewID] = []
    private(set) var deniedIDs: [ReviewID] = []

    init(snapshotResult: Result<ReviewSnapshotV1, ApprovalControlError>, events: CompositionEventRecorder? = nil) {
        self.snapshotResults = [snapshotResult]
        approveResults = []
        denyResults = []
        self.events = events
    }

    init(
        snapshotResults: [Result<ReviewSnapshotV1, ApprovalControlError>],
        approveResults: [Result<Void, ApprovalControlError>] = [],
        denyResults: [Result<Void, ApprovalControlError>] = [],
        events: CompositionEventRecorder? = nil
    ) {
        self.snapshotResults = snapshotResults
        self.approveResults = approveResults
        self.denyResults = denyResults
        self.events = events
    }

    func fetchSnapshot() async throws -> ReviewSnapshotV1 {
        fetchCount += 1
        events?.record("fetch")
        return try snapshotResults.removeFirst().get()
    }

    func approve(_ reviewID: ReviewID) async throws {
        approveCount += 1
        approvedIDs.append(reviewID)
        guard !approveResults.isEmpty else { return }
        try approveResults.removeFirst().get()
    }

    func deny(_ reviewID: ReviewID) async throws {
        denyCount += 1
        deniedIDs.append(reviewID)
        guard !denyResults.isEmpty else { return }
        try denyResults.removeFirst().get()
    }
}

@MainActor
private final class CompositionNotificationCenter: ApprovalNotificationCenter {
    private let events: CompositionEventRecorder?
    private(set) var categoryRegistrationCount = 0
    private(set) var authorizationRequestCount = 0
    private var authorization: ApprovalNotificationAuthorization = .notDetermined

    init(events: CompositionEventRecorder? = nil) {
        self.events = events
    }

    func registerApprovalCategory() {
        categoryRegistrationCount += 1
        events?.record("category")
    }
    func authorizationStatus() async -> ApprovalNotificationAuthorization { authorization }
    func requestAuthorizationFromUser() async throws -> Bool {
        authorizationRequestCount += 1
        authorization = .authorized
        return true
    }
    func schedule(_ request: ApprovalNotificationRequest) async throws {}
    func existingRequestIdentifiers() async -> Set<String> { [] }
    func removeRequests(identifiers: Set<String>) {}
}

@MainActor
private final class CompositionNotificationStorage: ApprovalNotificationDedupeStoring {
    func loadRememberedReviewIDs() -> Set<ReviewID> { [] }
    func saveRememberedReviewIDs(_ reviewIDs: Set<ReviewID>) {}
}

@MainActor
private final class CompositionDelegateInstaller: ApprovalNotificationDelegateInstalling {
    private let events: CompositionEventRecorder?
    private(set) var delegates: [ApprovalNotificationDelegate] = []
    init(events: CompositionEventRecorder? = nil) {
        self.events = events
    }
    func install(_ delegate: ApprovalNotificationDelegate) {
        delegates.append(delegate)
        events?.record("delegate")
    }
}

@MainActor
private final class CompositionLoginService: ApprovalLoginItemServicing {
    private(set) var registerCount = 0
    private(set) var unregisterCount = 0
    private(set) var statusCount = 0
    private(set) var openSettingsCount = 0
    var registerFailure = false
    private var currentStatus: ApprovalLoginItemStatus = .notRegistered

    func status() -> ApprovalLoginItemStatus {
        statusCount += 1
        return currentStatus
    }
    func register() throws {
        registerCount += 1
        if registerFailure { throw CompositionLoginError.failed }
        currentStatus = .enabled
    }
    func unregister() throws {
        unregisterCount += 1
        currentStatus = .notRegistered
    }
    func openLoginItemsSettings() { openSettingsCount += 1 }
}

private actor CompositionTelemetryService: ApprovalTelemetryServicing {
    private var currentStatus: ApprovalTelemetryStatus
    private var mutationCount = 0

    init(status: ApprovalTelemetryStatus = .enabled(.config)) {
        currentStatus = status
    }

    func status() -> ApprovalTelemetryStatus { currentStatus }

    func setEnabled(_ enabled: Bool) -> ApprovalTelemetryStatus {
        mutationCount += 1
        currentStatus = enabled ? .enabled(.config) : .disabled(.config)
        return currentStatus
    }

    func replaceStatus(_ status: ApprovalTelemetryStatus) {
        currentStatus = status
    }

    func setCount() -> Int { mutationCount }
}

@MainActor
private final class CompositionApplication: ApprovalApplicationControlling {
    private let events: CompositionEventRecorder?
    private(set) var activationCount = 0
    private(set) var terminationCount = 0
    init(events: CompositionEventRecorder? = nil) {
        self.events = events
    }
    func activate() {
        activationCount += 1
        events?.record("activate")
    }
    func terminate() { terminationCount += 1 }
}

private struct CompositionSleeper: ApprovalSleeping {
    func sleep(seconds: Int) async throws {
        try await Task.sleep(nanoseconds: 3_600_000_000_000)
    }
}

@MainActor
private final class CompositionEventRecorder {
    private(set) var values: [String] = []
    func record(_ value: String) { values.append(value) }
}

private enum CompositionLoginError: Error {
    case failed
}

@MainActor
private final class BlockingCompositionNotificationCenter: ApprovalNotificationCenter {
    private var firstExistingRequestContinuation: CheckedContinuation<Void, Never>?
    private var firstRequestIsBlocked = true
    private var didBlockFirstRequest = false
    private var pendingIdentifiers: Set<String> = []
    private(set) var scheduledReviewIDs: [ReviewID] = []

    var pendingReviewIDs: Set<ReviewID> {
        Set(scheduledReviewIDs.filter {
            pendingIdentifiers.contains(ApprovalNotificationConfiguration.requestIdentifier(for: $0))
        })
    }

    func registerApprovalCategory() {}
    func authorizationStatus() async -> ApprovalNotificationAuthorization { .authorized }
    func requestAuthorizationFromUser() async throws -> Bool { true }
    func schedule(_ request: ApprovalNotificationRequest) async throws {
        guard let rawReviewID = request.userInfo[ApprovalNotificationConfiguration.reviewIDUserInfoKey],
              let reviewID = try? ReviewID(rawValue: rawReviewID)
        else {
            return
        }
        scheduledReviewIDs.append(reviewID)
        pendingIdentifiers.insert(request.identifier)
    }
    func existingRequestIdentifiers() async -> Set<String> {
        if firstRequestIsBlocked {
            firstRequestIsBlocked = false
            didBlockFirstRequest = true
            await withCheckedContinuation { continuation in
                firstExistingRequestContinuation = continuation
            }
        }
        return pendingIdentifiers
    }
    func removeRequests(identifiers: Set<String>) {
        pendingIdentifiers.subtract(identifiers)
    }

    func waitUntilFirstExistingRequest() async {
        while !didBlockFirstRequest {
            await Task.yield()
        }
    }

    func releaseFirstExistingRequest() {
        let continuation = firstExistingRequestContinuation
        firstExistingRequestContinuation = nil
        continuation?.resume()
    }
}
