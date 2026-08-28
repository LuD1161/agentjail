import AgentjailApprovalCore
import Combine
import Foundation

@MainActor
final class ApprovalAppComposition: ObservableObject {
    let store: ApprovalStore
    let setupCoordinator: AgentJailSetupCoordinator
    let mcpInventoryStore: MCPInventoryStore

    @Published private(set) var reviewRoute: ApprovalNotificationReviewRoute?
    @Published private(set) var focusRequest: ReviewFocusRequest?
    @Published private(set) var settingsRouteGeneration: UInt64 = 0
    @Published private(set) var setupRouteGeneration: UInt64 = 0
    @Published private(set) var mcpInventoryRouteGeneration: UInt64 = 0
    @Published private(set) var notificationAuthorization: ApprovalNotificationAuthorization = .notDetermined
    @Published private(set) var loginStatus: ApprovalLoginItemStatus = .notRegistered
    @Published private(set) var telemetryStatus: ApprovalTelemetryStatus = .unknown
    @Published private(set) var settingsError: String?

    private let notificationCoordinator: ApprovalNotificationCoordinator
    private let notificationDelegateInstaller: any ApprovalNotificationDelegateInstalling
    private let loginService: any ApprovalLoginItemServicing
    private let application: any ApprovalApplicationControlling
    private let telemetryService: any ApprovalTelemetryServicing
    private let clock: any ApprovalClock
    private var notificationDelegate: ApprovalNotificationDelegate?
    private var stateObservation: AnyCancellable?
    private var notificationSyncTask: Task<Void, Never>?
    private var pendingNotificationSnapshot: AuthoritativeApprovalSnapshot?
    private var hasPreparedForLaunch = false
    private var hasStarted = false
    private var hasTerminated = false
    private var openedReviewRouteGeneration: UInt64?

    init(
        client: any ReviewControlling,
        notificationCenter: any ApprovalNotificationCenter,
        notificationStorage: any ApprovalNotificationDedupeStoring,
        notificationDelegateInstaller: any ApprovalNotificationDelegateInstalling,
        loginService: any ApprovalLoginItemServicing,
        application: any ApprovalApplicationControlling,
        setupCoordinator: AgentJailSetupCoordinator? = nil,
        mcpInventoryStore: MCPInventoryStore? = nil,
        telemetryService: any ApprovalTelemetryServicing = BundledAgentJailTelemetryService(),
        clock: any ApprovalClock = SystemApprovalClock(),
        sleeper: any ApprovalSleeping = TaskApprovalSleeper()
    ) {
        self.clock = clock
        self.setupCoordinator = setupCoordinator ?? AgentJailSetupCoordinator()
        self.mcpInventoryStore = mcpInventoryStore ?? MCPInventoryStore()
        self.store = ApprovalStore(client: client, clock: clock, sleeper: sleeper)
        self.notificationCoordinator = ApprovalNotificationCoordinator(
            center: notificationCenter,
            storage: notificationStorage,
            store: store
        )
        self.notificationDelegateInstaller = notificationDelegateInstaller
        self.loginService = loginService
        self.application = application
        self.telemetryService = telemetryService

        notificationCoordinator.reviewRouteHandler = { [weak self] route in
            self?.receiveReviewRoute(route)
        }
        notificationDelegate = ApprovalNotificationDelegate { [weak self] response in
            await self?.handleNotificationResponse(response)
        }
        stateObservation = store.$state.sink { [weak self] state in
            self?.synchronizeNotifications(for: state)
        }
    }

    convenience init() {
        let center = UserNotificationCenterAdapter()
        self.init(
            client: ReviewControlClient(),
            notificationCenter: center,
            notificationStorage: UserDefaultsApprovalNotificationDedupeStorage(),
            notificationDelegateInstaller: UserNotificationCenterDelegateInstaller(),
            loginService: SMAppServiceLoginItemService(),
            application: NSApplicationController()
        )
    }

    deinit {
        notificationSyncTask?.cancel()
    }

    func prepareForLaunch() {
        guard !hasPreparedForLaunch, let notificationDelegate else { return }
        hasPreparedForLaunch = true
        notificationDelegateInstaller.install(notificationDelegate)
        notificationCoordinator.registerCategories()
    }

    func start() {
        guard !hasStarted else { return }
        hasStarted = true
        store.start()
    }

    func stop() {
        guard hasStarted else { return }
        hasStarted = false
        store.stop()
    }

    func applicationDidBecomeActive() {
        guard hasStarted else { return }
        store.applicationDidBecomeActive()
    }

    func menuBarExtraInsertionChanged(_ inserted: Bool) {
        guard !inserted else {
            start()
            return
        }
        stop()
        terminateOnce()
    }

    func refreshFromMenuOpening() {
        Task { [store] in
            _ = await store.refreshNow()
        }
    }

    func approve(_ reviewID: ReviewID) {
        Task { [store] in
            _ = await store.approve(reviewID)
        }
    }

    func quit() {
        stop()
        terminateOnce()
    }

    func deny(_ reviewID: ReviewID) {
        Task { [store] in
            _ = await store.deny(reviewID)
        }
    }

    func requestSettings() {
        settingsRouteGeneration &+= 1
    }

    func requestSetup() {
        application.activate()
        setupRouteGeneration &+= 1
    }

    func requestMCPInventory() {
        application.activate()
        mcpInventoryRouteGeneration &+= 1
    }

    func presentSetupIfNeeded() {
        Task { [weak self] in
            guard let self else { return }
            let health = await setupCoordinator.refresh()
            if !health.isReady {
                requestSetup()
            }
        }
    }

    func dispatchReviewRoute(_ route: ApprovalNotificationReviewRoute, openWindow: @escaping @MainActor () -> Void) async {
        guard reviewRoute == route, openedReviewRouteGeneration != route.generation else { return }
        openedReviewRouteGeneration = route.generation
        _ = await store.refreshNow()
        guard reviewRoute == route else { return }
        focusRequest = ReviewFocusRequest(reviewID: route.reviewID, generation: route.generation)
        openWindow()
    }

    func consumeFocus(_ request: ReviewFocusRequest) {
        guard focusRequest == request, reviewRoute?.generation == request.generation else { return }
        focusRequest = nil
        reviewRoute = nil
    }

    func refreshSettingsStatus() async {
        notificationAuthorization = await notificationCoordinator.notificationAuthorizationStatus()
        loginStatus = loginService.status()
        telemetryStatus = await telemetryService.status()
    }

    func enableNotificationsFromUserAction() async {
        notificationAuthorization = await notificationCoordinator.enableNotificationsFromUserAction()
    }

    func setLoginItemEnabledFromUserAction(_ enabled: Bool) async {
        do {
            if enabled {
                try loginService.register()
            } else {
                try loginService.unregister()
            }
            settingsError = nil
        } catch {
            settingsError = "Unable to update launch-at-login. Check System Settings and try again."
        }
        loginStatus = loginService.status()
    }

    func openLoginItemsSettings() {
        loginService.openLoginItemsSettings()
    }

    func setTelemetryEnabledFromUserAction(_ enabled: Bool) async {
        guard telemetryStatus.canChange else { return }
        telemetryStatus = .updating(telemetryStatus.isEnabled)
        let updated = await telemetryService.setEnabled(enabled)
        telemetryStatus = updated
        if updated == .unavailable {
            settingsError = "Unable to update anonymous usage metrics. Try again from the AgentJail CLI."
        } else {
            settingsError = nil
        }
    }

    private func handleNotificationResponse(_ response: ApprovalNotificationResponse) async {
        await notificationCoordinator.handleNotificationResponse(response)
    }

    func receiveReviewRoute(_ route: ApprovalNotificationReviewRoute) {
        application.activate()
        openedReviewRouteGeneration = nil
        reviewRoute = route
    }

    private func synchronizeNotifications(for state: ApprovalStoreState) {
        guard case let .ready(snapshot) = state else { return }
        pendingNotificationSnapshot = snapshot
        guard notificationSyncTask == nil else { return }
        notificationSyncTask = Task { [weak self] in
            await self?.drainNotificationSynchronizations()
        }
    }

    private func drainNotificationSynchronizations() async {
        while let snapshot = pendingNotificationSnapshot {
            pendingNotificationSnapshot = nil
            await notificationCoordinator.synchronize(snapshot: snapshot)
        }
        notificationSyncTask = nil
    }

    private func terminateOnce() {
        guard !hasTerminated else { return }
        hasTerminated = true
        application.terminate()
    }

    func panelPresentation(focusRequest: ReviewFocusRequest? = nil) -> PanelPresentation {
        PanelPresentation(
            state: store.state,
            actionStates: store.actionStates,
            now: clock.now(),
            focusRequest: focusRequest
        )
    }
}
