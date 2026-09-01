import AgentjailApprovalCore
import Foundation

@MainActor
final class ActivityStore: ObservableObject {
    @Published private(set) var networkSnapshot: NetworkSnapshotV1?
    @Published private(set) var sessionLogSnapshot: SessionLogSnapshotV1?
    @Published private(set) var isRefreshingNetwork = false
    @Published private(set) var isRefreshingLogs = false
    @Published private(set) var networkUnavailable = false
    @Published private(set) var logsUnavailable = false
    @Published private(set) var selectedSessionID = ""
    @Published private(set) var actionDetail: SessionActionDetailV1?
    @Published private(set) var isLoadingActionDetail = false
    @Published private(set) var actionDetailUnavailable = false

    private let client: any ActivityControlling
    private let pollInterval: Duration
    private var networkTask: Task<Void, Never>?
    private var logTask: Task<Void, Never>?
    private var requestedSessionID: String?
    private var logGeneration: UInt64 = 0
    private var detailGeneration: UInt64 = 0

    init(
        client: any ActivityControlling = ActivityControlClient(),
        pollInterval: Duration = .seconds(2)
    ) {
        self.client = client
        self.pollInterval = pollInterval
    }

    deinit {
        networkTask?.cancel()
        logTask?.cancel()
    }

    func startNetworkPolling() {
        guard networkTask == nil else { return }
        networkTask = Task { [weak self] in
            guard let self else { return }
            while !Task.isCancelled {
                await refreshNetwork()
                do { try await Task.sleep(for: pollInterval) }
                catch { return }
            }
        }
    }

    func stopNetworkPolling() {
        networkTask?.cancel()
        networkTask = nil
    }

    func startLogPolling(sessionID: String? = nil) {
        if let sessionID {
            requestedSessionID = sessionID
            selectedSessionID = sessionID
        }
        guard logTask == nil else { return }
        logTask = Task { [weak self] in
            guard let self else { return }
            while !Task.isCancelled {
                await refreshLogs()
                do { try await Task.sleep(for: pollInterval) }
                catch { return }
            }
        }
    }

    func stopLogPolling() {
        logTask?.cancel()
        logTask = nil
    }

    func selectSession(_ sessionID: String) {
        guard requestedSessionID != sessionID else { return }
        clearActionDetail()
        logGeneration &+= 1
        requestedSessionID = sessionID
        selectedSessionID = sessionID
        logTask?.cancel()
        logTask = nil
        startLogPolling(sessionID: sessionID)
    }

    func loadActionDetail(_ entry: SessionAction) async {
        let sessionID = selectedSessionID
        guard !sessionID.isEmpty else {
            actionDetailUnavailable = true
            return
        }
        detailGeneration &+= 1
        let generation = detailGeneration
        actionDetail = nil
        actionDetailUnavailable = false
        isLoadingActionDetail = true
        defer {
            if generation == detailGeneration { isLoadingActionDetail = false }
        }
        do {
            let detail = try await client.fetchSessionActionDetail(sessionID: sessionID, actionID: entry.id)
            guard generation == detailGeneration, detail.actionID == entry.id,
                  detail.sessionID == selectedSessionID else { return }
            actionDetail = detail
        } catch is CancellationError {
            return
        } catch {
            if generation == detailGeneration { actionDetailUnavailable = true }
        }
    }

    func clearActionDetail() {
        detailGeneration &+= 1
        actionDetail = nil
        actionDetailUnavailable = false
        isLoadingActionDetail = false
    }

    func refreshNetwork() async {
        guard !isRefreshingNetwork else { return }
        isRefreshingNetwork = true
        defer { isRefreshingNetwork = false }
        do {
            networkSnapshot = try await client.fetchNetwork()
            networkUnavailable = false
        } catch is CancellationError {
            return
        } catch {
            networkUnavailable = networkSnapshot == nil
        }
    }

    func refreshLogs() async {
        let requested = requestedSessionID
        let generation = logGeneration
        isRefreshingLogs = true
        defer {
            if generation == logGeneration { isRefreshingLogs = false }
        }
        do {
            let snapshot = try await client.fetchSessionLog(sessionID: requested)
            guard !Task.isCancelled, generation == logGeneration, requested == requestedSessionID else { return }
            sessionLogSnapshot = snapshot
            requestedSessionID = snapshot.selectedSessionID.isEmpty ? nil : snapshot.selectedSessionID
            selectedSessionID = snapshot.selectedSessionID
            logsUnavailable = false
        } catch is CancellationError {
            return
        } catch {
            if generation == logGeneration { logsUnavailable = sessionLogSnapshot == nil }
        }
    }
}
