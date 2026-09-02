import AgentjailApprovalCore
import Foundation

@MainActor
final class ActivityStore: ObservableObject {
    @Published private(set) var networkSnapshot: NetworkSnapshotV1?
    @Published private(set) var sessionLogSnapshot: SessionLogSnapshotV1?
    @Published private(set) var sessionEntries: [SessionAction] = []
    @Published private(set) var logTotalMatches = 0
    @Published private(set) var logHasMore = false
    @Published private(set) var isLoadingMoreLogs = false
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
    private var logSearch = ""
    private var logOutcomes: [SessionActionOutcome] = []
    private var nextLogBeforeID: Int64?
    private var hasLoadedOlderLogPages = false
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
        resetLogCollection()
        logTask?.cancel()
        logTask = nil
        startLogPolling(sessionID: sessionID)
    }

    func setLogQuery(search: String, outcomes: [SessionActionOutcome]) {
        let normalized = String(search.trimmingCharacters(in: .whitespacesAndNewlines).prefix(256))
        guard normalized != logSearch || outcomes != logOutcomes else { return }
        clearActionDetail()
        logGeneration &+= 1
        logSearch = normalized
        logOutcomes = outcomes
        resetLogCollection()
        logTask?.cancel()
        logTask = nil
        startLogPolling(sessionID: requestedSessionID)
    }

    func loadMoreLogs() async {
        guard !isLoadingMoreLogs, !isRefreshingLogs, logHasMore,
              let beforeID = nextLogBeforeID, !selectedSessionID.isEmpty else { return }
        let generation = logGeneration
        let query = SessionLogQuery(
            sessionID: selectedSessionID,
            beforeID: beforeID,
            search: logSearch,
            outcomes: logOutcomes
        )
        isLoadingMoreLogs = true
        defer {
            if generation == logGeneration { isLoadingMoreLogs = false }
        }
        do {
            let page = try await client.fetchSessionLog(query)
            guard !Task.isCancelled, generation == logGeneration,
                  page.selectedSessionID == selectedSessionID else { return }
            appendUniqueLogEntries(page.entries)
            logTotalMatches = page.totalMatches
            logHasMore = page.hasMore
            nextLogBeforeID = page.nextBeforeID
            hasLoadedOlderLogPages = true
            logsUnavailable = false
        } catch is CancellationError {
            return
        } catch {
            return
        }
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
        guard !isRefreshingLogs else { return }
        let requested = requestedSessionID
        let generation = logGeneration
        isRefreshingLogs = true
        defer {
            if generation == logGeneration { isRefreshingLogs = false }
        }
        do {
            let snapshot = try await client.fetchSessionLog(SessionLogQuery(
                sessionID: requested,
                search: logSearch,
                outcomes: logOutcomes
            ))
            guard !Task.isCancelled, generation == logGeneration, requested == requestedSessionID else { return }
            sessionLogSnapshot = snapshot
            requestedSessionID = snapshot.selectedSessionID.isEmpty ? nil : snapshot.selectedSessionID
            selectedSessionID = snapshot.selectedSessionID
            applyFirstLogPage(snapshot)
            logsUnavailable = false
        } catch is CancellationError {
            return
        } catch {
            if generation == logGeneration { logsUnavailable = sessionLogSnapshot == nil }
        }
    }

    private func applyFirstLogPage(_ snapshot: SessionLogSnapshotV1) {
        logTotalMatches = snapshot.totalMatches
        if hasLoadedOlderLogPages, snapshot.totalMatches >= sessionEntries.count {
            appendUniqueLogEntries(snapshot.entries)
            return
        }
        sessionEntries = snapshot.entries
        logHasMore = snapshot.hasMore
        nextLogBeforeID = snapshot.nextBeforeID
        hasLoadedOlderLogPages = false
    }

    private func appendUniqueLogEntries(_ entries: [SessionAction]) {
        var byID = Dictionary(uniqueKeysWithValues: sessionEntries.map { ($0.id, $0) })
        for entry in entries { byID[entry.id] = entry }
        sessionEntries = byID.values.sorted { $0.id > $1.id }
    }

    private func resetLogCollection() {
        sessionEntries = []
        logTotalMatches = 0
        logHasMore = false
        nextLogBeforeID = nil
        hasLoadedOlderLogPages = false
        isRefreshingLogs = false
        isLoadingMoreLogs = false
    }
}
