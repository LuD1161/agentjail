import Combine
import Foundation

@MainActor
public final class ApprovalStore: ObservableObject {
    @Published public private(set) var state: ApprovalStoreState = .starting
    @Published public private(set) var actionStates: [ReviewID: ReviewActionState] = [:]

    private let client: any ReviewControlling
    private let clock: any ApprovalClock
    private let sleeper: any ApprovalSleeping
    private var pollTask: Task<Void, Never>?
    private var activationTask: Task<Void, Never>?
    private var pollGeneration = 0
    private var stablePollGeneration: Int?
    private var pendingPollDelay: Int?
    private var pollingDesired = false
    private var refreshGeneration = 0
    private var lifecycleGeneration = 0

    public init(
        client: any ReviewControlling,
        clock: any ApprovalClock = SystemApprovalClock(),
        sleeper: any ApprovalSleeping = TaskApprovalSleeper()
    ) {
        self.client = client
        self.clock = clock
        self.sleeper = sleeper
    }

    deinit {
        pollTask?.cancel()
        activationTask?.cancel()
    }

    public func start() {
        pollingDesired = true
        beginPolling(initialDelay: nil)
    }

    private func beginPolling(initialDelay: Int?) {
        guard pollTask == nil else { return }
        pollGeneration += 1
        let generation = pollGeneration
        let sleeper = sleeper
        pollTask = Task { [weak self, sleeper] in
            if let initialDelay {
                do {
                    try await sleeper.sleep(seconds: initialDelay)
                } catch {
                    self?.finishPoll(generation: generation)
                    return
                }
            }
            var failureDelay = 2
            while !Task.isCancelled {
                guard let result = await self?.pollRefresh(generation: generation) else { break }
                if Task.isCancelled { break }

                let delay: Int
                switch result {
                case .authoritative, .superseded:
                    failureDelay = 2
                    delay = 2
                case .disconnected:
                    delay = failureDelay
                    failureDelay = min(failureDelay * 2, 30)
                case .unauthorized, .unsupportedProtocol, .cancelled:
                    self?.finishPoll(generation: generation)
                    return
                }

                do {
                    try await sleeper.sleep(seconds: delay)
                } catch {
                    break
                }
            }
            self?.finishPoll(generation: generation)
        }
    }

    public func stop() {
        lifecycleGeneration += 1
        refreshGeneration += 1
        pollGeneration += 1
        stablePollGeneration = nil
        pendingPollDelay = nil
        pollingDesired = false
        pollTask?.cancel()
        pollTask = nil
        activationTask?.cancel()
        activationTask = nil
    }

    public func applicationDidBecomeActive() {
        activationTask?.cancel()
        activationTask = Task { [weak self] in
            let result = await self?.refreshNow()
            guard !Task.isCancelled else { return }
            self?.finishActivationRefresh()
            self?.resumePollingAfterRefresh(result)
        }
    }

    @discardableResult
    public func refreshNow() async -> ApprovalRefreshResult {
        refreshGeneration += 1
        let generation = refreshGeneration
        let lifecycle = lifecycleGeneration
        guard isCurrentRefresh(generation, lifecycle: lifecycle) else { return .superseded }
        if state.authoritativeSnapshot == nil, state.staleSnapshot == nil {
            state = .connecting
        }

        do {
            let snapshot = try await client.fetchSnapshot()
            guard isCurrentRefresh(generation, lifecycle: lifecycle) else { return refreshInvalidationResult() }
            let authoritative = AuthoritativeApprovalSnapshot(snapshot)
            apply(authoritative)
            resumePollingAfterRefresh(.authoritative(authoritative))
            return .authoritative(authoritative)
        } catch is CancellationError {
            return .cancelled
        } catch let error as ApprovalControlError {
            guard isCurrentRefresh(generation, lifecycle: lifecycle) else { return refreshInvalidationResult() }
            let result = apply(error)
            resumePollingAfterRefresh(result)
            return result
        } catch {
            guard isCurrentRefresh(generation, lifecycle: lifecycle) else { return refreshInvalidationResult() }
            let result = apply(.daemonUnavailable)
            resumePollingAfterRefresh(result)
            return result
        }
    }

    @discardableResult
    public func approve(_ reviewID: ReviewID) async -> ApprovalActionResult {
        await perform(.approving, reviewID: reviewID)
    }

    @discardableResult
    public func deny(_ reviewID: ReviewID) async -> ApprovalActionResult {
        await perform(.denying, reviewID: reviewID)
    }

    public func actionState(for reviewID: ReviewID) -> ReviewActionState {
        actionStates[reviewID] ?? .idle
    }

    private func finishActivationRefresh() {
        activationTask = nil
    }

    private func finishPoll(generation: Int) {
        guard pollGeneration == generation else { return }
        pollTask = nil
        stablePollGeneration = nil
        if let pendingPollDelay {
            self.pendingPollDelay = nil
            beginPolling(initialDelay: pendingPollDelay)
        }
    }

    private func pollRefresh(generation: Int) async -> ApprovalRefreshResult? {
        guard pollGeneration == generation else { return nil }
        let result = await refreshNow()
        guard pollGeneration == generation, !Task.isCancelled else { return nil }
        switch result {
        case .unauthorized, .unsupportedProtocol, .cancelled:
            stablePollGeneration = generation
        case .authoritative, .disconnected, .superseded:
            break
        }
        return result
    }

    private func resumePollingAfterRefresh(_ result: ApprovalRefreshResult?) {
        guard pollingDesired else { return }
        switch result {
        case .authoritative, .disconnected:
            break
        case .unauthorized, .unsupportedProtocol, .cancelled, .superseded, .none:
            return
        }
        guard pollTask != nil else {
            beginPolling(initialDelay: 2)
            return
        }
        guard stablePollGeneration == pollGeneration else { return }
        pendingPollDelay = 2
    }

    private func apply(_ snapshot: AuthoritativeApprovalSnapshot) {
        let currentIDs = Set(snapshot.reviews.map(\.id))
        actionStates = actionStates.filter { currentIDs.contains($0.key) }
        state = .ready(snapshot)
    }

    private func apply(_ error: ApprovalControlError) -> ApprovalRefreshResult {
        let stale = state.staleSnapshot
        switch error {
        case .unauthorized:
            state = .unauthorized(stale)
            return .unauthorized
        case .protocolMismatch:
            state = .unsupportedProtocol(stale)
            return .unsupportedProtocol
        default:
            let failure = ApprovalConnectionFailure(error)
            state = .disconnected(stale, failure)
            return .disconnected(failure)
        }
    }

    private func perform(_ inFlight: ReviewActionState, reviewID: ReviewID) async -> ApprovalActionResult {
        guard let review = actionableReview(reviewID, action: inFlight) else { return .notActionable }
        actionStates[review.id] = inFlight

        do {
            switch inFlight {
            case .approving:
                try await client.approve(review.id)
            case .denying:
                try await client.deny(review.id)
            case .idle, .failed:
                return .notActionable
            }
            _ = await refreshNow()
            if actionState(for: review.id) == inFlight {
                actionStates[review.id] = .idle
            }
            return .completed
        } catch is CancellationError {
            actionStates[review.id] = .failed(.unavailable)
            return .cancelled
        } catch let error as ApprovalControlError {
            let failure = ApprovalActionFailure(error)
            actionStates[review.id] = .failed(failure)
            _ = await refreshNow()
            return .failed(failure)
        } catch {
            actionStates[review.id] = .failed(.unavailable)
            _ = await refreshNow()
            return .failed(.unavailable)
        }
    }

    private func actionableReview(_ reviewID: ReviewID, action: ReviewActionState) -> Review? {
        guard case let .ready(snapshot) = state,
              let review = snapshot.reviews.first(where: { $0.id == reviewID }),
              review.expiresAt > clock.now()
        else {
            return nil
        }

        switch actionState(for: reviewID) {
        case .approving, .denying:
            return nil
        case .idle, .failed:
            break
        }

        switch action {
        case .approving:
            guard review.contextState == .verified, review.canApprove else { return nil }
        case .denying:
            guard review.canDeny else { return nil }
        case .idle, .failed:
            return nil
        }
        return review
    }

    private func isCurrentRefresh(_ refresh: Int, lifecycle: Int) -> Bool {
        !Task.isCancelled && refresh == refreshGeneration && lifecycle == lifecycleGeneration
    }

    private func refreshInvalidationResult() -> ApprovalRefreshResult {
        Task.isCancelled ? .cancelled : .superseded
    }
}

private extension ApprovalConnectionFailure {
    init(_ error: ApprovalControlError) {
        switch error {
        case .tokenMissing:
            self = .tokenMissing
        case .tokenUnreadable:
            self = .tokenUnreadable
        case .daemonUnavailable:
            self = .unavailable
        case .timeout:
            self = .timeout
        case .protocolMismatch:
            self = .malformedReply
        case .malformedReply:
            self = .malformedReply
        case .oversizedReply:
            self = .oversizedReply
        case .invalidSocketPath:
            self = .invalidSocketPath
        case .serverRefused:
            self = .serverRefused
        case .unauthorized:
            self = .unavailable
        }
    }
}

private extension ApprovalActionFailure {
    init(_ error: ApprovalControlError) {
        switch error {
        case .serverRefused:
            self = .refused
        case .daemonUnavailable:
            self = .unavailable
        case .timeout:
            self = .timeout
        case .unauthorized:
            self = .unauthorized
        case .protocolMismatch:
            self = .unsupportedProtocol
        case .malformedReply:
            self = .malformedReply
        case .oversizedReply:
            self = .oversizedReply
        case .tokenMissing, .tokenUnreadable:
            self = .tokenUnavailable
        case .invalidSocketPath:
            self = .invalidSocketPath
        }
    }
}
