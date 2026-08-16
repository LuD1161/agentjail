import Foundation
@testable import AgentjailApprovalCore

final class StateScriptedReviewClient: ReviewControlling, @unchecked Sendable {
    private let lock = NSLock()
    private var fetchResults: [StateFetchResult]
    private var approveResults: [StateMutationResult]
    private var denyResults: [StateMutationResult]
    private var fetchCount = 0
    private var approveCount = 0
    private var denyCount = 0

    init(fetches: [StateFetchResult], approve: [StateMutationResult] = [.success], deny: [StateMutationResult] = [.success]) {
        fetchResults = fetches
        approveResults = approve
        denyResults = deny
    }

    var fetchCalls: Int { lock.withLock { fetchCount } }
    var approveCalls: Int { lock.withLock { approveCount } }
    var denyCalls: Int { lock.withLock { denyCount } }

    func fetchSnapshot() async throws -> ReviewSnapshotV1 {
        let result = lock.withLock { () -> StateFetchResult in
            fetchCount += 1
            return fetchResults.isEmpty ? .failure(.daemonUnavailable) : fetchResults.removeFirst()
        }
        switch result {
        case let .success(snapshot): return snapshot
        case let .failure(error): throw error
        }
    }

    func approve(_ reviewID: ReviewID) async throws {
        try throwIfFailed(nextApproveResult())
    }

    func deny(_ reviewID: ReviewID) async throws {
        try throwIfFailed(nextDenyResult())
    }

    private func nextApproveResult() -> StateMutationResult {
        lock.withLock {
            approveCount += 1
            return approveResults.isEmpty ? .failure(.daemonUnavailable) : approveResults.removeFirst()
        }
    }

    private func nextDenyResult() -> StateMutationResult {
        lock.withLock {
            denyCount += 1
            return denyResults.isEmpty ? .failure(.daemonUnavailable) : denyResults.removeFirst()
        }
    }

    private func throwIfFailed(_ result: StateMutationResult) throws {
        if case let .failure(error) = result { throw error }
    }
}
