import Foundation
@testable import AgentjailApprovalCore

final class StateMutationThenRefreshClient: ReviewControlling, @unchecked Sendable {
    private let lock = NSLock()
    private let initial: ReviewSnapshotV1
    private let refreshed: ReviewSnapshotV1
    private let concurrent: ReviewSnapshotV1?
    private var fetchCount = 0
    private var approvalCount = 0
    private var approvalContinuation: CheckedContinuation<Void, Error>?
    private var refreshContinuation: CheckedContinuation<ReviewSnapshotV1, Error>?
    private var refreshWaiting = false

    init(initial: ReviewSnapshotV1, refreshed: ReviewSnapshotV1, concurrent: ReviewSnapshotV1? = nil) {
        self.initial = initial
        self.refreshed = refreshed
        self.concurrent = concurrent
    }

    var approveCalls: Int { lock.withLock { approvalCount } }
    var refreshStarted: Bool { lock.withLock { refreshWaiting } }

    func fetchSnapshot() async throws -> ReviewSnapshotV1 {
        let call = lock.withLock { () -> Int in
            fetchCount += 1
            return fetchCount
        }
        if call == 1 { return initial }
        if call > 2, let concurrent { return concurrent }
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<ReviewSnapshotV1, Error>) in
            lock.withLock {
                refreshContinuation = continuation
                refreshWaiting = true
            }
        }
    }

    func approve(_ reviewID: ReviewID) async throws {
        lock.withLock { approvalCount += 1 }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            lock.withLock { approvalContinuation = continuation }
        }
    }

    func deny(_ reviewID: ReviewID) async throws {}

    func finishApproval() {
        let continuation = lock.withLock { () -> CheckedContinuation<Void, Error>? in
            defer { approvalContinuation = nil }
            return approvalContinuation
        }
        continuation?.resume()
    }

    func finishRefresh() {
        let continuation = lock.withLock { () -> CheckedContinuation<ReviewSnapshotV1, Error>? in
            defer { refreshContinuation = nil }
            return refreshContinuation
        }
        continuation?.resume(returning: refreshed)
    }
}
