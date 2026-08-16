import Foundation
@testable import AgentjailApprovalCore

final class StateOrderedReviewClient: ReviewControlling, @unchecked Sendable {
    private let lock = NSLock()
    private let first: ReviewSnapshotV1
    private let second: ReviewSnapshotV1
    private var firstCall = true
    private var continuation: CheckedContinuation<ReviewSnapshotV1, Error>?
    private var started = false

    init(first: ReviewSnapshotV1, second: ReviewSnapshotV1) {
        self.first = first
        self.second = second
    }

    var firstStarted: Bool { lock.withLock { started } }

    func fetchSnapshot() async throws -> ReviewSnapshotV1 {
        let waits = lock.withLock { () -> Bool in
            guard firstCall else { return false }
            firstCall = false
            started = true
            return true
        }
        if !waits { return second }
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<ReviewSnapshotV1, Error>) in
            lock.withLock { self.continuation = continuation }
        }
    }

    func approve(_ reviewID: ReviewID) async throws {}
    func deny(_ reviewID: ReviewID) async throws {}

    func finishFirst() {
        let continuation = lock.withLock { () -> CheckedContinuation<ReviewSnapshotV1, Error>? in
            defer { self.continuation = nil }
            return self.continuation
        }
        continuation?.resume(returning: first)
    }
}
