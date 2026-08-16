import Foundation
@testable import AgentjailApprovalCore

final class StateConcurrentApprovalClient: ReviewControlling, @unchecked Sendable {
    private let lock = NSLock()
    private let snapshot: ReviewSnapshotV1
    private var continuations: [ReviewID: CheckedContinuation<Void, Error>] = [:]
    private var count = 0

    init(snapshot: ReviewSnapshotV1) { self.snapshot = snapshot }
    var approvalCount: Int { lock.withLock { count } }

    func fetchSnapshot() async throws -> ReviewSnapshotV1 { snapshot }

    func approve(_ reviewID: ReviewID) async throws {
        lock.withLock { count += 1 }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            lock.withLock { continuations[reviewID] = continuation }
        }
    }

    func deny(_ reviewID: ReviewID) async throws {}

    func finishApproval(for reviewID: ReviewID) {
        let continuation = lock.withLock { () -> CheckedContinuation<Void, Error>? in
            continuations.removeValue(forKey: reviewID)
        }
        continuation?.resume()
    }
}
