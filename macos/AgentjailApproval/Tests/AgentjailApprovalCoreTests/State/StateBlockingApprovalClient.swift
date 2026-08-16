import Foundation
@testable import AgentjailApprovalCore

final class StateBlockingApprovalClient: ReviewControlling, @unchecked Sendable {
    private let lock = NSLock()
    private var fetchResults: [ReviewSnapshotV1]
    private var approvalContinuation: CheckedContinuation<Void, Error>?
    private var count = 0

    init(fetches: [ReviewSnapshotV1]) { fetchResults = fetches }
    var approveCalls: Int { lock.withLock { count } }

    func fetchSnapshot() async throws -> ReviewSnapshotV1 {
        lock.withLock { fetchResults.removeFirst() }
    }

    func approve(_ reviewID: ReviewID) async throws {
        lock.withLock { count += 1 }
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
}
