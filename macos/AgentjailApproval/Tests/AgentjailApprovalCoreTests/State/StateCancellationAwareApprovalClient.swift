import Foundation
@testable import AgentjailApprovalCore

final class StateCancellationAwareApprovalClient: ReviewControlling, @unchecked Sendable {
    private let lock = NSLock()
    private let snapshot: ReviewSnapshotV1
    private var started = false
    private var count = 0

    init(snapshot: ReviewSnapshotV1) { self.snapshot = snapshot }
    var approveStarted: Bool { lock.withLock { started } }
    var approveCalls: Int { lock.withLock { count } }

    func fetchSnapshot() async throws -> ReviewSnapshotV1 { snapshot }

    func approve(_ reviewID: ReviewID) async throws {
        lock.withLock {
            started = true
            count += 1
        }
        while !Task.isCancelled { await Task.yield() }
        throw CancellationError()
    }

    func deny(_ reviewID: ReviewID) async throws {}
}
