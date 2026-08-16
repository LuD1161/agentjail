import Foundation
@testable import AgentjailApprovalCore

final class StateDeferredFetchClient: ReviewControlling, @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<ReviewSnapshotV1, Error>?
    private var waiting = false
    private var finished = false

    var isWaiting: Bool {
        lock.lock()
        defer { lock.unlock() }
        return waiting
    }

    var didFinish: Bool {
        lock.lock()
        defer { lock.unlock() }
        return finished
    }

    func fetchSnapshot() async throws -> ReviewSnapshotV1 {
        do {
            let snapshot = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<ReviewSnapshotV1, Error>) in
                lock.lock()
                self.continuation = continuation
                waiting = true
                lock.unlock()
            }
            markFinished()
            return snapshot
        } catch {
            markFinished()
            throw error
        }
    }

    func approve(_ reviewID: ReviewID) async throws {}
    func deny(_ reviewID: ReviewID) async throws {}

    func finish(_ result: StateFetchResult) {
        lock.lock()
        let continuation = self.continuation
        self.continuation = nil
        lock.unlock()
        switch result {
        case let .success(snapshot): continuation?.resume(returning: snapshot)
        case let .failure(error): continuation?.resume(throwing: error)
        }
    }

    private func markFinished() {
        lock.lock()
        finished = true
        lock.unlock()
    }
}
