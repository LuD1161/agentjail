import Foundation
@testable import AgentjailApprovalCore

struct StateFixedClock: ApprovalClock {
    let value: Int64
    init(now: Int64) { value = now }
    func now() -> UnixMilliseconds { UnixMilliseconds(rawValue: value) }
}
struct StateThrowingSleeper: ApprovalSleeping {
    func sleep(seconds: Int) async throws { throw CancellationError() }
}

final class StateRecordingSleeper: ApprovalSleeping, @unchecked Sendable {
    private let lock = NSLock()
    private let stopAfter: Int
    private var recorded: [Int] = []

    init(stopAfter: Int) { self.stopAfter = stopAfter }
    var durations: [Int] { lock.withLock { recorded } }

    func sleep(seconds: Int) async throws {
        let shouldStop = lock.withLock {
            recorded.append(seconds)
            return recorded.count >= stopAfter
        }
        if shouldStop { throw CancellationError() }
    }
}

final class StateCancellationObservingSleeper: ApprovalSleeping, @unchecked Sendable {
    private let lock = NSLock()
    private var started = false
    private var cancelled = false

    var hasStarted: Bool { lock.withLock { started } }
    var observedCancellation: Bool { lock.withLock { cancelled } }

    func sleep(seconds: Int) async throws {
        lock.withLock { started = true }
        while !Task.isCancelled { await Task.yield() }
        lock.withLock { cancelled = true }
        throw CancellationError()
    }
}
