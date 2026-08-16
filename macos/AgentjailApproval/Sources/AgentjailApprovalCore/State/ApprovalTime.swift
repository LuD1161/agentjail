import Foundation

public protocol ApprovalClock: Sendable {
    func now() -> UnixMilliseconds
}

public struct SystemApprovalClock: ApprovalClock {
    public init() {}

    public func now() -> UnixMilliseconds {
        UnixMilliseconds(rawValue: Int64(Date().timeIntervalSince1970 * 1_000))
    }
}

public protocol ApprovalSleeping: Sendable {
    func sleep(seconds: Int) async throws
}

public struct TaskApprovalSleeper: ApprovalSleeping {
    public init() {}

    public func sleep(seconds: Int) async throws {
        try await Task.sleep(nanoseconds: UInt64(seconds) * 1_000_000_000)
    }
}
