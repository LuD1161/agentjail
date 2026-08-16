import XCTest
@testable import AgentjailApprovalCore

enum StateFetchResult {
    case success(ReviewSnapshotV1)
    case failure(ApprovalControlError)
}

enum StateMutationResult {
    case success
    case failure(ApprovalControlError)
}

func stateReview(id: String, context: ReviewContextState, canApprove: Bool, expiresAt: Int64 = 2_000, canDeny: Bool = true) throws -> Review {
    try Review(id: ReviewID(rawValue: id), kind: .projectHost, host: "\(id).example.test", projectPath: context == .verified ? "/projects/\(id)" : nil, reason: "reason", reasonTruncated: false, contextState: context, createdAt: UnixMilliseconds(rawValue: 1), expiresAt: UnixMilliseconds(rawValue: expiresAt), approvalScope: .futureProjectSessions, canApprove: canApprove, canDeny: canDeny)
}

func stateSnapshot(reviews: [Review], totalPending: Int? = nil) throws -> ReviewSnapshotV1 {
    let pending = totalPending ?? reviews.count
    return try ReviewSnapshotV1(version: ReviewSnapshotV1.protocolVersion, generatedAt: UnixMilliseconds(rawValue: 100), totalPending: pending, truncated: pending > reviews.count, reviews: reviews)
}

func stateWaitFor(_ condition: @escaping @Sendable () -> Bool) async {
    for _ in 0..<1_000 {
        if condition() { return }
        await Task.yield()
    }
    XCTFail("condition was not reached")
}
