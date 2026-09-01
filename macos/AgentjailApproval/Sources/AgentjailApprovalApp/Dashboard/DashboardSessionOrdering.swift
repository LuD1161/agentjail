import AgentjailApprovalCore

enum DashboardSessionOrdering {
    static func liveFirst(_ sessions: [DashboardSession]) -> [DashboardSession] {
        sessions.sorted { left, right in
            if left.active != right.active {
                return left.active
            }

            let leftRecency = left.active ? left.startedAtUnixMs : (left.endedAtUnixMs ?? left.startedAtUnixMs)
            let rightRecency = right.active ? right.startedAtUnixMs : (right.endedAtUnixMs ?? right.startedAtUnixMs)
            if leftRecency != rightRecency {
                return leftRecency > rightRecency
            }
            return left.sessionID < right.sessionID
        }
    }
}
