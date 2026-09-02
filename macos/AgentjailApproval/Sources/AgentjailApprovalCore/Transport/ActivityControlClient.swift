import Foundation

public struct ActivityControlClient: ActivityControlling {
    private let tokenLoader: any ControlTokenLoading
    private let transport: any ControlFraming

    public init(
        tokenLoader: any ControlTokenLoading = FileControlTokenLoader(),
        transport: any ControlFraming = UnixControlTransport(timeout: 4)
    ) {
        self.tokenLoader = tokenLoader
        self.transport = transport
    }

    public func fetchNetwork() async throws -> NetworkSnapshotV1 {
        let token = try await loadToken()
        let request = ActivityRequest(type: "network_snapshot", token: token)
        return try await roundTrip(request, token: token).networkSnapshot()
    }

    public func fetchSessionLog(_ query: SessionLogQuery) async throws -> SessionLogSnapshotV1 {
        let token = try await loadToken()
        let request = ActivityRequest(
            type: "session_log_snapshot",
            token: token,
            sessionID: query.sessionID,
            beforeID: query.beforeID,
            search: query.search.isEmpty ? nil : query.search,
            actions: query.outcomes.isEmpty ? nil : query.outcomes.map(\.rawValue)
        )
        return try await roundTrip(request, token: token).sessionLogSnapshot()
    }

    public func fetchSessionActionDetail(sessionID: String, actionID: Int64) async throws -> SessionActionDetailV1 {
        let token = try await loadToken()
        let request = ActivityRequest(type: "session_action_detail", token: token, sessionID: sessionID, actionID: actionID)
        return try await roundTrip(request, token: token).sessionActionDetail()
    }

    private func loadToken() async throws -> String {
        try await Task.detached(priority: .userInitiated) {
            do { return try tokenLoader.loadToken() }
            catch let error as ApprovalControlError { throw error }
            catch { throw ApprovalControlError.tokenUnreadable }
        }.value
    }

    private func roundTrip(
        _ request: ActivityRequest,
        token: String
    ) async throws -> ActivityResponse {
        let frame: Data
        do { frame = try request.frame() } catch { throw ApprovalControlError.malformedReply }
        let reply: Data
        do { reply = try await transport.roundTrip(frame) }
        catch let error as ApprovalControlError { throw error }
        catch is CancellationError { throw CancellationError() }
        catch { throw ApprovalControlError.daemonUnavailable }
        return try ActivityResponse.decode(frame: reply, redacting: token)
    }
}

private struct ActivityRequest: Encodable, Sendable {
    let type: String
    let token: String
    let protocolVersion: UInt32 = 1
    let sessionID: String?
    let actionID: Int64?
    let beforeID: Int64?
    let search: String?
    let actions: [String]?

    init(
        type: String,
        token: String,
        sessionID: String? = nil,
        actionID: Int64? = nil,
        beforeID: Int64? = nil,
        search: String? = nil,
        actions: [String]? = nil
    ) {
        self.type = type
        self.token = token
        self.sessionID = sessionID
        self.actionID = actionID
        self.beforeID = beforeID
        self.search = search
        self.actions = actions
    }

    enum CodingKeys: String, CodingKey {
        case type, token = "ctl_token", protocolVersion = "protocol_version"
        case sessionID = "session_id", actionID = "action_id"
        case beforeID = "before_id", search, actions
    }

    func frame() throws -> Data {
        let payload = try JSONEncoder().encode(self)
        guard !payload.contains(10), payload.count + 1 <= UnixControlTransport.maximumFrameBytes else {
            throw ApprovalControlError.malformedReply
        }
        return payload + Data([10])
    }
}

private struct ActivityResponse: Decodable, Sendable {
    let ok: Bool
    let error: String?
    let network: NetworkSnapshotV1?
    let sessionLog: SessionLogSnapshotV1?
    let actionDetail: SessionActionDetailV1?

    enum CodingKeys: String, CodingKey {
        case ok, error, network = "network_snapshot", sessionLog = "session_log_snapshot"
        case actionDetail = "session_action_detail"
    }

    static func decode(
        frame: Data,
        redacting token: String
    ) throws -> Self {
        guard frame.last == 10, frame.count <= UnixControlTransport.maximumFrameBytes else {
            throw ApprovalControlError.oversizedReply
        }
        do {
            let response = try JSONDecoder().decode(Self.self, from: frame.dropLast())
            guard response.ok else {
                let message = String((response.error ?? "request refused").replacingOccurrences(of: token, with: "[redacted]").prefix(512))
                if message == "unauthorized" { throw ApprovalControlError.unauthorized }
                throw ApprovalControlError.serverRefused(message)
            }
            return response
        } catch let error as ApprovalControlError {
            throw error
        } catch let error as ActivityModelError {
            if error == .unsupportedProtocolVersion { throw ApprovalControlError.protocolMismatch }
            throw ApprovalControlError.malformedReply
        } catch {
            throw ApprovalControlError.malformedReply
        }
    }

    func networkSnapshot() throws -> NetworkSnapshotV1 {
        guard let network else { throw ApprovalControlError.protocolMismatch }
        return network
    }

    func sessionLogSnapshot() throws -> SessionLogSnapshotV1 {
        guard let sessionLog else { throw ApprovalControlError.protocolMismatch }
        return sessionLog
    }

    func sessionActionDetail() throws -> SessionActionDetailV1 {
        guard let actionDetail else { throw ApprovalControlError.protocolMismatch }
        return actionDetail
    }
}
