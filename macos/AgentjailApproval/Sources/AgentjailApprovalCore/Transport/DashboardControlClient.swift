import Foundation

public struct DashboardControlClient: DashboardControlling {
    private let tokenLoader: any ControlTokenLoading
    private let transport: any ControlFraming

    public init(tokenLoader: any ControlTokenLoading = FileControlTokenLoader(), transport: any ControlFraming = UnixControlTransport(timeout: 10)) {
        self.tokenLoader = tokenLoader
        self.transport = transport
    }

    public func fetchDashboard() async throws -> DashboardSnapshotV1 {
        let token = try await Task.detached(priority: .userInitiated) {
            do { return try tokenLoader.loadToken() }
            catch let error as ApprovalControlError { throw error }
            catch { throw ApprovalControlError.tokenUnreadable }
        }.value
        let request = DashboardRequest(token: token)
        let frame: Data
        do { frame = try request.frame() } catch { throw ApprovalControlError.malformedReply }
        let reply: Data
        do { reply = try await transport.roundTrip(frame) }
        catch let error as ApprovalControlError { throw error }
        catch is CancellationError { throw CancellationError() }
        catch { throw ApprovalControlError.daemonUnavailable }
        return try DashboardResponse.decode(frame: reply, redacting: token)
    }
}

private struct DashboardRequest: Encodable, Sendable {
    let type = "dashboard_snapshot"
    let token: String
    let protocolVersion = DashboardSnapshotV1.protocolVersion
    enum CodingKeys: String, CodingKey { case type; case token = "ctl_token"; case protocolVersion = "protocol_version" }
    func frame() throws -> Data {
        let payload = try JSONEncoder().encode(self)
        guard !payload.contains(10), payload.count + 1 <= UnixControlTransport.maximumFrameBytes else { throw ApprovalControlError.malformedReply }
        return payload + Data([10])
    }
}

private struct DashboardResponse: Decodable, Sendable {
    let ok: Bool
    let error: String?
    let dashboard: DashboardSnapshotV1?
    enum CodingKeys: String, CodingKey { case ok, error; case dashboard = "dashboard_snapshot" }

    static func decode(frame: Data, redacting token: String) throws -> DashboardSnapshotV1 {
        guard frame.last == 10, frame.count <= UnixControlTransport.maximumFrameBytes else { throw ApprovalControlError.oversizedReply }
        do {
            let response = try JSONDecoder().decode(Self.self, from: frame.dropLast())
            guard response.ok else {
                let message = String((response.error ?? "request refused").replacingOccurrences(of: token, with: "[redacted]").prefix(512))
                if message == "unauthorized" { throw ApprovalControlError.unauthorized }
                throw ApprovalControlError.serverRefused(message)
            }
            guard let dashboard = response.dashboard else { throw ApprovalControlError.protocolMismatch }
            return dashboard
        } catch let error as ApprovalControlError { throw error }
        catch let error as DashboardModelError {
            if error == .unsupportedProtocolVersion { throw ApprovalControlError.protocolMismatch }
            throw ApprovalControlError.malformedReply
        } catch { throw ApprovalControlError.malformedReply }
    }
}
