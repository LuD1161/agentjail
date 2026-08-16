import ServiceManagement

enum ApprovalLoginItemStatus: Equatable {
    case enabled
    case notRegistered
    case requiresApproval
    case notFound
    case unknown
}

@MainActor
protocol ApprovalLoginItemServicing: AnyObject {
    func status() -> ApprovalLoginItemStatus
    func register() throws
    func unregister() throws
    func openLoginItemsSettings()
}

@MainActor
final class SMAppServiceLoginItemService: ApprovalLoginItemServicing {
    func status() -> ApprovalLoginItemStatus {
        switch SMAppService.mainApp.status {
        case .enabled:
            .enabled
        case .notRegistered:
            .notRegistered
        case .requiresApproval:
            .requiresApproval
        case .notFound:
            .notFound
        @unknown default:
            .unknown
        }
    }

    func register() throws {
        try SMAppService.mainApp.register()
    }

    func unregister() throws {
        try SMAppService.mainApp.unregister()
    }

    func openLoginItemsSettings() {
        SMAppService.openSystemSettingsLoginItems()
    }
}
