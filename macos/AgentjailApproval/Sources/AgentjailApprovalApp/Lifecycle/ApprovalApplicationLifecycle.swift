import AppKit
@preconcurrency import UserNotifications

@MainActor
protocol ApprovalApplicationControlling: AnyObject {
    func activate()
    func terminate()
}

@MainActor
final class NSApplicationController: ApprovalApplicationControlling {
    func activate() {
        NSApplication.shared.activate(ignoringOtherApps: true)
    }

    func terminate() {
        NSApplication.shared.terminate(nil)
    }
}

@MainActor
protocol ApprovalNotificationDelegateInstalling: AnyObject {
    func install(_ delegate: ApprovalNotificationDelegate)
}

@MainActor
final class UserNotificationCenterDelegateInstaller: ApprovalNotificationDelegateInstalling {
    func install(_ delegate: ApprovalNotificationDelegate) {
        UNUserNotificationCenter.current().delegate = delegate
    }
}
