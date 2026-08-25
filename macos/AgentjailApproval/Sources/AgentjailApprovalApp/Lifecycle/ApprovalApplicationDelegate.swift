import AppKit

@MainActor
final class ApprovalApplicationDelegate: NSObject, NSApplicationDelegate {
    let composition = ApprovalAppComposition()

    func applicationWillFinishLaunching(_ notification: Notification) {
        composition.prepareForLaunch()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        composition.start()
        composition.presentSetupIfNeeded()
    }

    func applicationDidBecomeActive(_ notification: Notification) {
        composition.applicationDidBecomeActive()
    }

    func applicationWillTerminate(_ notification: Notification) {
        composition.stop()
    }
}
