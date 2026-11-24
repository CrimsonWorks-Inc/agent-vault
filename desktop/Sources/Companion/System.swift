import AppKit
import CompanionCore
import ServiceManagement
import UserNotifications

/// The user's choices, in the companion's own defaults.
enum Preferences {
    static func load() -> Prefs {
        let d = UserDefaults.standard
        return Prefs(
            notifications: d.object(forKey: "notifications") as? Bool ?? true,
            autostart: false,
            welcomed: d.bool(forKey: "welcomed"),
            terminal: d.bool(forKey: "terminal")
        )
    }

    static func save(_ prefs: Prefs) {
        let d = UserDefaults.standard
        d.set(prefs.notifications, forKey: "notifications")
        d.set(prefs.welcomed, forKey: "welcomed")
        d.set(prefs.terminal, forKey: "terminal")
    }
}

/// Start at login, as macOS's own login item for this app.
enum LoginItem {
    static var isEnabled: Bool {
        SMAppService.mainApp.status == .enabled
    }

    static func set(_ on: Bool) throws {
        if on {
            try SMAppService.mainApp.register()
        } else {
            try SMAppService.mainApp.unregister()
        }
    }
}

/// Opening Terminal on a fixed command, for the steps where the human has to
/// type a password or passphrase. The command reaches Terminal as an
/// AppleScript string, run in this process: never through a file another
/// process could rewrite first, and never in another process's arguments.
enum TerminalWindow {
    /// Why Terminal did not open, or `nil` when it did.
    static func open(_ command: String) -> String? {
        guard let script = NSAppleScript(source: terminalAppleScript(command)) else {
            return "Terminal did not open. Try again in a moment."
        }
        var error: NSDictionary?
        script.executeAndReturnError(&error)
        guard let error else { return nil }
        if (error[NSAppleScript.errorNumber] as? Int) == -1743 {
            return "macOS blocked the companion from opening Terminal. Allow it under System Settings → Privacy & Security → Automation, then try again."
        }
        return "Terminal did not open. Try again in a moment."
    }
}

/// Notifications, when the app runs as a bundle (a bare `swift run` binary
/// has no identity to post them under).
enum Notifier {
    /// Called when the user clicks a notification.
    static var onOpen: (() -> Void)?
    private static let delegate = Delegate()

    private static var available: Bool {
        Bundle.main.bundleIdentifier != nil && Bundle.main.bundleURL.pathExtension == "app"
    }

    static func prepare() {
        guard available else { return }
        let center = UNUserNotificationCenter.current()
        center.delegate = delegate
        center.requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    static func post(_ body: String) {
        guard available else { return }
        let content = UNMutableNotificationContent()
        content.title = "agent-vault"
        content.body = body
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }

    private final class Delegate: NSObject, UNUserNotificationCenterDelegate {
        func userNotificationCenter(
            _ center: UNUserNotificationCenter, willPresent notification: UNNotification,
            withCompletionHandler done: @escaping (UNNotificationPresentationOptions) -> Void
        ) {
            done([.banner, .list])
        }

        func userNotificationCenter(
            _ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
            withCompletionHandler done: @escaping () -> Void
        ) {
            DispatchQueue.main.async { Notifier.onOpen?() }
            done()
        }
    }
}
