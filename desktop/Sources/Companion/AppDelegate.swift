import AppKit
import CompanionCore

final class AppDelegate: NSObject, NSApplicationDelegate {
    let companion = Companion()
    private lazy var island = Island(companion: companion)
    private lazy var statusMenu = StatusMenu(companion: companion)
    private var signals: [DispatchSourceSignal] = []

    func applicationDidFinishLaunching(_ notification: Notification) {
        companion.onNotice = { [weak self] notice in
            if case .waiting(let n) = notice {
                self?.island.peek(n == 1 ? "Agent waiting" : "\(n) waiting")
            }
        }
        companion.beforeDialog = { [weak self] in self?.island.collapse(force: true) }
        companion.afterAction = { [weak self] in self?.island.collapse(force: true) }
        Notifier.onOpen = { [weak self] in self?.island.expand(pinned: true) }

        place()
        NotificationCenter.default.addObserver(
            forName: NSApplication.didChangeScreenParametersNotification, object: nil, queue: .main
        ) { [weak self] _ in self?.place() }
        trapSignals()
        companion.start()
    }

    func applicationWillTerminate(_ notification: Notification) {
        companion.shutdown()
    }

    /// On a screen with a notch, the island; otherwise the menu bar icon.
    /// Checked again whenever displays change (a lid closed on a dock, an
    /// external display unplugged).
    private func place() {
        if let screen = Placing.islandScreen() {
            statusMenu.hide()
            island.show(on: screen)
            companion.placement = .island
        } else {
            island.hide()
            statusMenu.show()
            companion.placement = .menuBar
        }
    }

    /// A terminate signal (logout, `kill`) would otherwise leave the
    /// companion's `watch` and `ui` processes running on their own.
    private func trapSignals() {
        for sig in [SIGTERM, SIGINT, SIGHUP] {
            signal(sig, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: sig, queue: .main)
            source.setEventHandler { NSApp.terminate(nil) }
            source.resume()
            signals.append(source)
        }
    }
}

enum Placing {
    /// The defaults key a developer can set to try the other placement:
    /// `defaults write com.iolitelabs.agentvault.companion placement menu-bar`
    /// (or `island`, to put the island on a screen without a notch).
    static let override = "placement"

    static func notchScreen() -> NSScreen? {
        NSScreen.screens.first { screen in
            screen.safeAreaInsets.top > 0 && screen.auxiliaryTopLeftArea != nil && screen.auxiliaryTopRightArea != nil
        }
    }

    static func islandScreen() -> NSScreen? {
        switch UserDefaults.standard.string(forKey: override) {
        case "menu-bar": return nil
        case "island": return notchScreen() ?? NSScreen.main
        default: return notchScreen()
        }
    }
}
