import AppKit
import Combine
import CompanionCore
import SwiftUI

/// What the island's view draws. Set by `Island`, which owns the window.
final class IslandModel: ObservableObject {
    @Published var expanded = false
    /// The notch, or on a screen without one, a pill of the menu bar's height.
    @Published var notch = CGSize(width: 180, height: 32)
    /// Width of each ear beside the notch when closed: the vault's mark on the
    /// left, what needs the user (if anything) on the right.
    @Published var ear: CGFloat = Island.ear
    /// Whether the vault answered, for the quiet "all is well" dot.
    @Published var reachable = false
    @Published var badge: Badge?
    /// A few words shown in the right ear for a moment, when something arrives.
    @Published var peek: String?
    /// The natural height of the open island's list, as measured by the view.
    @Published var contentHeight: CGFloat = 320
    @Published var expandedSize = CGSize(width: Island.width, height: 360)
    /// The screens opened from home, the last one showing. Empty is home.
    @Published var path: [Screen] = []

    enum Screen: Equatable {
        case home
        case request(String)
        case session(String)
        case key(String)
        case start
        case template(String)
        case addKey
        case replaceKey(String)
        case settings
        case confirm(Action)

        var title: String {
            switch self {
            case .home: return "agent-vault"
            case .request: return "Waiting for you"
            case .session: return "Session"
            case .key: return "Key"
            case .start: return "Start a session"
            case .template: return "Start a session"
            case .addKey: return "Add a key"
            case .replaceKey: return "Replace a key's value"
            case .settings: return "Settings"
            case .confirm: return "Are you sure?"
            }
        }
    }

    var screen: Screen { path.last ?? .home }

    var collapsedSize: CGSize {
        CGSize(width: notch.width + 2 * ear, height: notch.height)
    }
}

/// A borderless panel that sits over the notch, above the menu bar, on every
/// Space, and never takes focus from the app the user is in.
final class IslandPanel: NSPanel {
    init() {
        super.init(
            contentRect: NSRect(x: 0, y: 0, width: 200, height: 32),
            styleMask: [.borderless, .nonactivatingPanel],
            backing: .buffered, defer: false
        )
        isOpaque = false
        backgroundColor = .clear
        hasShadow = false
        isMovable = false
        hidesOnDeactivate = false
        isReleasedWhenClosed = false
        level = NSWindow.Level(rawValue: NSWindow.Level.mainMenu.rawValue + 3)
        collectionBehavior = [.canJoinAllSpaces, .stationary, .fullScreenAuxiliary, .ignoresCycle]
    }

    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }

    /// The island belongs in the menu bar's band, where ordinary windows are
    /// not allowed.
    override func constrainFrameRect(_ frameRect: NSRect, to screen: NSScreen?) -> NSRect {
        frameRect
    }
}

/// Hover in and out of the island, whatever app is in front.
final class TrackingView: NSView {
    var onEnter: (() -> Void)?
    var onExit: (() -> Void)?

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        trackingAreas.forEach(removeTrackingArea)
        addTrackingArea(NSTrackingArea(
            rect: .zero, options: [.mouseEnteredAndExited, .activeAlways, .inVisibleRect], owner: self
        ))
    }

    override func mouseEntered(with event: NSEvent) { onEnter?() }
    override func mouseExited(with event: NSEvent) { onExit?() }
}

/// A click on the island works the first time, without first focusing it.
final class FirstClickHostingView<Content: View>: NSHostingView<Content> {
    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }
}

/// The island around the notch: closed, it is the notch itself, with an ear on
/// each side when there is something to say; open, it drops down into the
/// companion's list.
final class Island {
    static let width: CGFloat = 470
    static let ear: CGFloat = 34

    let model = IslandModel()
    private let companion: Companion
    private lazy var builder = MenuBuilder { [weak self] in self?.companion.perform($0) }
    private var panel: IslandPanel?
    private var screen: NSScreen?
    private var watching: [AnyCancellable] = []
    private var openTimer: Timer?
    private var closeTimer: Timer?
    private var peekTimer: Timer?
    private var menusOpen = 0
    private var pinned = false
    private var clickMonitor: Any?
    private var keyMonitor: Any?

    init(companion: Companion) {
        self.companion = companion
        let center = NotificationCenter.default
        center.addObserver(forName: NSMenu.didBeginTrackingNotification, object: nil, queue: .main) { [weak self] _ in
            self?.menusOpen += 1
            self?.closeTimer?.invalidate()
        }
        center.addObserver(forName: NSMenu.didEndTrackingNotification, object: nil, queue: .main) { [weak self] _ in
            guard let self else { return }
            self.menusOpen = max(0, self.menusOpen - 1)
            if self.menusOpen == 0 && !self.pointerInside { self.scheduleClose() }
        }
    }

    // MARK: Placement

    func show(on screen: NSScreen) {
        self.screen = screen
        let panel = self.panel ?? makePanel()
        self.panel = panel
        model.notch = Island.notchSize(of: screen)
        if watching.isEmpty {
            watching.append(companion.$snapshot.receive(on: RunLoop.main).sink { [weak self] _ in self?.refit() })
            watching.append(companion.$now.receive(on: RunLoop.main).sink { [weak self] _ in self?.refit() })
            watching.append(model.$contentHeight.removeDuplicates().receive(on: RunLoop.main).sink { [weak self] _ in
                self?.fitOpen(animated: true)
            })
            // A result that arrives while the island is closed (after Touch ID,
            // say) is said in the ear for a moment; the full text waits inside.
            watching.append(companion.$banner.compactMap { $0 }.receive(on: RunLoop.main).sink { [weak self] banner in
                guard let self, !self.model.expanded else { return }
                self.peek(banner.failed ? "Didn't work" : "Done")
            })
        }
        refit()
        panel.orderFrontRegardless()
    }

    func hide() {
        watching.removeAll()
        panel?.orderOut(nil)
        screen = nil
    }

    static func notchSize(of screen: NSScreen) -> CGSize {
        if screen.safeAreaInsets.top > 0,
           let left = screen.auxiliaryTopLeftArea, let right = screen.auxiliaryTopRightArea {
            return CGSize(width: screen.frame.width - left.width - right.width, height: screen.safeAreaInsets.top)
        }
        // No notch (only when asked for): a pill as tall as the menu bar.
        let bar = max(24, screen.frame.maxY - screen.visibleFrame.maxY)
        return CGSize(width: 180, height: bar)
    }

    /// The middle of the notch, in screen coordinates.
    private var notchMidX: CGFloat {
        guard let screen else { return 0 }
        if let left = screen.auxiliaryTopLeftArea, screen.safeAreaInsets.top > 0 {
            return screen.frame.minX + left.width + model.notch.width / 2
        }
        return screen.frame.midX
    }

    private func frame(for size: CGSize) -> NSRect {
        guard let screen else { return .zero }
        return NSRect(x: (notchMidX - size.width / 2).rounded(), y: screen.frame.maxY - size.height,
                      width: size.width, height: size.height)
    }

    private func makePanel() -> IslandPanel {
        let panel = IslandPanel()
        let tracking = TrackingView()
        tracking.onEnter = { [weak self] in self?.pointerEntered() }
        tracking.onExit = { [weak self] in self?.pointerLeft() }
        let root = IslandView(
            model: model, companion: companion,
            actions: IslandActions(
                tap: { [weak self] in self?.tapped() },
                push: { [weak self] screen in self?.push(screen) },
                back: { [weak self] in self?.back() },
                home: { [weak self] in self?.goHome() },
                popUp: { [weak self] items in self?.popUp(items) }
            )
        )
        let host = FirstClickHostingView(rootView: root)
        host.sizingOptions = []
        host.translatesAutoresizingMaskIntoConstraints = false
        tracking.addSubview(host)
        NSLayoutConstraint.activate([
            host.leadingAnchor.constraint(equalTo: tracking.leadingAnchor),
            host.trailingAnchor.constraint(equalTo: tracking.trailingAnchor),
            host.topAnchor.constraint(equalTo: tracking.topAnchor),
            host.bottomAnchor.constraint(equalTo: tracking.bottomAnchor),
        ])
        panel.contentView = tracking
        return panel
    }

    // MARK: Size

    /// Recompute what the closed island says, and its size.
    private func refit() {
        guard screen != nil else { return }
        let badge = CompanionCore.badge(companion.snapshot, now: companion.now)
        if badge != model.badge { model.badge = badge }
        let reachable = companion.snapshot.reach.isUp
        if reachable != model.reachable { model.reachable = reachable }
        let ear = earWidth(badge: badge, peek: model.peek)
        if ear != model.ear {
            withAnimation(.spring(response: 0.35, dampingFraction: 0.8)) { model.ear = ear }
        }
        if model.expanded {
            fitOpen(animated: false)
        } else {
            panel?.setFrame(frame(for: model.collapsedSize), display: true)
        }
    }

    /// Always wide enough for the vault's mark, so the island can be found
    /// even when nothing needs the user; wider while it says a few words.
    private func earWidth(badge: Badge?, peek: String?) -> CGFloat {
        if let peek {
            let font = NSFont.systemFont(ofSize: 12, weight: .semibold)
            let text = (peek as NSString).size(withAttributes: [.font: font]).width
            return max(Island.ear, ceil(text) + 22)
        }
        return Island.ear
    }

    private var openSize: CGSize {
        guard let screen else { return model.expandedSize }
        let width = max(Island.width, model.collapsedSize.width)
        let most = screen.frame.height * 0.85
        let height = min(most, model.notch.height + model.contentHeight)
        return CGSize(width: width, height: height.rounded(.up))
    }

    private func fitOpen(animated: Bool) {
        guard model.expanded, let panel else { return }
        let size = openSize
        guard size != model.expandedSize || panel.frame.size != size else { return }
        // Grow the window first, so the island never draws outside it.
        let grown = CGSize(width: max(size.width, panel.frame.width), height: max(size.height, panel.frame.height))
        panel.setFrame(frame(for: grown), display: true)
        if animated {
            withAnimation(.spring(response: 0.35, dampingFraction: 0.85)) { model.expandedSize = size }
        } else {
            model.expandedSize = size
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + (animated ? 0.4 : 0)) { [weak self] in
            guard let self, self.model.expanded, self.model.expandedSize == size else { return }
            self.panel?.setFrame(self.frame(for: size), display: true)
        }
    }

    // MARK: Opening and closing

    func expand(pinned: Bool = false) {
        guard let panel, screen != nil else { return }
        self.pinned = self.pinned || pinned
        openTimer?.invalidate()
        closeTimer?.invalidate()
        if pinned {
            // Only now take focus: a hover never steals the keyboard.
            panel.makeKey()
            watchForClicksOutside()
        }
        guard !model.expanded else { return }
        companion.poke()
        model.expandedSize = CGSize(width: max(Island.width, model.collapsedSize.width), height: openSize.height)
        panel.setFrame(frame(for: model.expandedSize), display: true)
        withAnimation(.spring(response: 0.38, dampingFraction: 0.82)) { model.expanded = true }
    }

    /// Close the island. `force` closes it even while pinned open or while one
    /// of its menus is up (before a dialog, or after a click handed work on).
    func collapse(force: Bool = false) {
        openTimer?.invalidate()
        closeTimer?.invalidate()
        guard model.expanded else { return }
        if !force && (pinned || menusOpen > 0) { return }
        pinned = false
        stopWatchingClicks()
        withAnimation(.spring(response: 0.32, dampingFraction: 0.9)) { model.expanded = false }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) { [weak self] in
            guard let self, !self.model.expanded else { return }
            self.panel?.setFrame(self.frame(for: self.model.collapsedSize), display: true)
            // Closed is closed: the next time, it opens at home.
            self.model.path = []
            if self.companion.working == nil { self.companion.banner = nil }
        }
    }

    private func tapped() {
        if model.expanded && pinned {
            collapse(force: true)
        } else {
            expand(pinned: true)
        }
    }

    private func pointerEntered() {
        closeTimer?.invalidate()
        guard !model.expanded else { return }
        openTimer?.invalidate()
        // A short dwell, so passing through on the way to the menu bar does not open it.
        openTimer = Timer.scheduledTimer(withTimeInterval: 0.15, repeats: false) { [weak self] _ in
            self?.expand()
        }
    }

    private func pointerLeft() {
        openTimer?.invalidate()
        scheduleClose()
    }

    private func scheduleClose() {
        guard model.expanded, !pinned, menusOpen == 0 else { return }
        closeTimer?.invalidate()
        closeTimer = Timer.scheduledTimer(withTimeInterval: 0.4, repeats: false) { [weak self] _ in
            guard let self, !self.pointerInside else { return }
            self.collapse()
        }
    }

    private var pointerInside: Bool {
        panel?.frame.contains(NSEvent.mouseLocation) ?? false
    }

    private func watchForClicksOutside() {
        guard clickMonitor == nil else { return }
        clickMonitor = NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) { [weak self] _ in
            // Not while Touch ID or the vault is being waited on: the
            // fingerprint prompt is another app's window.
            guard let self, !self.companion.awaitingTouch else { return }
            self.collapse(force: true)
        }
        keyMonitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] event in
            if event.keyCode == 53 { // Escape
                self?.collapse(force: true)
                return nil
            }
            return event
        }
    }

    private func stopWatchingClicks() {
        if let clickMonitor { NSEvent.removeMonitor(clickMonitor) }
        if let keyMonitor { NSEvent.removeMonitor(keyMonitor) }
        clickMonitor = nil
        keyMonitor = nil
    }

    // MARK: Screens

    /// Open a screen. A click inside keeps the island open (and lets it take
    /// the keyboard, for the screens with a field to type in).
    func push(_ screen: IslandModel.Screen) {
        companion.banner = nil
        expand(pinned: true)
        model.path.append(screen)
    }

    func back() {
        companion.banner = nil
        if !model.path.isEmpty { model.path.removeLast() }
    }

    func goHome() {
        model.path = []
    }

    /// A submenu of the list, as a native menu at the pointer.
    private func popUp(_ items: [Item]) {
        builder.menu(items).popUp(positioning: nil, at: NSEvent.mouseLocation, in: nil)
    }

    /// Say a few words in the right ear for a moment.
    func peek(_ text: String) {
        guard screen != nil else { return }
        peekTimer?.invalidate()
        model.peek = text
        refit()
        peekTimer = Timer.scheduledTimer(withTimeInterval: 6, repeats: false) { [weak self] _ in
            guard let self else { return }
            self.model.peek = nil
            self.refit()
        }
    }
}
