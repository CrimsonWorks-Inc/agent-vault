import AppKit
import Combine
import CompanionCore

/// Native menus built from the companion's items: the menu bar menu on a
/// screen without a notch, and the island's submenus.
final class MenuBuilder: NSObject {
    private let perform: (Action) -> Void

    init(perform: @escaping (Action) -> Void) {
        self.perform = perform
    }

    func menu(_ items: [Item]) -> NSMenu {
        let m = NSMenu()
        fill(m, items)
        return m
    }

    func fill(_ m: NSMenu, _ items: [Item]) {
        m.autoenablesItems = false
        for item in items {
            switch item {
            case .text(let text):
                let mi = NSMenuItem(title: text, action: nil, keyEquivalent: "")
                mi.isEnabled = false
                m.addItem(mi)
            case .action(let action, let text):
                m.addItem(entry(action, text))
            case .check(let action, let text, let on):
                let mi = entry(action, text)
                mi.state = on ? .on : .off
                m.addItem(mi)
            case .separator:
                m.addItem(.separator())
            case .submenu(let text, let children):
                let mi = NSMenuItem(title: text, action: nil, keyEquivalent: "")
                mi.submenu = menu(children)
                m.addItem(mi)
            }
        }
    }

    private func entry(_ action: Action, _ text: String) -> NSMenuItem {
        let mi = NSMenuItem(title: text, action: #selector(clicked(_:)), keyEquivalent: "")
        mi.target = self
        mi.representedObject = ActionBox(action)
        mi.isEnabled = true
        return mi
    }

    @objc private func clicked(_ sender: NSMenuItem) {
        guard let box = sender.representedObject as? ActionBox else { return }
        // After the menu has closed, so a dialog is not opened inside its tracking.
        DispatchQueue.main.async { self.perform(box.action) }
    }
}

final class ActionBox: NSObject {
    let action: Action
    init(_ action: Action) { self.action = action }
}

/// The menu bar icon, for screens without a notch.
final class StatusMenu: NSObject, NSMenuDelegate {
    private let companion: Companion
    private lazy var builder = MenuBuilder { [weak self] in self?.companion.perform($0) }
    private var item: NSStatusItem?
    private var watching: AnyCancellable?

    init(companion: Companion) {
        self.companion = companion
    }

    func show() {
        guard item == nil else { return }
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let image = Bundle.main.image(forResource: "TrayTemplate") {
            image.isTemplate = true
            image.size = NSSize(width: 18, height: 18)
            item.button?.image = image
        } else {
            item.button?.title = "AV"
        }
        item.button?.imagePosition = .imageLeading
        let menu = NSMenu()
        menu.delegate = self
        item.menu = menu
        self.item = item
        watching = companion.$snapshot.receive(on: RunLoop.main).sink { [weak self] _ in self?.update() }
        update()
    }

    func hide() {
        watching = nil
        if let item { NSStatusBar.system.removeStatusItem(item) }
        item = nil
    }

    private func update() {
        let snap = companion.snapshot
        item?.button?.title = trayTitle(snap).map { " \($0)" } ?? ""
        item?.button?.toolTip = tooltip(snap)
    }

    /// Built as it opens, from what the companion knows right now.
    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        builder.fill(menu, companion.items)
    }
}
