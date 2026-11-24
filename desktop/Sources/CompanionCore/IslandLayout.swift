import Foundation

// How the island arranges the companion's items. The island shows the very
// list the menu bar menu shows, so both offer the same actions under the same
// labels; this only decides where each item sits.

public struct IslandGroup: Equatable {
    /// The group's first line, when more follows it.
    public var heading: String?
    public var entries: [Item]
}

public struct IslandLayout: Equatable {
    /// The Settings submenu's items, shown behind a gear beside the notch.
    public var settings: [Item]
    /// Refresh and Quit, shown as buttons beside the notch.
    public var chrome: [Item]
    /// Everything else, in order, split where the list has separators.
    public var groups: [IslandGroup]
}

public func islandLayout(_ items: [Item]) -> IslandLayout {
    var settings: [Item] = []
    var chrome: [Item] = []
    var groups: [IslandGroup] = []
    var current: [Item] = []

    func flush() {
        guard !current.isEmpty else { return }
        if case .text(let heading) = current[0], current.count > 1 {
            groups.append(IslandGroup(heading: heading, entries: Array(current.dropFirst())))
        } else {
            groups.append(IslandGroup(heading: nil, entries: current))
        }
        current = []
    }

    for item in items {
        switch item {
        case .separator:
            flush()
        case .submenu(_, let children) where children.contains(where: isNotificationsToggle):
            settings = children
        case .action(.refresh, _), .action(.quit, _):
            chrome.append(item)
        default:
            current.append(item)
        }
    }
    flush()
    return IslandLayout(settings: settings, chrome: chrome, groups: groups)
}

private func isNotificationsToggle(_ item: Item) -> Bool {
    if case .check(.toggleNotifications, _, _) = item { return true }
    return false
}

/// Every action in a list of items, submenus included, in order.
public func actions(in items: [Item]) -> [Action] {
    items.flatMap { item -> [Action] in
        switch item {
        case .action(let a, _), .check(let a, _, _): return [a]
        case .submenu(_, let children): return actions(in: children)
        case .text, .separator: return []
        }
    }
}
