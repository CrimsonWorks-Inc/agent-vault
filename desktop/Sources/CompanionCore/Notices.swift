import Foundation

// What deserves a notification, worked out by comparing two snapshots. Pure,
// like the model, so the rules are tested rather than watched.
//
// A notice says that something happened, never what an agent wrote about it.

public enum Notice: Equatable {
    case waiting(Int)
    case endingSoon(label: String, minutes: Int)
    case ended(label: String)
    case locked
    case unreachable
    case back
    case keyProblem(slug: String)
    case keyStopped(slug: String)

    public func text(_ placement: Placement) -> String {
        let look = placement == .island
            ? "Point at the notch at the top of your screen"
            : "Open the menu bar icon"
        switch self {
        case .waiting(1):
            return "An agent is waiting for your decision. \(look) to review it."
        case .waiting(let n):
            return "\(n) things are waiting for your decision. \(look) to review them."
        case .endingSoon(let label, let minutes):
            return "Session “\(label)” ends in about \(minutes) min."
        case .ended(let label):
            return "Session “\(label)” has ended."
        case .locked:
            return "The vault is locked. Agents cannot use any key until you unlock it."
        // Only what the companion knows: it lost contact. Whether agents are
        // affected depends on why, which it cannot tell from here.
        case .unreachable:
            return "The companion lost contact with agent-vault, so what it shows may be out of date. It keeps trying."
        case .back:
            return "The companion is in contact with agent-vault again."
        case .keyProblem(let slug):
            return "The key “\(slug)” failed its check. It may have expired or been revoked."
        case .keyStopped(let slug):
            return "The key “\(slug)” is stopped. No agent can use it."
        }
    }
}

/// What the companion remembers between refreshes so nothing is said twice.
public struct Memo {
    /// Pending ids already announced. `nil` until the first look.
    var seen: Set<String>?
    /// Sessions already given their "ending soon" warning.
    var warned: Set<String> = []
    /// Sessions the user just ended from the companion: their end needs no notice.
    var quiet: Set<String> = []

    public init() {}

    /// The user ended these themselves and was already told.
    public mutating func endedByUser<S: Sequence>(_ ids: S) where S.Element == String {
        quiet.formUnion(ids)
    }

    /// The command failed, so these sessions are still running after all.
    public mutating func notEnded(_ ids: [String]) {
        quiet.subtract(ids)
    }
}

public func notices(_ prev: Snapshot, _ next: Snapshot, now: Date, memo: inout Memo) -> [Notice] {
    var out: [Notice] = []
    let wasUp = prev.reach.isUp
    guard case .up(let status) = next.reach else {
        if wasUp && next.reach.isDown {
            out.append(.unreachable)
        }
        return out
    }
    if prev.reach.isDown {
        out.append(.back)
    }

    // Requests waiting. On the first look, mention whatever is already there.
    if !next.unread.pending {
        let ids = Set(next.pending.map(\.id))
        let fresh = memo.seen.map { ids.subtracting($0).count } ?? ids.count
        memo.seen = ids
        if fresh > 0 {
            out.append(.waiting(fresh))
        }
    }

    if case .up(let before) = prev.reach, !before.locked, status.locked {
        out.append(.locked)
    }

    if !next.unread.sessions {
        // Ended: there before, gone now. Only when both lists were really read.
        if wasUp && !prev.unread.sessions {
            for s in prev.sessions where next.session(s.id) == nil {
                if memo.quiet.remove(s.id) == nil {
                    out.append(.ended(label: s.label))
                }
            }
        }
        // Ending soon: once per session.
        for s in next.sessions {
            guard !s.infinite, let end = s.expiresAt else { continue }
            let left = end.timeIntervalSince(now)
            if left <= 0 { continue } // already over: the next refresh reports it as ended
            if left <= Double(endingSoonMinutes * 60) && memo.warned.insert(s.id).inserted {
                out.append(.endingSoon(label: s.label, minutes: max(1, (Int(left.rounded(.down)) + 59) / 60)))
            }
        }
        memo.warned = memo.warned.filter { next.session($0) != nil }
        memo.quiet = memo.quiet.filter { next.session($0) != nil }
    }

    // Keys: only changes seen while running. A key that was already failing
    // when the companion started is shown in the list, not announced.
    if wasUp && !prev.unread.keys && !next.unread.keys {
        for k in next.keys {
            guard let before = prev.keys.first(where: { $0.slug == k.slug }) else { continue }
            if !before.stopped && k.stopped {
                out.append(.keyStopped(slug: k.slug))
            } else if before.health == .ok && k.health == .problem {
                out.append(.keyProblem(slug: k.slug))
            }
        }
    }
    return out
}
