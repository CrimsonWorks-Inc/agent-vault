import AppKit
import CompanionCore
import SwiftUI

/// The island's shape: flat along the top of the screen, rounded below.
struct IslandShape: Shape {
    var radius: CGFloat

    var animatableData: CGFloat {
        get { radius }
        set { radius = newValue }
    }

    func path(in r: CGRect) -> Path {
        let rad = min(radius, r.height / 2, r.width / 2)
        var p = Path()
        p.move(to: CGPoint(x: r.minX, y: r.minY))
        p.addLine(to: CGPoint(x: r.maxX, y: r.minY))
        p.addLine(to: CGPoint(x: r.maxX, y: r.maxY - rad))
        p.addArc(tangent1End: CGPoint(x: r.maxX, y: r.maxY), tangent2End: CGPoint(x: r.maxX - rad, y: r.maxY), radius: rad)
        p.addLine(to: CGPoint(x: r.minX + rad, y: r.maxY))
        p.addArc(tangent1End: CGPoint(x: r.minX, y: r.maxY), tangent2End: CGPoint(x: r.minX, y: r.maxY - rad), radius: rad)
        p.closeSubpath()
        return p
    }
}

struct HeightKey: PreferenceKey {
    static var defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = max(value, nextValue()) }
}

/// The vault's hexagon-and-keyhole mark (the menu bar icon), drawn in white.
struct VaultMark: View {
    let size: CGFloat
    private static let image: NSImage? = Bundle.main.image(forResource: "TrayTemplate")

    var body: some View {
        if let image = Self.image {
            Image(nsImage: image)
                .renderingMode(.template)
                .resizable()
                .interpolation(.high)
                .aspectRatio(contentMode: .fit)
                .frame(width: size, height: size)
                .foregroundStyle(.white)
        } else {
            Image(systemName: "lock.shield.fill")
                .font(.system(size: size * 0.85, weight: .semibold))
                .foregroundStyle(.white)
        }
    }
}

enum Tint {
    static let waiting = Color(red: 1.0, green: 0.62, blue: 0.18)
    static let danger = Color(red: 1.0, green: 0.36, blue: 0.33)
    static let good = Color(red: 0.32, green: 0.84, blue: 0.47)
    static let accent = Color(red: 0.42, green: 0.66, blue: 1.0)
    static let quiet = Color.white.opacity(0.55)
    static let faint = Color.white.opacity(0.35)
    static let card = Color.white.opacity(0.06)
    static let row = Color.white.opacity(0.08)
}

/// What the island's views can ask of it.
struct IslandActions {
    let tap: () -> Void
    let push: (IslandModel.Screen) -> Void
    let back: () -> Void
    let home: () -> Void
    let popUp: ([Item]) -> Void
}

struct IslandView: View {
    @ObservedObject var model: IslandModel
    @ObservedObject var companion: Companion
    let actions: IslandActions

    var body: some View {
        let size = model.expanded ? model.expandedSize : model.collapsedSize
        let radius = model.expanded ? 24 : min(12, size.height / 2.6)
        VStack(spacing: 0) {
            ZStack(alignment: .top) {
                IslandShape(radius: radius).fill(Color.black)
                if model.expanded {
                    OpenIsland(model: model, companion: companion, actions: actions)
                        .transition(.opacity.combined(with: .scale(scale: 0.96, anchor: .top)))
                } else {
                    ClosedIsland(model: model)
                        .contentShape(Rectangle())
                        .onTapGesture(perform: actions.tap)
                        .transition(.opacity)
                }
            }
            .frame(width: size.width, height: size.height)
            .clipShape(IslandShape(radius: radius))
            .shadow(color: .black.opacity(model.expanded ? 0.35 : 0), radius: 14, y: 6)
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .environment(\.colorScheme, .dark)
    }
}

// MARK: - Closed

struct ClosedIsland: View {
    @ObservedObject var model: IslandModel

    var body: some View {
        HStack(spacing: 0) {
            VaultMark(size: 15)
                .frame(width: model.ear, height: model.notch.height)
                .accessibilityLabel("agent-vault companion")
            Spacer(minLength: model.notch.width)
            rightMark
                .frame(width: model.ear, height: model.notch.height)
        }
        .frame(height: model.notch.height)
        .animation(.easeOut(duration: 0.2), value: model.peek)
    }

    /// What needs the user, if anything; otherwise a quiet dot.
    @ViewBuilder private var rightMark: some View {
        if let peek = model.peek {
            Text(peek)
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(Tint.waiting)
                .lineLimit(1)
                .fixedSize()
        } else if let badge = model.badge {
            Group {
                switch badge {
                case .waiting(let n):
                    Text("\(n)")
                        .font(.system(size: 11, weight: .bold).monospacedDigit())
                        .foregroundStyle(.black)
                        .padding(.horizontal, 5)
                        .frame(minWidth: 18, minHeight: 18)
                        .background(Capsule().fill(Tint.waiting))
                case .unknownWaiting:
                    Text("?").font(.system(size: 12, weight: .bold)).foregroundStyle(Tint.waiting)
                case .ending(let minutes):
                    Text("\(minutes)m").font(.system(size: 11, weight: .semibold).monospacedDigit()).foregroundStyle(.yellow)
                case .locked:
                    Image(systemName: "lock.fill").font(.system(size: 11, weight: .semibold)).foregroundStyle(.white)
                case .unreachable:
                    Image(systemName: "exclamationmark.triangle.fill").font(.system(size: 11, weight: .semibold)).foregroundStyle(Tint.danger)
                case .notSetUp:
                    Image(systemName: "plus.circle.fill").font(.system(size: 11, weight: .semibold)).foregroundStyle(.white)
                case .untrusted:
                    Image(systemName: "xmark.shield.fill").font(.system(size: 11, weight: .semibold)).foregroundStyle(Tint.danger)
                }
            }
            .accessibilityLabel(describe(badge))
        } else {
            Circle()
                .fill(model.reachable ? Tint.good : Tint.quiet)
                .frame(width: 6, height: 6)
                .accessibilityLabel(model.reachable ? "Nothing needs you" : "Checking agent-vault")
        }
    }

    private func describe(_ b: Badge) -> String {
        switch b {
        case .waiting(let n): return "\(n) waiting for you"
        case .unknownWaiting: return "Couldn't check what is waiting"
        case .locked: return "The vault is locked"
        case .ending(let m): return "A session ends in \(m) minutes"
        case .unreachable: return "agent-vault is not answering"
        case .notSetUp: return "agent-vault is not set up"
        case .untrusted: return "This agent-vault install cannot be trusted"
        }
    }
}

// MARK: - Open

struct OpenIsland: View {
    @ObservedObject var model: IslandModel
    @ObservedObject var companion: Companion
    let actions: IslandActions

    var body: some View {
        VStack(spacing: 0) {
            band
            ScrollView(.vertical, showsIndicators: false) {
                VStack(alignment: .leading, spacing: 10) {
                    if let working = companion.working {
                        WorkingView(text: working)
                    } else if let banner = companion.banner {
                        BannerView(banner: banner) { companion.banner = nil }
                    }
                    Screens(model: model, companion: companion, actions: actions)
                }
                .padding(.horizontal, 14)
                .padding(.top, 4)
                .padding(.bottom, 14)
                .background(GeometryReader { p in Color.clear.preference(key: HeightKey.self, value: p.size.height) })
            }
            .onPreferenceChange(HeightKey.self) { h in
                if h > 0 && abs(h - model.contentHeight) > 0.5 { model.contentHeight = h }
            }
        }
        .foregroundStyle(.white)
        .animation(.easeOut(duration: 0.18), value: model.path)
    }

    /// The band beside the notch: where you are, and the island's own buttons.
    private var band: some View {
        HStack(spacing: 0) {
            HStack(spacing: 6) {
                if model.path.isEmpty {
                    VaultMark(size: 14)
                    Text("agent-vault").font(.system(size: 12, weight: .semibold))
                    Circle().fill(dot).frame(width: 6, height: 6)
                } else {
                    BandButton(symbol: "chevron.left", help: "Back", action: actions.back)
                    Text(model.screen.title).font(.system(size: 12, weight: .semibold)).lineLimit(1)
                }
            }
            .padding(.leading, model.path.isEmpty ? 18 : 10)
            Spacer(minLength: model.notch.width + 8)
            HStack(spacing: 2) {
                BandButton(symbol: "arrow.clockwise", help: "Refresh") { companion.perform(.refresh) }
                BandButton(symbol: "gearshape", help: "Settings") { actions.push(.settings) }
                BandButton(symbol: "power", help: "Quit companion") { companion.perform(.quit) }
            }
            .padding(.trailing, 12)
        }
        .frame(height: model.notch.height)
    }

    private var dot: Color {
        switch companion.snapshot.reach {
        case .up(let s): return s.locked ? .white.opacity(0.7) : Tint.good
        case .loading: return Tint.quiet
        case .down, .missing: return Tint.danger
        }
    }
}

// MARK: - Pieces

struct BandButton: View {
    let symbol: String
    let help: String
    let action: () -> Void
    @State private var hover = false

    var body: some View {
        Button(action: action) {
            Image(systemName: symbol)
                .font(.system(size: 12, weight: .medium))
                .frame(width: 26, height: 22)
                .background(RoundedRectangle(cornerRadius: 6).fill(hover ? Tint.row : .clear))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(help)
        .accessibilityLabel(help)
        .onHover { hover = $0 }
    }
}

/// A rounded group of rows with an optional heading and a button beside it.
struct Card<Content: View>: View {
    var title: String?
    var trailing: (label: String, symbol: String, action: () -> Void)?
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            if title != nil || trailing != nil {
                HStack {
                    if let title {
                        Text(title).font(.system(size: 11, weight: .semibold)).foregroundStyle(Tint.quiet)
                    }
                    Spacer()
                    if let trailing {
                        Button(action: trailing.action) {
                            Label(trailing.label, systemImage: trailing.symbol)
                                .font(.system(size: 11, weight: .semibold))
                                .foregroundStyle(Tint.accent)
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(.horizontal, 8)
                .padding(.bottom, 2)
            }
            content
        }
        .padding(6)
        .background(RoundedRectangle(cornerRadius: 12).fill(Tint.card))
    }
}

struct Row: View {
    let symbol: String
    let text: String
    var detail: String? = nil
    var tint: Color? = nil
    var chevron = true
    let action: () -> Void
    @State private var hover = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 9) {
                Image(systemName: symbol)
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(tint ?? Color.white.opacity(0.85))
                    .frame(width: 16)
                VStack(alignment: .leading, spacing: 1) {
                    Text(text)
                        .font(.system(size: 12.5, weight: .medium))
                        .foregroundStyle(tint ?? .white)
                        .lineLimit(2)
                        .multilineTextAlignment(.leading)
                        .fixedSize(horizontal: false, vertical: true)
                    if let detail {
                        Text(detail)
                            .font(.system(size: 11))
                            .foregroundStyle(Tint.quiet)
                            .lineLimit(2)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                Spacer(minLength: 4)
                if chevron {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundStyle(Tint.faint)
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            .background(RoundedRectangle(cornerRadius: 8).fill(hover ? Tint.row : .clear))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hover = $0 }
    }
}

/// A line of plain text in a card.
struct Note: View {
    let text: String
    var tint: Color = Tint.quiet

    var body: some View {
        Text(text)
            .font(.system(size: 12))
            .foregroundStyle(tint)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// A large button. `touchId` puts the fingerprint on it.
struct ActionButton: View {
    let title: String
    var symbol: String? = nil
    var tint: Color = Tint.accent
    var filled = true
    var disabled = false
    let action: () -> Void
    @State private var hover = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 6) {
                if let symbol { Image(systemName: symbol).font(.system(size: 13, weight: .semibold)) }
                Text(title).font(.system(size: 12.5, weight: .semibold)).lineLimit(1)
            }
            .foregroundStyle(filled ? Color.black : tint)
            .frame(maxWidth: .infinity, minHeight: 30)
            .background(
                RoundedRectangle(cornerRadius: 9)
                    .fill(filled ? tint.opacity(hover ? 1 : 0.9) : tint.opacity(hover ? 0.2 : 0.12))
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(disabled)
        .opacity(disabled ? 0.45 : 1)
        .onHover { hover = $0 }
    }
}

struct Pill: View {
    let title: String
    let symbol: String
    var tint: Color = .white
    let action: () -> Void
    @State private var hover = false

    var body: some View {
        Button(action: action) {
            Label(title, systemImage: symbol)
                .font(.system(size: 11.5, weight: .semibold))
                .foregroundStyle(tint)
                .padding(.horizontal, 10)
                .frame(height: 26)
                .background(Capsule().fill(hover ? Tint.row.opacity(1.6) : Tint.row))
                .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .onHover { hover = $0 }
    }
}

struct Facts: View {
    let facts: [Fact]

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            ForEach(Array(facts.enumerated()), id: \.offset) { _, f in
                HStack(alignment: .firstTextBaseline, spacing: 10) {
                    Text(f.label)
                        .font(.system(size: 11.5))
                        .foregroundStyle(Tint.quiet)
                        .frame(width: 84, alignment: .leading)
                    Text(f.value)
                        .font(.system(size: 12, weight: .medium))
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 0)
                }
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
    }
}

struct BannerView: View {
    let banner: Companion.Banner
    let dismiss: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: banner.failed ? "exclamationmark.circle.fill" : "checkmark.circle.fill")
                .foregroundStyle(banner.failed ? Tint.danger : Tint.good)
            Text(banner.text)
                .font(.system(size: 12))
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 4)
            Button(action: dismiss) {
                Image(systemName: "xmark").font(.system(size: 10, weight: .bold)).foregroundStyle(Tint.quiet)
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Dismiss")
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 10).fill((banner.failed ? Tint.danger : Tint.good).opacity(0.14)))
    }
}

struct WorkingView: View {
    let text: String

    var body: some View {
        HStack(spacing: 8) {
            ProgressView().controlSize(.small)
            Text(text).font(.system(size: 12, weight: .medium))
            Spacer()
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 10).fill(Tint.card))
    }
}
