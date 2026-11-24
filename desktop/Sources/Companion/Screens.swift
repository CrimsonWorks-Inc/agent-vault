import AppKit
import CompanionCore
import SwiftUI

/// The island's screens. Every change that widens access goes through
/// `Companion.route`: Touch ID here when it is set up, otherwise the vault
/// page or Terminal, and each button says which.
struct Screens: View {
    @ObservedObject var model: IslandModel
    @ObservedObject var companion: Companion
    let actions: IslandActions

    var body: some View {
        switch model.screen {
        case .home: HomeScreen(companion: companion, actions: actions)
        case .request(let id): RequestScreen(id: id, companion: companion, actions: actions)
        case .session(let id): SessionScreen(id: id, companion: companion, actions: actions)
        case .key(let slug): KeyScreen(slug: slug, companion: companion, actions: actions)
        case .start: StartScreen(companion: companion, actions: actions)
        case .template(let name): TemplateScreen(name: name, companion: companion, actions: actions)
        case .addKey: AddKeyScreen(companion: companion, actions: actions)
        case .replaceKey(let slug): ReplaceKeyScreen(slug: slug, companion: companion, actions: actions)
        case .settings: SettingsScreen(companion: companion, actions: actions)
        case .confirm(let action): ConfirmScreen(action: action, companion: companion, actions: actions)
        }
    }
}

/// A button for a change that needs the human, labelled with where it goes.
struct HumanButton: View {
    @ObservedObject var companion: Companion
    let title: String
    /// The verb when the decision is made elsewhere ("Decide", not "Approve").
    var elsewhere: String? = nil
    let signed: SignedRequest?
    let fallback: Action
    var tint: Color = Tint.accent
    var value: String? = nil
    var disabled = false
    var after: (Bool) -> Void = { _ in }

    var body: some View {
        switch companion.route(signed, otherwise: fallback) {
        case .touchId(let request):
            ActionButton(title: "\(title) with Touch ID", symbol: "touchid", tint: tint,
                         disabled: disabled || companion.working != nil) {
                companion.runSigned(request, value: value, done: after)
            }
        case .handoff(let action):
            VStack(alignment: .leading, spacing: 4) {
                ActionButton(title: "\(elsewhere ?? title) \(action.opensTerminal ? "in Terminal" : "in the vault")",
                             symbol: action.opensTerminal ? "terminal" : "safari", tint: tint, filled: false) {
                    companion.perform(action)
                }
                if signed != nil, let why = whyElsewhere {
                    Text(why).font(.system(size: 10.5)).foregroundStyle(Tint.quiet).padding(.horizontal, 4)
                }
            }
        }
    }

    /// Why this goes to the vault page or Terminal instead of Touch ID here.
    private var whyElsewhere: String? {
        switch companion.touchId {
        case .ready: return nil
        case .vaultTooOld: return "Doing this here with Touch ID needs a newer agent-vault than the one installed."
        case .notSetUp: return "To do this here with Touch ID, set it up in Settings (the gear)."
        case .otherKey: return "Touch ID is set up for another Mac's companion; set it up on this one in Settings."
        case .unavailable: return "This Mac has no fingerprint reader set up, so this needs the vault page or Terminal."
        }
    }
}

// MARK: - Home

struct HomeScreen: View {
    @ObservedObject var companion: Companion
    let actions: IslandActions

    var body: some View {
        let snap = companion.snapshot
        if case .up(let status) = snap.reach {
            up(snap, status)
        } else {
            // Not reachable, not set up, or still checking: the same lines and
            // actions the menu bar menu would show.
            Card {
                ForEach(Array(islandLayout(companion.items).groups.prefix(1).flatMap { g in
                    (g.heading.map { [Item.text($0)] } ?? []) + g.entries
                }.enumerated()), id: \.offset) { _, item in
                    switch item {
                    case .text(let t): Note(text: t, tint: .white)
                    case .action(let a, let t): Row(symbol: "arrow.right.circle", text: t, chevron: false) { companion.perform(a) }
                    default: EmptyView()
                    }
                }
            }
        }
    }

    @ViewBuilder private func up(_ snap: Snapshot, _ status: Status) -> some View {
        HStack(spacing: 8) {
            Image(systemName: status.locked ? "lock.fill" : "lock.open.fill")
                .foregroundStyle(status.locked ? .white : Tint.good)
            Text("\(status.locked ? "Locked" : "Unlocked") · agent-vault \(status.version)")
                .font(.system(size: 12.5, weight: .semibold))
            Spacer()
            if companion.touchId == .ready {
                Label("Touch ID", systemImage: "touchid").font(.system(size: 11)).foregroundStyle(Tint.quiet)
            }
        }
        .padding(.horizontal, 8)

        let steps = setupSteps(snap)
        if !steps.isEmpty {
            Card(title: "Finish setting up") {
                ForEach(Array(steps.enumerated()), id: \.offset) { _, item in
                    if case .action(let a, let t) = item {
                        Row(symbol: "circle.dashed", text: t, tint: Tint.accent, chevron: false) { companion.perform(a) }
                    }
                }
            }
        }

        Card(title: snap.unread.pending ? "Couldn't check what is waiting" : snap.pending.isEmpty ? "Nothing waiting for you" : "Waiting for you (\(snap.pending.count))") {
            ForEach(snap.pending, id: \.id) { p in
                Row(symbol: "hand.raised.fill", text: pendingTitle(p), detail: p.createdAt.map { ago($0, companion.now) }, tint: Tint.waiting) {
                    actions.push(.request(p.id))
                }
            }
        }

        Card(title: snap.unread.sessions ? "Couldn't read open sessions" : snap.sessions.isEmpty ? "No open sessions: agents cannot use any key" : "Open sessions (\(snap.sessions.count))",
             trailing: ("Start", "play.fill", { actions.push(.start) })) {
            ForEach(snap.sessions, id: \.id) { s in
                Row(symbol: "clock", text: s.label, detail: "\(count(s.creds.count, "key")) · \(ends(s))") {
                    actions.push(.session(s.id))
                }
            }
        }

        Card(title: snap.unread.keys ? "Couldn't read your keys" : snap.keys.isEmpty ? "No keys stored yet" : "Keys (\(snap.keys.count))",
             trailing: ("Add", "plus", { addKey() })) {
            ForEach(snap.keys, id: \.slug) { k in
                let (symbol, tint, state) = keyState(k, inUse: snap.inUse(k.slug))
                Row(symbol: symbol, text: k.slug, detail: "\(k.service) · \(state)", tint: tint) {
                    actions.push(.key(k.slug))
                }
            }
        }

        HStack(spacing: 6) {
            Pill(title: "Open the vault", symbol: "safari") { companion.perform(.openUi) }
            if status.locked {
                Pill(title: "Unlock", symbol: "lock.open") { companion.perform(prefsRoute(.unlock)) }
            } else {
                Pill(title: "Lock", symbol: "lock") { companion.runConfirmed(.lock) }
            }
            Spacer(minLength: 0)
            Pill(title: "Panic", symbol: "exclamationmark.octagon", tint: Tint.danger) { actions.push(.confirm(.panic)) }
        }
        .padding(.top, 2)
    }

    private func addKey() {
        if companion.touchId == .ready {
            actions.push(.addKey)
        } else {
            companion.perform(prefsRoute(.addKey))
        }
    }

    private func prefsRoute(_ a: Action) -> Action {
        companion.prefs.terminal && a.hasBothRoutes ? .terminal(a) : a
    }

    private func ends(_ s: Session) -> String {
        s.infinite ? "no expiry" : (s.expiresAt.map { until($0, companion.now) } ?? "expiry unknown")
    }
}

func pendingTitle(_ p: Pending) -> String {
    switch p.kind {
    case "session": return "An agent is asking for access"
    case "request": return "An agent wants to make a change"
    default: return "Something needs your decision"
    }
}

func keyState(_ k: Key, inUse: Bool) -> (String, Color?, String) {
    if k.stopped { return ("pause.circle.fill", Tint.quiet, "stopped") }
    if k.health == .problem { return ("exclamationmark.triangle.fill", Tint.waiting, "last check failed") }
    if k.expiring { return ("exclamationmark.triangle.fill", Tint.waiting, "expires soon") }
    if inUse { return ("key.fill", nil, "in use") }
    if k.health == .ok { return ("key", nil, "ready") }
    return ("key", nil, "not checked yet")
}

// MARK: - A request

struct RequestScreen: View {
    let id: String
    @ObservedObject var companion: Companion
    let actions: IslandActions

    var body: some View {
        if let p = companion.snapshot.pending.first(where: { $0.id == id }) {
            Card {
                VStack(alignment: .leading, spacing: 2) {
                    Text(pendingTitle(p)).font(.system(size: 13, weight: .semibold))
                    if let at = p.createdAt {
                        Text("Asked \(ago(at, companion.now))").font(.system(size: 11)).foregroundStyle(Tint.quiet)
                    }
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                if p.facts.isEmpty {
                    Note(text: "The vault page shows what this request asks for.")
                } else {
                    Facts(facts: p.facts)
                }
                Note(text: "What the agent wrote about its reasons is not shown here; it is the agent's own claim. The vault page shows it, marked as such.")
            }
            HStack(spacing: 8) {
                HumanButton(companion: companion, title: "Approve", elsewhere: "Decide", signed: .approve(id: p.id), fallback: .review(p.id), tint: Tint.good) { ok in
                    if ok { actions.home() }
                }
                if companion.touchId == .ready {
                    HumanButton(companion: companion, title: "Deny", signed: .deny(id: p.id), fallback: .review(p.id), tint: Tint.danger) { ok in
                        if ok { actions.home() }
                    }
                }
            }
            Row(symbol: "safari", text: "See every detail in the vault", chevron: false) { companion.perform(.review(p.id)) }
        } else {
            Card { Note(text: "This request is no longer waiting.", tint: .white) }
        }
    }
}

// MARK: - A session

struct SessionScreen: View {
    let id: String
    @ObservedObject var companion: Companion
    let actions: IslandActions

    var body: some View {
        if let s = companion.snapshot.session(id) {
            Card {
                Text(s.label).font(.system(size: 13, weight: .semibold)).padding(.horizontal, 8).padding(.top, 4)
                Facts(facts: [
                    Fact("Keys", s.creds.isEmpty ? "none listed" : s.creds.joined(separator: ", ")),
                    Fact("Ends", s.infinite ? "never" : (s.expiresAt.map { until($0, companion.now) } ?? "unknown")),
                    Fact("Agents", s.mode),
                ])
            }
            ActionButton(title: "Revoke this session", symbol: "xmark.circle", tint: Tint.danger, filled: false) {
                actions.push(.confirm(.revoke(s.id)))
            }
        } else {
            Card { Note(text: "This session has ended.", tint: .white) }
        }
    }
}

// MARK: - A key

struct KeyScreen: View {
    let slug: String
    @ObservedObject var companion: Companion
    let actions: IslandActions

    var body: some View {
        let snap = companion.snapshot
        if let k = snap.keys.first(where: { $0.slug == slug }) {
            let using = snap.sessions.filter { $0.creds.contains(k.slug) }.map(\.label)
            Card {
                Text(k.slug).font(.system(size: 13, weight: .semibold)).padding(.horizontal, 8).padding(.top, 4)
                Facts(facts: [
                    Fact("Service", k.service),
                    Fact("State", keyState(k, inUse: !using.isEmpty).2),
                    Fact("Used by", using.isEmpty ? "no open session" : using.joined(separator: ", ")),
                ])
            }
            HStack(spacing: 8) {
                let checking = companion.checking.contains(k.slug)
                ActionButton(title: checking ? "Checking…" : "Check it now", symbol: checking ? "hourglass" : "checkmark.seal",
                             filled: false, disabled: checking) {
                    companion.checkKey(k.slug)
                }
                if companion.touchId == .ready {
                    ActionButton(title: "Replace value…", symbol: "arrow.triangle.2.circlepath", filled: false) {
                        actions.push(.replaceKey(k.slug))
                    }
                } else {
                    HumanButton(companion: companion, title: "Replace", signed: nil, fallback: .rotateKey(k.slug))
                }
            }
            if k.stopped {
                HumanButton(companion: companion, title: "Allow it again", signed: .release(slug: k.slug), fallback: .releaseKey(k.slug), tint: Tint.good)
            } else {
                ActionButton(title: "Stop all use of this key", symbol: "pause.circle", tint: Tint.danger, filled: false) {
                    actions.push(.confirm(.stopKey(k.slug)))
                }
            }
        } else {
            Card { Note(text: "This key is no longer in the vault.", tint: .white) }
        }
    }
}

// MARK: - Starting a session

struct StartScreen: View {
    @ObservedObject var companion: Companion
    let actions: IslandActions

    var body: some View {
        let templates = companion.snapshot.templates
        Card(title: templates.isEmpty ? "No templates saved yet" : "From a template") {
            ForEach(templates, id: \.self) { name in
                Row(symbol: "doc.text", text: name) { actions.push(.template(name)) }
            }
        }
        HumanButton(companion: companion, title: "Choose keys and limits", signed: nil, fallback: .newSession)
    }
}

struct TemplateScreen: View {
    let name: String
    @ObservedObject var companion: Companion
    let actions: IslandActions
    @State private var facts: [Fact]?
    @State private var problem: String?

    var body: some View {
        Card {
            Text("“\(name)”").font(.system(size: 13, weight: .semibold)).padding(.horizontal, 8).padding(.top, 4)
            if let facts {
                Facts(facts: facts.isEmpty ? [Fact("Starts", "a session as this template describes")] : facts)
            } else if let problem {
                Note(text: problem, tint: Tint.danger)
            } else {
                Note(text: "Reading the template…")
            }
            Note(text: "Agents can use these keys until the session ends.")
        }
        .onAppear {
            companion.template(name) { result in
                switch result {
                case .success(let f): facts = f
                case .failure(let e): problem = e.message
                }
            }
        }
        HumanButton(companion: companion, title: "Start", signed: .start(template: name), fallback: .start(name), tint: Tint.good,
                    disabled: facts == nil) { ok in
            if ok { actions.home() }
        }
    }
}

// MARK: - Key values

struct AddKeyScreen: View {
    @ObservedObject var companion: Companion
    let actions: IslandActions
    @State private var slug = ""
    @State private var kind = "openai"
    @State private var host = ""
    @State private var value = ""

    var body: some View {
        let request = SignedRequest.add(slug: slug, kind: kind, host: kind == "http" ? host : nil)
        Card {
            Field(label: "Name") {
                TextField("openai-work", text: $slug).textFieldStyle(.roundedBorder)
            }
            Field(label: "Service") {
                Picker("", selection: $kind) {
                    ForEach(keyKinds, id: \.kind) { Text($0.name).tag($0.kind) }
                }
                .labelsHidden()
            }
            if kind == "http" {
                Field(label: "Host") {
                    TextField("api.example.com", text: $host).textFieldStyle(.roundedBorder)
                }
            }
            Field(label: "Value") {
                SecureField("paste the key", text: $value).textFieldStyle(.roundedBorder)
            }
            Note(text: "The value goes straight to the vault. The companion never shows, keeps or logs it, and agents only ever see a placeholder.")
        }
        ActionButton(title: "Add with Touch ID", symbol: "touchid", tint: Tint.good,
                     disabled: request.args == nil || value.isEmpty || companion.working != nil) {
            companion.runSigned(request, value: value) { ok in
                value = ""
                if ok { actions.home() }
            }
        }
        .onDisappear { value = "" }
    }
}

struct ReplaceKeyScreen: View {
    let slug: String
    @ObservedObject var companion: Companion
    let actions: IslandActions
    @State private var value = ""

    var body: some View {
        Card {
            Text("New value for \(slug)").font(.system(size: 13, weight: .semibold)).padding(.horizontal, 8).padding(.top, 4)
            Field(label: "Value") {
                SecureField("paste the new key", text: $value).textFieldStyle(.roundedBorder)
            }
            Note(text: "Open sessions keep working, with the new value. The companion never shows, keeps or logs it.")
        }
        ActionButton(title: "Replace with Touch ID", symbol: "touchid", tint: Tint.good,
                     disabled: value.isEmpty || companion.working != nil) {
            companion.runSigned(.rotate(slug: slug), value: value) { ok in
                value = ""
                if ok { actions.back() }
            }
        }
        .onDisappear { value = "" }
    }
}

struct Field<Content: View>: View {
    let label: String
    @ViewBuilder var content: Content

    var body: some View {
        HStack(spacing: 10) {
            Text(label).font(.system(size: 11.5)).foregroundStyle(Tint.quiet).frame(width: 60, alignment: .leading)
            content
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
    }
}

// MARK: - Settings

struct SettingsScreen: View {
    @ObservedObject var companion: Companion
    let actions: IslandActions

    var body: some View {
        let prefs = companion.prefs
        Card(title: "Touch ID in the island") {
            switch companion.touchId {
            case .ready:
                Note(text: "On. Approvals, new sessions and key changes are confirmed here with your fingerprint.", tint: .white)
                Row(symbol: "touchid", text: "Turn off Touch ID in the island", chevron: false) { companion.turnOffTouchId() }
            case .notSetUp:
                Note(text: "Approve here with your fingerprint instead of in the vault page or Terminal. Setting it up asks for your passphrase once, in Terminal.")
                Row(symbol: "touchid", text: "Set up Touch ID in the island… (opens Terminal)", tint: Tint.accent, chevron: false) {
                    companion.setUpTouchId()
                }
            case .otherKey:
                Note(text: "The vault trusts another Mac's companion for Touch ID. Set it up here to use this Mac instead.")
                Row(symbol: "touchid", text: "Set up Touch ID on this Mac… (opens Terminal)", tint: Tint.accent, chevron: false) {
                    companion.setUpTouchId()
                }
            case .unavailable:
                Note(text: "This Mac has no fingerprint reader with a finger enrolled, so approvals go to the vault page or Terminal.")
            case .vaultTooOld:
                Note(text: "Touch ID in the island needs a newer agent-vault than the one installed. Update it (brew upgrade agent-vault, then av upgrade), and approvals go to the vault page or Terminal until then.")
            }
        }
        Card(title: "Settings") {
            Toggle("Show notifications", isOn: binding(prefs.notifications, .toggleNotifications))
                .padding(.horizontal, 8).padding(.vertical, 3)
            Toggle("Start at login", isOn: binding(prefs.autostart, .toggleAutostart))
                .padding(.horizontal, 8).padding(.vertical, 3)
            Toggle("Without Touch ID, approve in Terminal with my passphrase", isOn: binding(prefs.terminal, .toggleTerminal))
                .padding(.horizontal, 8).padding(.vertical, 3)
            Row(symbol: "safari", text: "Set up Touch ID approvals in the browser…", chevron: false) { companion.perform(.touchIdInUi) }
        }
        .toggleStyle(.switch)
        .controlSize(.mini)
        .font(.system(size: 12))
        if companion.snapshot.reach.isUp {
            Card(title: "Agents") {
                if companion.snapshot.agents.isEmpty {
                    Note(text: "No supported agents found on this computer")
                }
                ForEach(companion.snapshot.agents, id: \.id) { a in
                    if a.connected {
                        Row(symbol: "checkmark.circle.fill", text: "\(a.name) · connected", tint: Tint.good, chevron: false) {}
                    } else {
                        Row(symbol: "link", text: "Connect \(a.name)", chevron: false) { companion.perform(.connect(a.id)) }
                    }
                }
            }
            Card(title: "Move keys to another computer") {
                Row(symbol: "square.and.arrow.up", text: "Save my keys to an encrypted file… (opens Terminal)", chevron: false) { companion.perform(.exportInTerminal) }
                Row(symbol: "square.and.arrow.down", text: "Bring in keys from that file… (opens Terminal)", chevron: false) { companion.perform(.restoreInTerminal) }
            }
        }
    }

    private func binding(_ on: Bool, _ action: Action) -> Binding<Bool> {
        Binding(get: { on }, set: { _ in companion.perform(action) })
    }
}

// MARK: - Confirming

struct ConfirmScreen: View {
    let action: Action
    @ObservedObject var companion: Companion
    let actions: IslandActions

    var body: some View {
        if let ask = action.confirm(companion.snapshot) {
            Card {
                Text(ask.title).font(.system(size: 13, weight: .semibold)).padding(.horizontal, 8).padding(.top, 4)
                Note(text: ask.body, tint: .white)
            }
            HStack(spacing: 8) {
                ActionButton(title: "Cancel", tint: .white, filled: false) { actions.back() }
                ActionButton(title: ask.ok, tint: Tint.danger) {
                    companion.runConfirmed(action)
                    actions.home()
                }
            }
        }
    }
}
