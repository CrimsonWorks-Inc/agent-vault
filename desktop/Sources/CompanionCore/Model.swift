import Foundation

// What the companion shows, worked out from the CLI's JSON. Pure: no I/O and
// no AppKit, so every rule here is covered by the tests.

/// Agents the vault can write itself into, as `mcp install --agent` names them.
public let agents: [(id: String, name: String)] = [
    ("claude-code", "Claude Code"),
    ("codex", "Codex"),
    ("cursor", "Cursor"),
    ("gemini", "Gemini CLI"),
]

/// The folder in the home directory that says an agent is on this computer.
public func agentMarker(_ id: String) -> String {
    switch id {
    case "claude-code": return ".claude"
    case "codex": return ".codex"
    case "cursor": return ".cursor"
    default: return ".gemini"
    }
}

/// Where the companion is on screen, which changes how it describes itself.
public enum Placement: Equatable {
    /// Around the notch at the top of a built-in display.
    case island
    /// A menu bar icon, on a screen without a notch.
    case menuBar
}

/// Why there is no vault to talk to.
public enum Missing: Error, Equatable {
    /// Nothing installed: the companion can start the installer.
    case notInstalled
    /// Something is there, but it is not a root-owned install: never run it.
    case untrusted(String)
    /// The vault does not run on this operating system.
    case unsupported
}

/// How far the companion got in reaching the vault.
public enum Reach: Equatable {
    /// Nothing checked yet.
    case loading
    /// No trustworthy agent-vault install on this computer.
    case missing(Missing)
    /// Installed, but the daemon did not answer.
    case down(String)
    /// Answering.
    case up(Status)

    public var isUp: Bool {
        if case .up = self { return true }
        return false
    }

    public var isDown: Bool {
        if case .down = self { return true }
        return false
    }
}

public struct Status: Equatable {
    public var version: String
    public var locked: Bool

    public init(version: String, locked: Bool) {
        self.version = version
        self.locked = locked
    }
}

public struct Session: Equatable {
    public var id: String
    public var label: String
    public var creds: [String]
    public var expiresAt: Date?
    public var infinite: Bool
    /// One plain sentence on what agents may do with it.
    public var mode: String
}

public struct Pending: Equatable {
    public var id: String
    public var kind: String
    public var createdAt: Date?
    /// What the vault recorded about the request, for the island's detail
    /// screen. Never the agent's stated reason.
    public var facts: [Fact] = []

    public init(id: String, kind: String, createdAt: Date?, facts: [Fact] = []) {
        self.id = id
        self.kind = kind
        self.createdAt = createdAt
        self.facts = facts
    }
}

/// One line of a detail screen: a label and a value, both already cleaned.
public struct Fact: Equatable {
    public var label: String
    public var value: String

    public init(_ label: String, _ value: String) {
        self.label = label
        self.value = value
    }
}

public enum Health: Equatable {
    case ok, problem, unknown
}

public struct Key: Equatable {
    public var slug: String
    public var service: String
    public var health: Health
    public var stopped: Bool
    public var expiring: Bool
}

/// What `doctor` says about the human factor. `nil` means not known.
///
/// Whether Touch ID *approvals* are enrolled is not here: the CLI does not
/// report it. (`doctor`'s "authenticator" is Touch ID *unlock*, a separate
/// thing.) So the companion never guesses which way the user approves; the
/// user says, in Settings.
public struct Setup: Equatable {
    public var passphrase: Bool?

    public init(passphrase: Bool? = nil) {
        self.passphrase = passphrase
    }
}

public struct AgentLink: Equatable {
    public var id: String
    public var name: String
    public var connected: Bool

    public init(id: String, name: String, connected: Bool) {
        self.id = id
        self.name = name
        self.connected = connected
    }
}

/// The user's choices, kept between launches.
public struct Prefs: Equatable {
    public var notifications = true
    public var autostart = false
    /// The first-run welcome has been shown.
    public var welcomed = false
    /// Decide and grant in Terminal with the passphrase, even when Touch ID
    /// approvals are set up.
    public var terminal = false

    public init(notifications: Bool = true, autostart: Bool = false, welcomed: Bool = false, terminal: Bool = false) {
        self.notifications = notifications
        self.autostart = autostart
        self.welcomed = welcomed
        self.terminal = terminal
    }
}

/// Lists the CLI failed to return. Shown as "couldn't read", never as an
/// empty list: "no open sessions" must mean exactly that.
public struct Unread: Equatable {
    public var sessions = false
    public var pending = false
    public var templates = false
    public var keys = false

    public init(sessions: Bool = false, pending: Bool = false, templates: Bool = false, keys: Bool = false) {
        self.sessions = sessions
        self.pending = pending
        self.templates = templates
        self.keys = keys
    }
}

public struct Snapshot: Equatable {
    public var reach: Reach
    public var sessions: [Session] = []
    public var pending: [Pending] = []
    public var templates: [String] = []
    public var keys: [Key] = []
    public var setup = Setup()
    /// Agents found on this computer, connected or not.
    public var agents: [AgentLink] = []
    /// What the vault says about Touch ID in the companion; `nil` if unread.
    public var enrollment: Enrollment?
    /// The installed CLI has no `companion` command: an older vault.
    public var companionUnsupported = false
    public var unread = Unread()

    public init(reach: Reach) {
        self.reach = reach
    }

    public static func loading() -> Snapshot { Snapshot(reach: .loading) }

    public func session(_ id: String) -> Session? {
        sessions.first { $0.id == id }
    }

    public func inUse(_ slug: String) -> Bool {
        sessions.contains { $0.creds.contains(slug) }
    }
}

// MARK: - Actions

/// Everything a click can ask for.
///
/// The companion itself runs only the commands in `cliArgs`, none of which
/// the daemon gates. Everything that widens access (deciding a request,
/// starting a session, adding, replacing or re-allowing a key, unlocking) is
/// handed to one of the two places where the human proves presence: a page of
/// the vault's web UI (Touch ID), or a Terminal window on the vault's own
/// command (passphrase). `Prefs.terminal` picks which.
public indirect enum Action: Equatable, Hashable {
    case review(String)
    case start(String)
    case newSession
    case addKey
    case releaseKey(String)
    case rotateKey(String)
    case touchIdInUi
    case openUi
    case unlock
    case revoke(String)
    case stopKey(String)
    case testKeys
    /// Check one key against its own service.
    case testKey(String)
    /// Set up Touch ID in the companion: enrol this Mac's Secure Enclave key,
    /// with the passphrase typed in Terminal. The public key (base64url) and
    /// a plain label for this Mac.
    case enrollTouchIdInTerminal(String, String)
    case connect(String)
    case lock
    case panic
    case installInTerminal
    case passphraseInTerminal
    case exportInTerminal
    case restoreInTerminal
    case toggleNotifications
    case toggleAutostart
    case toggleTerminal
    case refresh
    case quit
    /// One of the actions above that has both routes, sent to Terminal. The
    /// route is part of the item, so what its label says is what a click
    /// does, whatever has changed since the item was drawn.
    case terminal(Action)

    /// The web UI page to open, as a URL fragment the UI's router reads.
    public var uiFragment: String? {
        switch self {
        case .review(let id): return "#approvals/\(encodeComponent(id))"
        case .start(let name): return "#sessions/\(encodeComponent("new:\(name)"))"
        case .newSession: return "#sessions/new"
        case .addKey, .rotateKey: return "#credentials"
        case .releaseKey: return "#containment"
        case .touchIdInUi, .unlock: return "#settings"
        case .openUi: return ""
        default: return nil
        }
    }

    /// The exact CLI command an action runs, if it runs one. Every command
    /// here is one the daemon lets an unproven caller run: it narrows access
    /// (revoke, stop a key, lock, panic), checks keys against their own
    /// service, or writes the vault's entry into an agent's own config file.
    /// A value that is not plain is never passed on.
    public var cliArgs: [String]? {
        switch self {
        case .revoke(let sid) where safeId(sid):
            return ["session", "revoke", sid]
        case .stopKey(let slug) where safeId(slug):
            return ["cred", "quarantine", slug, "--reason", "stopped from the agent-vault companion"]
        case .testKeys:
            return ["cred", "test", "--all"]
        case .testKey(let slug) where safeId(slug):
            return ["cred", "test", slug]
        case .connect(let agent) where CompanionCore.agents.contains(where: { $0.id == agent }):
            return ["mcp", "install", "--agent", agent, "--scope", "user"]
        case .lock:
            return ["lock"]
        case .panic:
            return ["panic", "--reason", "panic from the agent-vault companion"]
        default:
            return nil
        }
    }

    /// The command to run in Terminal, for the steps where the human types a
    /// password or passphrase. The text is fixed except for an id, key name or
    /// template name, and those are only ever the plain kind (`safeId`).
    ///
    /// Terminal starts the user's own shell, whichever that is, with whatever
    /// its profile sets up. So the shell is handed one thing to do: start
    /// `/bin/sh` in an emptied environment on a single-quoted script. The
    /// user's shell only expands `$HOME`, `$USER` and `$TERM`; everything else
    /// is read by `/bin/sh`, the same way on every Mac.
    ///
    /// The vault keeps a short window open after a passphrase is typed, in
    /// which it does not ask again. So a command that would decide or grant
    /// something the moment it runs first shows what it is about and asks for
    /// a typed answer, matched exactly.
    public var terminalScript: String? {
        let v = "/var/db/agent-vault/app/bin/agent-vault"
        let file = "~/Desktop/agent-vault-backup.json"
        let close = "echo; echo \"You can close this window.\""
        // Reads one line as typed: no trimming, no backslash handling, and an
        // unreadable or closed input counts as no answer.
        let ask = "answer=\"\"; IFS= read -r answer || answer=\"\""
        let body: String
        switch self {
        // The installer unpacks the release and prints the one privileged
        // command; `setup --print-only` prints it again on its own line, and
        // that line is what runs under sudo. Then the passphrase, at once: a
        // vault with no passphrase belongs to whoever sets the first one.
        case .installInTerminal:
            body = [
                "echo \"Setting up agent-vault. This takes about a minute.\"; echo;",
                "/usr/bin/curl -fsSL https://github.com/CrimsonWorks-Inc/agent-vault/releases/latest/download/install.sh",
                "| PATH=/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin /bin/sh",
                "&& echo && echo \"Enter your Mac password to finish installing.\"",
                "&& ~/.local/bin/agent-vault setup --print-only | /usr/bin/grep \"^sudo \" | /bin/sh",
                "&& echo && echo \"Now choose a passphrase. You will need it to approve what agents may do.\"",
                "&& \(v) passphrase set",
                "&& echo && echo \"Finished. You can close this window.\"",
                "|| echo \"Setup did not finish. Choose Set up agent-vault in the companion to try again.\"",
            ].joined(separator: " ")
        case .passphraseInTerminal:
            body = [
                "echo \"Choose a passphrase for agent-vault. You will need it to approve what agents may do.\"; echo;",
                "\(v) passphrase set",
                "&& echo && echo \"Finished. You can close this window.\"",
                "|| echo \"The passphrase was not set. Choose it in the companion to try again.\"",
            ].joined(separator: " ")
        // The vault encrypts the file under a recovery passphrase it asks for,
        // and wants fresh proof of the human before it writes one.
        case .exportInTerminal:
            body = [
                "echo \"Saving your keys to an encrypted file on your Desktop.\";",
                "echo \"You will choose a recovery passphrase (12 or more characters). You need it to open the file on the other computer.\"; echo;",
                "\(v) backup export --out \(file)",
                "&& echo && echo \"Saved. Move agent-vault-backup.json to the other computer and bring it in there. Delete it once your keys are there.\"",
                "|| echo \"No file was saved.\"",
            ].joined(separator: " ")
        case .restoreInTerminal:
            body = [
                "echo \"Bringing in keys from agent-vault-backup.json on your Desktop.\";",
                "echo \"It asks for the recovery passphrase you chose when you saved the file. Keys you already have here are left as they are.\"; echo;",
                "\(v) backup restore \(file) --on-conflict skip",
                "&& echo && echo \"Done. Check your keys in the companion, then delete the file from your Desktop.\"",
                "|| echo \"Nothing was brought in. Keep the file and try again.\"",
            ].joined(separator: " ")
        // Nothing is asked unless the request could be shown.
        case .review(let id) where safeId(id):
            body = [
                "echo \"An agent is waiting for your decision. This is the summary the vault has of the request.\";",
                "echo \"Anything the agent wrote about its reasons is its own claim, not a checked fact.\"; echo;",
                "\(v) approvals --show \(id) || { echo; echo \"This request is no longer waiting, so there is nothing to decide.\"; \(close); exit 0; };",
                "echo; echo \"The vault page (Open the vault, in the companion) shows every detail of a request, if you want more than this summary.\";",
                "printf \"Type yes to approve, no to deny, or press Return to decide later: \"; \(ask);",
                "if [ \"$answer\" = yes ]; then \(v) approve \(id);",
                "elif [ \"$answer\" = no ]; then \(v) deny \(id);",
                "else echo \"Nothing was decided. The request is still waiting.\"; fi;",
                close,
            ].joined(separator: " ")
        case .start(let name) where safeId(name):
            body = [
                "echo \"Starting a session lets agents use the keys below until it ends.\"; echo;",
                "\(v) template show \(name) || { echo; echo \"That template could not be read, so no session was started.\"; \(close); exit 0; };",
                "echo; printf \"Type yes to start it: \"; \(ask);",
                "if [ \"$answer\" = yes ]; then \(v) session create --template \(name) || echo \"No session was started.\";",
                "else echo \"No session was started.\"; fi;",
                close,
            ].joined(separator: " ")
        case .newSession:
            body = "echo \"Choose which keys agents may use, and for how long.\"; echo; \(v) session create; \(close)"
        case .addKey:
            body = "echo \"Add a key. When you paste the key it is not shown on screen.\"; echo; \(v) cred add; \(close)"
        case .rotateKey(let slug) where safeId(slug):
            body = [
                "echo \"Replace the value of \(slug). Open sessions keep working, with the new value.\";",
                "echo \"When you paste the new key it is not shown on screen.\"; echo;",
                "\(v) cred rotate \(slug); \(close)",
            ].joined(separator: " ")
        case .releaseKey(let slug) where safeId(slug):
            body = [
                "echo \"Allow agents to use \(slug) again.\"; echo;",
                "printf \"Type yes to allow it: \"; \(ask);",
                "if [ \"$answer\" = yes ]; then \(v) cred release \(slug) || echo \"The key is still stopped.\";",
                "else echo \"The key is still stopped.\"; fi;",
                close,
            ].joined(separator: " ")
        case .unlock:
            body = "echo \"Unlock agent-vault with your passphrase.\"; echo; \(v) unlock; \(close)"
        case .enrollTouchIdInTerminal(let key, let label) where plainKey(key) && plainLabel(label) == label:
            body = [
                "echo \"Set up Touch ID in the agent-vault companion. Confirm it with your passphrase.\"; echo;",
                "\(v) companion enroll \(key) --label \"\(label)\"",
                "&& echo && echo \"Done. You can approve in the companion with Touch ID now.\"",
                "|| echo \"Touch ID was not set up. Try again from the companion.\";",
                close,
            ].joined(separator: " ")
        case .terminal(let inner):
            return inner.hasBothRoutes ? inner.terminalScript : nil
        default:
            return nil
        }
        // A single quote would end the quoted script early.
        guard !body.contains("'") else { return nil }
        return "/usr/bin/env -i HOME=$HOME USER=$USER TERM=$TERM PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/sh -c 'clear; \(body)'"
    }

    /// Whether the action can go to either place where the human proves
    /// presence: a page of the web UI, or a Terminal command.
    public var hasBothRoutes: Bool {
        if case .terminal = self { return false }
        return uiFragment != nil && terminalScript != nil
    }

    /// Whether a click on this action opens a Terminal window.
    public var opensTerminal: Bool {
        if case .terminal = self { return true }
        return uiFragment == nil && terminalScript != nil
    }

    /// What to ask before doing it, for the actions that take access away at once.
    public func confirm(_ snap: Snapshot) -> Confirm? {
        switch self {
        case .revoke(let sid):
            let label = snap.session(sid)?.label ?? sid
            return Confirm(
                title: "Revoke this session?",
                body: "“\(label)” ends now. Any agent using it loses access straight away.",
                ok: "Revoke"
            )
        case .stopKey(let slug):
            return Confirm(
                title: "Stop all use of this key?",
                body: "Agents lose “\(slug)” immediately, in every session. Allowing it again needs your confirmation in the vault.",
                ok: "Stop this key"
            )
        case .panic:
            return Confirm(
                title: "Revoke everything?",
                body: "Every session ends and every waiting request is denied. Agents lose all access until you open a new session.",
                ok: "Revoke everything"
            )
        default:
            return nil
        }
    }

    /// What to say once it worked. `nil` when the next refresh says it better.
    public func done(_ snap: Snapshot) -> String? {
        switch self {
        case .revoke(let sid):
            return "Revoked “\(snap.session(sid)?.label ?? sid)”."
        case .panic:
            return "Every session is revoked and everything waiting was denied."
        case .connect(let agent):
            let name = agentName(agent)
            return "\(name) is connected. Restart \(name) so it picks up the vault."
        default:
            return nil
        }
    }
}

public struct Confirm: Equatable {
    public var title: String
    public var body: String
    public var ok: String
}

public func agentName(_ id: String) -> String {
    agents.first { $0.id == id }?.name ?? "The agent"
}

// MARK: - First run

/// What to say the first time the companion ever runs: where it lives, what it
/// found, and the one thing to do next.
public struct Welcome: Equatable {
    public var title: String
    public var body: String
    /// Offered as the main button, when there is something to do.
    public var next: (label: String, action: Action)?

    public static func == (a: Welcome, b: Welcome) -> Bool {
        a.title == b.title && a.body == b.body && a.next?.label == b.next?.label && a.next?.action == b.next?.action
    }
}

public func home(_ placement: Placement) -> String {
    switch placement {
    case .island:
        return "The companion lives in the notch at the top of your screen: move the pointer onto the notch to open it."
    case .menuBar:
        return "The companion lives in your menu bar, at the top right of the screen: look for the hexagon with a keyhole."
    }
}

public func welcome(_ snap: Snapshot, placement: Placement) -> Welcome? {
    let home = home(placement)
    switch snap.reach {
    case .loading:
        return nil
    case .missing(.notInstalled):
        return Welcome(
            title: "Welcome to agent-vault",
            body: "agent-vault keeps your API keys where AI agents can use them but never see them.\n\nIt is not set up on this computer yet. Setting it up takes about a minute: Terminal opens, asks for your Mac password, then asks you to choose a passphrase.\n\n\(home)",
            next: ("Set up now", .installInTerminal)
        )
    case .missing, .down:
        return Welcome(
            title: "agent-vault companion",
            body: "The companion could not reach agent-vault on this computer. It says why when you open it.\n\n\(home)",
            next: nil
        )
    case .up:
        let found: String
        if snap.unread.keys {
            found = "Found your vault on this computer."
        } else if snap.keys.isEmpty {
            found = "Found your vault on this computer. It has no keys yet."
        } else {
            found = "Found your vault on this computer, with \(count(snap.keys.count, "key"))."
        }
        let first: (String, Action)? = setupSteps(snap).lazy.compactMap { item -> (String, Action)? in
            if case .action(let action, let text) = item { return (text, action) }
            return nil
        }.first
        let nextLine = first == nil ? "" : "\n\nOne thing is left to finish setting up; the button below starts it."
        return Welcome(
            title: "agent-vault companion is running",
            body: "\(found)\n\n\(home) It shows what agents can use, tells you when one is waiting for you, and lets you stop access with a click.\(nextLine)",
            next: first.map { (label: trimEllipsis($0.0), action: $0.1) }
        )
    }
}

private func trimEllipsis(_ s: String) -> String {
    var s = s
    while s.hasSuffix("…") { s.removeLast() }
    return s
}

// MARK: - Items

/// One line of the companion's list, in the island or the menu bar menu.
public indirect enum Item: Equatable {
    case text(String)
    case action(Action, String)
    case check(Action, String, Bool)
    case separator
    case submenu(String, [Item])
}

// MARK: - Parsing

private let isoPlain: ISO8601DateFormatter = {
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime]
    return f
}()

private let isoFractional: ISO8601DateFormatter = {
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return f
}()

public func parseTime(_ v: JSON?) -> Date? {
    guard let s = v?.string else { return nil }
    return isoPlain.date(from: s) ?? isoFractional.date(from: s)
}

public func parseStatus(_ data: JSON) -> Status? {
    guard let version = data["daemon_version"]?.string else { return nil }
    return Status(version: cleanText(version, 20), locked: data["locked"]?.bool ?? false)
}

/// Live sessions only. The daemon can still list a session as `active` after
/// its expiry has passed, so the companion checks the clock itself.
public func parseSessions(_ data: JSON, now: Date) -> [Session] {
    guard let rows = data.array else { return [] }
    return rows.compactMap { row in
        guard let id = row["id"]?.string, safeId(id), row["state"]?.string == "active" else { return nil }
        let infinite = row["infinite"]?.bool ?? false
        let expiresAt = parseTime(row["expires_at"])
        if !infinite, let t = expiresAt, t <= now { return nil }
        let grants = row["creds"]?.array ?? []
        let creds = grants.compactMap { $0["slug"]?.string }.map { cleanText($0, 32) }
        let label = row["label"]?.string.map { cleanText($0, 32) }.flatMap { $0.isEmpty ? nil : $0 } ?? id
        return Session(
            id: id, label: label, creds: creds, expiresAt: expiresAt, infinite: infinite,
            mode: sessionMode(grants)
        )
    }
}

/// One sentence on what agents may do, from the session's grants. When the
/// grants differ, the most permissive one is the one worth telling.
func sessionMode(_ grants: [JSON]) -> String {
    func readOnly(_ g: JSON) -> Bool {
        guard let methods = g["methods"]?.array, !methods.isEmpty else { return false }
        return methods.allSatisfy { ["GET", "HEAD", "OPTIONS"].contains($0.string ?? "") }
    }
    if grants.isEmpty { return "Access details unknown" }
    if grants.allSatisfy(readOnly) { return "Agents can only read" }
    let approvals = grants.filter { !readOnly($0) }.map { $0["approval"]?.string ?? "" }
    if approvals.contains("auto") { return "Agents can make changes without asking" }
    if approvals.contains("first-use") { return "Agents ask you once, then make changes" }
    if approvals.allSatisfy({ $0 == "on-write" || $0 == "each" }) { return "Agents ask you before every change" }
    return "Access details unknown"
}

/// Ids, kinds and ages only. `headline` and `claim` are left behind on
/// purpose: the claim is written by the agent and is never shown.
public func parsePending(_ data: JSON) -> [Pending] {
    guard let rows = data.array else { return [] }
    return rows.compactMap { row in
        guard let id = row["id"]?.string, safeId(id) else { return nil }
        let kind = row["kind"]?.string ?? ""
        return Pending(id: id, kind: kind, createdAt: parseTime(row["created_at"]), facts: pendingFacts(kind, row))
    }
}

/// The facts the island shows for a request: for a session request, what was
/// proposed (keys, methods, paths, limits, how long), as the vault recorded
/// it; for a held request, the vault's summary of what would be sent. The
/// agent's reason (`claim`) is never among them.
public func pendingFacts(_ kind: String, _ row: JSON) -> [Fact] {
    var out: [Fact] = []
    func list(_ v: JSON?) -> String? {
        if let s = v?.string { return cleanText(s, 80) }
        guard let a = v?.array, !a.isEmpty else { return nil }
        return cleanText(a.compactMap { $0.string ?? number($0) }.joined(separator: ", "), 80)
    }
    func number(_ v: JSON?) -> String? {
        if case .number(let n)? = v { return n == n.rounded() ? String(Int(n)) : String(n) }
        return nil
    }
    if kind == "session" {
        let p = row["proposal"] ?? .object([:])
        if let keys = list(p["creds"]) ?? list(p["cred"]) { out.append(Fact("Keys", keys)) }
        if let m = list(p["methods"]) { out.append(Fact("Methods", m)) }
        if let paths = list(p["paths"]) { out.append(Fact("Paths", paths)) }
        if p["infinite"]?.bool == true {
            out.append(Fact("Ends", "never (asked for no expiry)"))
        } else if let h = number(p["ttl_hours"]) {
            out.append(Fact("Ends", "after \(h) h"))
        }
        if let b = number(p["budget"]) { out.append(Fact("Requests", "up to \(b)")) }
        if let u = number(p["uses"]) { out.append(Fact("Uses", "up to \(u)")) }
        if let a = p["approval"]?.string {
            let said: String
            switch a {
            case "auto": said = "never (changes without asking)"
            case "first-use": said = "once, then not again"
            case "on-write", "each": said = "before every change"
            default: said = cleanText(a, 20)
            }
            out.append(Fact("Asks you", said))
        }
        if case .object(let o) = p {
            let shown: Set<String> = ["creds", "cred", "methods", "paths", "infinite", "ttl_hours", "budget", "uses", "approval", "label"]
            let more = o.keys.filter { !shown.contains($0) }.count
            if more > 0 { out.append(Fact("Also", "\(count(more, "more setting")); the vault page shows them")) }
        }
    } else if kind == "request" {
        if let h = row["headline"]?.string { out.append(Fact("Would send", cleanText(h, 120))) }
        let preview = row["preview"]
        let type = preview?["content_type"]?.string ?? preview?["body"]?["kind"]?.string
        if let type, let bytes = number(preview?["body"]?["bytes"]) {
            out.append(Fact("Body", "\(cleanText(type, 40)) · \(bytes) bytes"))
        }
    }
    return out
}

public func parseCompanionStatus(_ data: JSON) -> Enrollment? {
    parseEnrollment(data)
}

public func parseTemplates(_ data: JSON) -> [String] {
    (data.array ?? []).compactMap { $0["name"]?.string }.filter(safeId)
}

/// Names, services and health. Never a value: the CLI's list has none.
public func parseKeys(_ data: JSON) -> [Key] {
    guard let rows = data.array else { return [] }
    return rows.compactMap { row in
        guard let slug = row["slug"]?.string, safeId(slug) else { return nil }
        let health: Health
        switch row["health"]?["status"]?.string {
        case "ok": health = .ok
        case .some: health = .problem
        case .none: health = .unknown
        }
        return Key(
            slug: slug,
            service: serviceName(kind: row["kind"]?.string ?? "", host: row["connector"]?["host"]?.string ?? ""),
            health: health,
            stopped: row["quarantine"].isSet,
            expiring: row["expiry_warning"].isSet
        )
    }
}

public func serviceName(kind: String, host: String) -> String {
    switch kind {
    case "anthropic": return "Anthropic"
    case "openai": return "OpenAI"
    case "google-genai": return "Google Gemini"
    case "github": return "GitHub"
    case "slack": return "Slack"
    default:
        let host = cleanText(host, 40)
        return host.isEmpty ? "Other service" : host
    }
}

/// `doctor`'s "human factor enrolled" line: whether a passphrase is set.
public func parseSetup(_ doctor: JSON) -> Setup {
    guard let row = doctor.array?.first(where: { $0["name"]?.string == "human factor enrolled" }) else {
        return Setup()
    }
    let ok = row["ok"]?.bool ?? false
    let note = row["note"]?.string ?? ""
    return Setup(passphrase: ok && note.contains("passphrase"))
}

/// What one key's check came to.
public enum Probe: Equatable {
    case passed, failed
    /// The vault has no test for this kind of service.
    case untestable
    /// The key is stopped, so the vault refused to use it.
    case stopped
    /// The vault's own limits refused the check for now.
    case limited
}

/// The results of `cred test --all`, from that run itself. `nil` when the
/// reply has no results to read.
public func parseKeyTest(_ data: JSON) -> [(slug: String, probe: Probe)]? {
    guard let rows = data["results"]?.array else { return nil }
    return rows.compactMap { r in
        guard let slug = r["slug"]?.string, safeId(slug) else { return nil }
        let probe: Probe
        if r["ok"]?.bool == true {
            probe = .passed
        } else if r["rule"]?.string == "no_probe" {
            probe = .untestable
        } else {
            switch r["error"]?.string {
            case "AV_QUARANTINED": probe = .stopped
            case "AV_QUOTA_EXCEEDED": probe = .limited
            default: probe = .failed
            }
        }
        return (slug, probe)
    }
}

public func keyReport(_ results: [(slug: String, probe: Probe)]) -> String {
    func names(_ want: Probe) -> [String] { results.filter { $0.probe == want }.map(\.slug) }
    let tested = results.filter { $0.probe == .passed || $0.probe == .failed }.count
    var lines: [String] = []
    if tested == 0 {
        lines.append("No key could be checked.")
    } else {
        lines.append("\(names(.passed).count) of \(count(tested, "checked key")) passed.")
    }
    let failed = names(.failed)
    if !failed.isEmpty {
        lines.append("Failed: \(failed.joined(separator: ", ")). A failed key may have expired or been revoked.")
    }
    let untestable = names(.untestable)
    if !untestable.isEmpty {
        lines.append("No automatic check exists for: \(untestable.joined(separator: ", ")).")
    }
    let stopped = names(.stopped)
    if !stopped.isEmpty {
        lines.append("Stopped, so not checked: \(stopped.joined(separator: ", ")).")
    }
    let limited = names(.limited)
    if !limited.isEmpty {
        lines.append("Not checked this time (the vault limits how often): \(limited.joined(separator: ", ")).")
    }
    return lines.joined(separator: "\n")
}

/// Whether `mcp install --print` reports the vault as already written into an
/// agent's config.
public func parseConnected(_ data: JSON) -> Bool? {
    data["unchanged"]?.bool
}

// MARK: - What is shown

/// Text beside the menu bar icon: the number waiting, or nothing.
public func trayTitle(_ snap: Snapshot) -> String? {
    if snap.unread.pending && snap.reach.isUp { return "?" }
    return snap.pending.isEmpty ? nil : String(snap.pending.count)
}

public func tooltip(_ snap: Snapshot) -> String {
    switch snap.reach {
    case .up where !snap.pending.isEmpty:
        return "agent-vault: \(snap.pending.count) waiting for you"
    case .up(let s) where s.locked:
        return "agent-vault: locked"
    case .up where !snap.sessions.isEmpty:
        return "agent-vault: \(count(snap.sessions.count, "session")) open"
    case .up, .loading:
        return "agent-vault"
    case .down:
        return "agent-vault: not reachable"
    case .missing:
        return "agent-vault: not set up"
    }
}

/// What the closed island shows beside the notch. `nil` when there is nothing
/// to say, and the island is just the notch.
public enum Badge: Equatable {
    /// Requests waiting for the human.
    case waiting(Int)
    /// The list of waiting requests could not be read.
    case unknownWaiting
    case locked
    /// A session ends within ten minutes.
    case ending(minutes: Int)
    case unreachable
    case notSetUp
    case untrusted
}

public let endingSoonMinutes = 10

public func badge(_ snap: Snapshot, now: Date) -> Badge? {
    switch snap.reach {
    case .loading, .missing(.unsupported):
        return nil
    case .missing(.notInstalled):
        return .notSetUp
    case .missing(.untrusted):
        return .untrusted
    case .down:
        return .unreachable
    case .up(let status):
        if snap.unread.pending { return .unknownWaiting }
        if !snap.pending.isEmpty { return .waiting(snap.pending.count) }
        if status.locked { return .locked }
        let soonest = snap.sessions
            .filter { !$0.infinite }
            .compactMap { $0.expiresAt?.timeIntervalSince(now) }
            .filter { $0 > 0 && $0 <= Double(endingSoonMinutes * 60) }
            .min()
        if let left = soonest { return .ending(minutes: max(1, Int((left + 59) / 60))) }
        return nil
    }
}

public func menu(_ snap: Snapshot, prefs: Prefs, now: Date) -> [Item] {
    var items: [Item] = []
    switch snap.reach {
    case .loading:
        items.append(.text("Checking agent-vault…"))
    case .missing(.notInstalled):
        items.append(.text("agent-vault is not set up on this computer"))
        items.append(.action(.installInTerminal, "Set up agent-vault…"))
        items.append(.text("It asks for your Mac password, then a new passphrase"))
    case .missing(.unsupported):
        items.append(.text("agent-vault does not run on this operating system yet"))
    case .missing(.untrusted(let why)):
        items.append(.text("This agent-vault install cannot be trusted"))
        items.append(.text(cleanText(why, 70)))
    case .down(let why):
        items.append(.text("agent-vault is not answering"))
        items.append(.text(cleanText(why, 60)))
    case .up(let status):
        upMenu(&items, snap, status, now)
    }
    items.append(.separator)
    items.append(.submenu("Settings", settingsMenu(snap, prefs)))
    items.append(.action(.refresh, "Refresh"))
    items.append(.action(.quit, "Quit companion"))
    return markTerminal(items, terminal: prefs.terminal)
}

/// Send the actions that have both routes to Terminal when that is how the
/// user approves, and say so on every item that opens a Terminal window, so
/// nothing does it by surprise.
func markTerminal(_ items: [Item], terminal: Bool) -> [Item] {
    items.map { item in
        switch item {
        case .action(var action, var text):
            if terminal && action.hasBothRoutes {
                action = .terminal(action)
            }
            if action.opensTerminal {
                text += " (opens Terminal)"
            }
            return .action(action, text)
        case .submenu(let text, let children):
            return .submenu(text, markTerminal(children, terminal: terminal))
        default:
            return item
        }
    }
}

func settingsMenu(_ snap: Snapshot, _ prefs: Prefs) -> [Item] {
    var items: [Item] = [
        .check(.toggleNotifications, "Show notifications", prefs.notifications),
        .check(.toggleAutostart, "Start at login", prefs.autostart),
        .check(.toggleTerminal, "Approve in Terminal with my passphrase", prefs.terminal),
    ]
    if snap.reach.isUp {
        items.append(.action(.touchIdInUi, "Set up Touch ID approvals…"))
        let linked: [Item] = snap.agents.isEmpty
            ? [.text("No supported agents found on this computer")]
            : snap.agents.map { a in
                a.connected ? .text("\(a.name) · connected") : .action(.connect(a.id), "Connect \(a.name)")
            }
        items.append(.submenu("Connect agents", linked))
    }
    return items
}

/// What is still left to do before the vault is useful and safe, most
/// important first. Empty when everything is in place.
public func setupSteps(_ snap: Snapshot) -> [Item] {
    var steps: [Item] = []
    if snap.setup.passphrase == false {
        steps.append(.action(.passphraseInTerminal, "Set your passphrase…"))
    }
    if snap.keys.isEmpty && !snap.unread.keys {
        steps.append(.action(.addKey, "Add your first key…"))
    }
    if !snap.agents.isEmpty && snap.agents.allSatisfy({ !$0.connected }) {
        for a in snap.agents {
            steps.append(.action(.connect(a.id), "Connect \(a.name)"))
        }
    }
    return steps
}

func upMenu(_ items: inout [Item], _ snap: Snapshot, _ status: Status, _ now: Date) {
    items.append(.text("agent-vault \(status.version) · \(status.locked ? "Locked" : "Unlocked")"))
    items.append(.separator)

    let steps = setupSteps(snap)
    if !steps.isEmpty {
        items.append(.text("Finish setting up (\(steps.count) left)"))
        items.append(contentsOf: steps)
        items.append(.separator)
    }

    // Waiting for the human.
    if snap.unread.pending {
        items.append(.text("Couldn't check what is waiting"))
    } else if snap.pending.isEmpty {
        items.append(.text("Nothing waiting for you"))
    } else {
        items.append(.text("Waiting for you (\(snap.pending.count))"))
        for p in snap.pending {
            let what: String
            switch p.kind {
            case "session": what = "An agent is asking for access"
            case "request": what = "An agent wants to make a change"
            default: what = "Something needs your decision"
            }
            let when = p.createdAt.map { " (\(ago($0, now)))" } ?? ""
            items.append(.action(.review(p.id), "\(what)\(when): review…"))
        }
    }
    items.append(.separator)

    // Sessions: what agents can use right now.
    if snap.unread.sessions {
        items.append(.text("Couldn't read open sessions"))
    } else if snap.sessions.isEmpty {
        items.append(.text("No open sessions: agents cannot use any key"))
    } else {
        items.append(.text("Open sessions (\(snap.sessions.count)): what agents can use now"))
        for s in snap.sessions {
            let ends = s.infinite ? "no expiry" : (s.expiresAt.map { until($0, now) } ?? "expiry unknown")
            let keys = s.creds.isEmpty ? "No keys listed" : "Keys: \(s.creds.joined(separator: ", "))"
            items.append(.submenu("\(s.label) · \(count(s.creds.count, "key")) · \(ends)", [
                .text(keys),
                .text(s.mode),
                .separator,
                .action(.revoke(s.id), "Revoke this session…"),
            ]))
        }
    }
    var start: [Item] = snap.templates.map { .action(.start($0), "From “\($0)”…") }
    if !start.isEmpty { start.append(.separator) }
    start.append(.action(.newSession, "Choose keys and limits…"))
    items.append(.submenu("Start a session", start))
    items.append(.separator)

    // Keys.
    if snap.unread.keys {
        items.append(.text("Couldn't read your keys"))
    } else if snap.keys.isEmpty {
        items.append(.text("No keys stored yet"))
    } else {
        items.append(.text("Keys (\(snap.keys.count))"))
        for k in snap.keys {
            items.append(keyItem(k, inUse: snap.inUse(k.slug)))
        }
    }
    items.append(.action(.addKey, "Add a key…"))
    if !snap.keys.isEmpty {
        items.append(.action(.testKeys, "Check that all keys still work"))
    }
    items.append(.separator)

    items.append(.submenu("Move keys to another computer", [
        .text("Uses an encrypted file on your Desktop"),
        .action(.exportInTerminal, "Save my keys to an encrypted file…"),
        .action(.restoreInTerminal, "Bring in keys from that file…"),
    ]))
    items.append(.action(.openUi, "Open the vault…"))
    if status.locked {
        items.append(.action(.unlock, "Unlock…"))
    } else {
        items.append(.action(.lock, "Lock the vault"))
    }
    items.append(.action(.panic, "Panic: revoke everything…"))
}

func keyItem(_ k: Key, inUse: Bool) -> Item {
    let mark: String, tail: String, detail: String
    if k.stopped {
        (mark, tail, detail) = ("⏸ ", "stopped", "Stopped: no agent can use this key")
    } else if k.health == .problem {
        (mark, tail, detail) = ("⚠ ", "last check failed", "The last check of this key failed")
    } else if k.expiring {
        (mark, tail, detail) = ("⚠ ", "expires soon", "This key expires soon")
    } else if inUse {
        (mark, tail, detail) = ("", "in use", "In use by an open session")
    } else if k.health == .ok {
        (mark, tail, detail) = ("", "ready", "Working at its last check; not in any open session")
    } else {
        (mark, tail, detail) = ("", "not checked yet", "Not checked yet; not in any open session")
    }
    let toggle: Item = k.stopped
        ? .action(.releaseKey(k.slug), "Allow this key again…")
        : .action(.stopKey(k.slug), "Stop all use of this key…")
    return .submenu("\(mark)\(k.slug) · \(k.service) · \(tail)", [
        .text(detail),
        .separator,
        .action(.rotateKey(k.slug), "Replace this key's value…"),
        toggle,
    ])
}

// MARK: - Small helpers

/// A public key as the companion passes it on: base64url of a DER SPKI.
public func plainKey(_ s: String) -> Bool {
    (60...200).contains(s.utf8.count) && !s.hasPrefix("-") && s.utf8.allSatisfy { b in
        (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A)
            || b == UInt8(ascii: "_") || b == UInt8(ascii: "-")
    }
}

/// Ids, slugs and template names the companion is willing to pass on. They
/// must start with a letter, digit or underscore, so one can never be read as
/// a command-line flag.
public func safeId(_ s: String) -> Bool {
    let bytes = Array(s.utf8)
    guard !bytes.isEmpty, bytes.count <= 128, bytes[0] != UInt8(ascii: "-"), bytes[0] != UInt8(ascii: ".") else {
        return false
    }
    return bytes.allSatisfy { b in
        (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A)
            || b == UInt8(ascii: "_") || b == UInt8(ascii: "-") || b == UInt8(ascii: ".")
    }
}

/// Text that came from the vault (labels, slugs, versions), made safe to show:
/// control and bidirectional-override characters removed, length capped.
public func cleanText(_ s: String, _ max: Int) -> String {
    let kept = s.unicodeScalars.filter { !isControl($0) && !isBidi($0) }
    let cleaned = String(String.UnicodeScalarView(kept)).trimmingCharacters(in: .whitespacesAndNewlines)
    if cleaned.count <= max { return cleaned }
    return String(cleaned.prefix(Swift.max(0, max - 1))) + "…"
}

private func isControl(_ c: Unicode.Scalar) -> Bool {
    c.properties.generalCategory == .control
}

private func isBidi(_ c: Unicode.Scalar) -> Bool {
    switch c.value {
    case 0x200E, 0x200F, 0x202A...0x202E, 0x2066...0x2069, 0x061C: return true
    default: return false
    }
}

/// encodeURIComponent, which is what the web UI's router decodes.
public func encodeComponent(_ s: String) -> String {
    var out = ""
    for b in s.utf8 {
        let c = Character(Unicode.Scalar(b))
        if (b < 0x80 && (c.isLetter || c.isNumber)) || "-_.!~*'()".utf8.contains(b) {
            out.append(c)
        } else {
            out += String(format: "%%%02X", b)
        }
    }
    return out
}

public func count(_ n: Int, _ noun: String) -> String {
    n == 1 ? "1 \(noun)" : "\(n) \(noun)s"
}

public func until(_ t: Date, _ now: Date) -> String {
    let s = Int(t.timeIntervalSince(now).rounded(.down))
    if s <= 0 { return "ending now" }
    if s < 3600 { return "ends in \((s + 59) / 60)m" }
    if s < 86_400 { return "ends in \(s / 3600)h \((s % 3600) / 60)m" }
    return "ends in \(s / 86_400)d"
}

public func ago(_ t: Date, _ now: Date) -> String {
    let s = max(0, Int(now.timeIntervalSince(t).rounded(.down)))
    if s < 60 { return "just now" }
    if s < 3600 { return "\(s / 60) min ago" }
    return "\(s / 3600) h ago"
}
