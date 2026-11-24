import Foundation
@testable import CompanionCore

func j(_ text: String) -> JSON {
    guard let v = JSON(text: text) else { fatalError("bad JSON in a test: \(text)") }
    return v
}

func at(_ s: String) -> Date {
    parseTime(.string(s))!
}

let now = at("2026-11-20T12:00:00Z")

func up(_ locked: Bool) -> Reach {
    .up(Status(version: "0.4.0", locked: locked))
}

/// A vault with a bit of everything in it.
func busy() -> Snapshot {
    var snap = Snapshot(reach: up(false))
    snap.sessions = parseSessions(j("""
        [{"id":"s1","label":"keys-models","state":"active","expires_at":"2026-11-20T15:12:00Z",
          "creds":[{"slug":"openai-api","approval":"auto","methods":["GET","POST"]}]}]
        """), now: now)
    snap.pending = parsePending(j("""
        [{"id":"sr_1","kind":"session","created_at":"2026-11-20T11:58:00Z"},
         {"id":"ap_2","kind":"request"}]
        """))
    snap.templates = ["keys-all", "key-openai"]
    snap.keys = parseKeys(j("""
        [{"slug":"openai-api","kind":"openai","health":{"status":"ok"},"quarantine":null},
         {"slug":"anthropic-api","kind":"anthropic","health":{"status":"error"},"quarantine":null},
         {"slug":"hf","kind":"http","connector":{"host":"huggingface.co"},"health":null,"quarantine":{"reason":"x"}}]
        """))
    snap.setup = Setup(passphrase: true)
    snap.agents = [
        AgentLink(id: "claude-code", name: "Claude Code", connected: true),
        AgentLink(id: "codex", name: "Codex", connected: false),
    ]
    return snap
}

func allMenus() -> [[Item]] {
    var fresh = Snapshot(reach: up(true))
    fresh.setup = Setup(passphrase: false)
    fresh.agents = [AgentLink(id: "cursor", name: "Cursor", connected: false)]
    let snaps = [
        busy(),
        fresh,
        Snapshot(reach: .missing(.notInstalled)),
        Snapshot(reach: .missing(.untrusted("x"))),
        Snapshot(reach: .down("x")),
        Snapshot.loading(),
    ]
    var menus: [[Item]] = []
    for prefs in [Prefs(), Prefs(terminal: true)] {
        for snap in snaps {
            menus.append(menu(snap, prefs: prefs, now: now))
        }
    }
    return menus
}

/// Every line of text in a list, submenus included, one per line.
func texts(_ items: [Item]) -> String {
    var out = ""
    for item in items {
        switch item {
        case .text(let t), .action(_, let t), .check(_, let t, _):
            out += t + "\n"
        case .submenu(let t, let children):
            out += t + "\n" + texts(children)
        case .separator:
            break
        }
    }
    return out
}

func checks(_ items: [Item]) -> [(Action, Bool)] {
    items.flatMap { item -> [(Action, Bool)] in
        switch item {
        case .check(let a, _, let on): return [(a, on)]
        case .submenu(_, let children): return checks(children)
        default: return []
        }
    }
}

let terminalActions: [Action] = [
    .installInTerminal,
    .passphraseInTerminal,
    .exportInTerminal,
    .restoreInTerminal,
    .review("sr_01ABC"),
    .start("keys-all"),
    .newSession,
    .addKey,
    .rotateKey("openai-api"),
    .releaseKey("openai-api"),
    .unlock,
]

let shells: [String] = ["/bin/sh", "/bin/zsh", "/bin/bash"].filter { FileManager.default.fileExists(atPath: $0) }

/// Run a shell for real, feeding `input` and returning what it printed.
func shell(_ path: String, _ args: [String], input: String = "") -> (status: Int32, out: String, err: String) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: path)
    p.arguments = args
    let stdin = Pipe(), stdout = Pipe(), stderr = Pipe()
    p.standardInput = stdin
    p.standardOutput = stdout
    p.standardError = stderr
    try! p.run()
    stdin.fileHandleForWriting.write(Data(input.utf8))
    try? stdin.fileHandleForWriting.close()
    let out = stdout.fileHandleForReading.readDataToEndOfFile()
    let err = stderr.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return (p.terminationStatus, String(decoding: out, as: UTF8.self), String(decoding: err, as: UTF8.self))
}

/// Run a Terminal command for real, with a stand-in for the vault that prints
/// what it was asked to do, and the given typed answer. With `failsOn`, the
/// stand-in fails when its first word is that one.
func dryRun(_ action: Action, _ sh: String, typed: String, failsOn: String? = nil) -> String {
    let helper = FileManager.default.temporaryDirectory
        .appendingPathComponent("av-companion-test-\(ProcessInfo.processInfo.processIdentifier)-\(UUID().uuidString).sh")
    // $1 is the word to fail on; the rest is what the vault was asked.
    try! "fail=$1; shift; echo RAN \"$@\"; [ \"$1\" != \"$fail\" ]\n".write(to: helper, atomically: true, encoding: .utf8)
    defer { try? FileManager.default.removeItem(at: helper) }
    let standIn = "/bin/sh \(helper.path) \(failsOn ?? "nothing")"
    precondition(!standIn.contains("'") && !standIn.contains("\""))
    let script = action.terminalScript!.replacingOccurrences(of: "/var/db/agent-vault/app/bin/agent-vault", with: standIn)
    return shell(sh, ["-c", script], input: typed).out
}
