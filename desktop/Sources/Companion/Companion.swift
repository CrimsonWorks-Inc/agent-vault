import AppKit
import CompanionCore

/// The companion's state and everything it does. Main thread only, except for
/// the work it sends to its queues (CLI calls) and the watcher thread.
final class Companion: ObservableObject {
    @Published private(set) var snapshot = Snapshot.loading()
    @Published private(set) var prefs: Prefs
    /// What is shown, in the island or the menu bar menu: one list, so both
    /// offer the same actions under the same labels.
    @Published private(set) var items: [Item] = []
    @Published private(set) var now = Date()
    @Published var placement: Placement = .menuBar {
        didSet { if oldValue != placement { redraw() } }
    }
    /// Whether the island can approve with Touch ID right now.
    @Published private(set) var touchId: TouchId = .unavailable
    /// The last thing the island has to say: a result or why something failed.
    @Published var banner: Banner?
    /// What the island is waiting on (the vault, or Touch ID), if anything.
    @Published private(set) var working: String?
    /// macOS's Touch ID prompt is up: the island stays open under it.
    @Published private(set) var awaitingTouch = false
    /// Keys being checked against their services. A check runs on its own,
    /// so the island can close, and says how it went when it is done.
    @Published private(set) var checking: Set<String> = []

    struct Banner: Equatable {
        var text: String
        var failed: Bool
        var id = UUID()
    }

    /// Told about each notice as it is announced.
    var onNotice: ((Notice) -> Void)?
    /// Called before a dialog opens, and after a click hands work elsewhere.
    var beforeDialog: (() -> Void)?
    var afterAction: (() -> Void)?

    private var memo = Memo()
    private let refreshQueue = DispatchQueue(label: "agent-vault.companion.refresh")
    private let actionQueue = DispatchQueue(label: "agent-vault.companion.action")
    private var inFlight = false
    private var again = false
    private var timer: Timer?

    // Shared with the watcher thread and the action queue.
    private let lock = NSLock()
    private var stopping = false
    private var uiProcess: Process?
    private var watchProcess: Process?

    init() {
        var prefs = Preferences.load()
        prefs.autostart = LoginItem.isEnabled
        self.prefs = prefs
        redraw()
    }

    func start() {
        Notifier.prepare()
        timer = Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { [weak self] _ in self?.poke() }
        startWatcher()
        poke()
    }

    // MARK: Keeping what is shown current

    /// Ask for a refresh. Several in a row become one, plus one more if any
    /// arrived while a refresh was running.
    func poke() {
        if inFlight {
            again = true
            return
        }
        inFlight = true
        refreshQueue.async { [weak self] in
            let snap = Companion.gather()
            DispatchQueue.main.async { self?.apply(snap) }
        }
    }

    private func apply(_ snap: Snapshot) {
        inFlight = false
        guard !isStopping else { return }
        let now = Date()
        let said = notices(snapshot, snap, now: now, memo: &memo)
        snapshot = snap
        self.now = now
        touchId = CompanionCore.touchId(snap.enrollment, localKeyId: Enclave.keyId, available: Enclave.available,
                                        vaultTooOld: snap.companionUnsupported)
        redraw()
        for notice in said {
            tell(notice.text(placement))
            onNotice?(notice)
        }
        welcomeOnce()
        if again {
            again = false
            poke()
        }
    }

    private func redraw() {
        items = menu(snapshot, prefs: prefs, now: now)
    }

    static func gather() -> Snapshot {
        let cli: CLI
        switch CLI.locate() {
        case .success(let found): cli = found
        case .failure(let why): return Snapshot(reach: .missing(why))
        }
        let status: Status
        switch cli.run(["status"]) {
        case .success(let v):
            guard let s = parseStatus(v) else { return Snapshot(reach: .down("unexpected status reply")) }
            status = s
        case .failure(let e):
            return Snapshot(reach: .down(e.message))
        }
        let now = Date()
        var snap = Snapshot(reach: .up(status))
        switch cli.run(["session", "list"]) {
        case .success(let v): snap.sessions = parseSessions(v, now: now)
        case .failure: snap.unread.sessions = true
        }
        switch cli.run(["approvals"]) {
        case .success(let v): snap.pending = parsePending(v)
        case .failure: snap.unread.pending = true
        }
        switch cli.run(["template", "list"]) {
        case .success(let v): snap.templates = parseTemplates(v)
        case .failure: snap.unread.templates = true
        }
        switch cli.run(["cred", "list"]) {
        case .success(let v): snap.keys = parseKeys(v)
        case .failure: snap.unread.keys = true
        }
        if case .success(let v) = cli.run(["doctor"]) {
            snap.setup = parseSetup(v)
        }
        snap.agents = linkedAgents(cli)
        switch cli.run(["companion", "status"]) {
        case .success(let v): snap.enrollment = parseCompanionStatus(v)
        case .failure(let e): snap.companionUnsupported = e.message.contains("unknown command")
        }
        return snap
    }

    /// Agents found on this computer, and whether the vault is already written
    /// into each one's config. `mcp install --print` reports that without writing.
    private static func linkedAgents(_ cli: CLI) -> [AgentLink] {
        let home = FileManager.default.homeDirectoryForCurrentUser
        return agents.compactMap { agent in
            var isDir: ObjCBool = false
            let marker = home.appendingPathComponent(agentMarker(agent.id)).path
            guard FileManager.default.fileExists(atPath: marker, isDirectory: &isDir), isDir.boolValue else { return nil }
            guard case .success(let v) = cli.run(["mcp", "install", "--agent", agent.id, "--scope", "user", "--print"]),
                  let connected = parseConnected(v)
            else { return nil }
            return AgentLink(id: agent.id, name: agent.name, connected: connected)
        }
    }

    /// Wakes the refresher the moment the daemon reports a new request, so the
    /// island does not wait for the next 15-second tick.
    private func startWatcher() {
        Thread.detachNewThread { [self] in
            while !isStopping {
                // Looked up each time: the vault may be installed while we run.
                if case .success(let cli) = CLI.locate(), let watched = try? cli.watch() {
                    let (process, out) = watched
                    lock.lock()
                    watchProcess = process
                    let quit = stopping
                    lock.unlock()
                    // Quit may have run while the process was starting.
                    if quit {
                        process.terminate()
                        return
                    }
                    var lines = LineSplitter(cap: LineSplitter.cap)
                    var json = JSONLines()
                    while true {
                        let chunk = out.availableData
                        if chunk.isEmpty { break }
                        for line in lines.feed(chunk) {
                            if let v = json.push(line), v["data"]?["event"]?.string == "pending" {
                                DispatchQueue.main.async { self.poke() }
                            }
                        }
                    }
                    lock.lock()
                    watchProcess = nil
                    lock.unlock()
                    if process.isRunning { process.terminate() }
                    process.waitUntilExit()
                }
                // Not installed, locked or down: try again shortly.
                for _ in 0..<10 {
                    if isStopping { return }
                    Thread.sleep(forTimeInterval: 1)
                }
            }
        }
    }

    private var isStopping: Bool {
        lock.lock()
        defer { lock.unlock() }
        return stopping
    }

    /// Stop the companion's `watch` and `ui` processes. Safe to call twice.
    func shutdown() {
        lock.lock()
        stopping = true
        let running = [uiProcess, watchProcess].compactMap { $0 }
        uiProcess = nil
        watchProcess = nil
        lock.unlock()
        for p in running where p.isRunning {
            p.terminate()
            p.waitUntilExit()
        }
    }

    // MARK: Clicks

    func perform(_ action: Action) {
        switch action {
        case .quit:
            NSApp.terminate(nil)
            return
        case .refresh:
            poke()
            return
        case .toggleNotifications:
            prefs.notifications.toggle()
            Preferences.save(prefs)
            redraw()
            if prefs.notifications {
                tell("Notifications are on. This is what they look like.")
            }
            return
        case .toggleTerminal:
            prefs.terminal.toggle()
            Preferences.save(prefs)
            redraw()
            return
        case .toggleAutostart:
            do {
                try LoginItem.set(!LoginItem.isEnabled)
            } catch {
                fail("Could not change the login setting: \(error.localizedDescription)")
            }
            prefs.autostart = LoginItem.isEnabled
            redraw()
            return
        default:
            break
        }
        // Where the human proves presence. The item already carries its
        // route, so a click does what its label said.
        if case .terminal = action {
            guard let script = action.terminalScript else {
                fail("That is not available right now.")
                return
            }
            openTerminal(script)
            return
        }
        if let fragment = action.uiFragment {
            openUI(fragment)
            return
        }
        if let script = action.terminalScript {
            openTerminal(script)
            return
        }
        guard let args = action.cliArgs else { return }
        let snap = snapshot
        if let ask = action.confirm(snap), !confirm(ask) { return }
        guard case .success(let cli) = CLI.locate() else {
            fail("agent-vault is not available right now.")
            return
        }
        let ending: [String]
        switch action {
        case .revoke(let sid): ending = [sid]
        case .panic: ending = snap.sessions.map(\.id)
        default: ending = []
        }
        memo.endedByUser(ending)
        afterAction?()
        let limit = action == .testKeys ? CLI.slow : CLI.timeout
        actionQueue.async { [weak self] in
            let reply = cli.run(args, timeout: limit)
            DispatchQueue.main.async {
                guard let self else { return }
                switch reply {
                case .failure(let e):
                    self.memo.notEnded(ending)
                    self.fail(e.message)
                case .success(let v):
                    if action == .testKeys {
                        // From this run's own results, never from the stored
                        // health, which can be older than the check just asked for.
                        let report = parseKeyTest(v).map(keyReport)
                            ?? "The check ran, but its results could not be read. Open the vault to see them."
                        self.alert("Key check", report, style: .informational)
                    } else if let text = action.done(snap) {
                        self.tell(text)
                    }
                }
                self.poke()
            }
        }
    }

    private func openTerminal(_ script: String) {
        afterAction?()
        if let why = TerminalWindow.open(script) {
            fail(why)
        }
        poke()
    }

    /// Open the vault's web UI on one page. Each link works once, so a fresh
    /// UI process is started each time and the previous one is stopped.
    private func openUI(_ fragment: String) {
        let cli: CLI
        switch CLI.locate() {
        case .success(let found): cli = found
        case .failure(.notInstalled): return fail("agent-vault is not set up on this computer yet.")
        case .failure(.unsupported): return fail("agent-vault does not run on this operating system yet.")
        case .failure(.untrusted(let why)): return fail(why)
        }
        afterAction?()
        actionQueue.async { [weak self] in
            guard let self else { return }
            self.lock.lock()
            let old = self.uiProcess
            self.uiProcess = nil
            self.lock.unlock()
            if let old, old.isRunning {
                old.terminate()
                old.waitUntilExit()
            }
            let started = cli.ui()
            DispatchQueue.main.async {
                switch started {
                case .failure(let e):
                    self.fail(e.message.contains("in use")
                        ? "The vault is already open from a terminal. Use that browser tab, or close it and try again."
                        : e.message)
                case .success(let (process, url)):
                    self.lock.lock()
                    let quit = self.stopping
                    let other = quit ? nil : self.uiProcess
                    if !quit { self.uiProcess = process }
                    self.lock.unlock()
                    other?.terminate()
                    if quit {
                        process.terminate()
                        return
                    }
                    // LaunchServices hands the link to the browser, so it never
                    // sits in another process's arguments.
                    guard let link = URL(string: url + fragment), NSWorkspace.shared.open(link) else {
                        self.fail("The browser did not open.")
                        return
                    }
                }
            }
        }
    }

    // MARK: The island's own actions

    /// Where a change that needs the human goes from the island: Touch ID
    /// right here when it is set up, otherwise the vault page or Terminal (the
    /// user's setting), exactly as from the menu.
    enum Route: Equatable {
        case touchId(SignedRequest)
        case handoff(Action)
    }

    func route(_ signed: SignedRequest?, otherwise fallback: Action) -> Route {
        if touchId == .ready, let signed, signed.args != nil {
            return .touchId(signed)
        }
        return .handoff(prefs.terminal && fallback.hasBothRoutes ? .terminal(fallback) : fallback)
    }

    /// Do a change with Touch ID: the vault's challenge for this exact
    /// request, checked against what the user chose, then the fingerprint,
    /// then the request with its proof. `value` is a key's value, for adding
    /// or replacing one; it goes to the CLI on stdin only.
    func runSigned(_ request: SignedRequest, value: String? = nil, done: ((Bool) -> Void)? = nil) {
        guard working == nil else { return }
        guard let args = request.args else { return say("That is not available right now.", failed: true) }
        if request.takesValue && (value ?? "").isEmpty { return say("Paste the key's value first.", failed: true) }
        guard case .success(let cli) = CLI.locate() else {
            return say("agent-vault is not available right now.", failed: true)
        }
        working = "Asking the vault…"
        let valueLine = request.takesValue ? (value ?? "") + "\n" : nil
        actionQueue.async { [weak self] in
            let outcome = Companion.signAndSend(cli, request, args, valueLine) { stage in
                DispatchQueue.main.async {
                    self?.working = stage
                    self?.awaitingTouch = stage == Companion.touchStage
                }
            }
            DispatchQueue.main.async {
                guard let self else { return }
                self.working = nil
                self.awaitingTouch = false
                switch outcome {
                case .success:
                    self.say(request.done, failed: false)
                    done?(true)
                case .failure(let why):
                    self.say(why.message, failed: true)
                    done?(false)
                }
                self.poke()
            }
        }
    }

    static let touchStage = "Waiting for Touch ID…"

    private static func signAndSend(
        _ cli: CLI, _ request: SignedRequest, _ args: [String], _ valueLine: String?,
        stage: (String) -> Void
    ) -> Result<Void, Failure> {
        let issued: JSON
        switch cli.run(args + ["--companion-challenge"], input: valueLine ?? "") {
        case .success(let v): issued = v
        case .failure(let e): return .failure(e)
        }
        guard let challenge = parseChallenge(issued) else {
            return .failure(Failure("The vault's challenge could not be read, so nothing was signed."))
        }
        // Never sign something other than what was clicked.
        guard request.matches(challenge.operation) else {
            return .failure(Failure("The vault asked to sign something other than what you chose, so nothing was signed."))
        }
        stage(touchStage)
        let signature: Data
        switch Enclave.sign(signedMessage(challenge: challenge.challenge), reason: request.reason) {
        case .success(let s): signature = s
        case .failure(.cancelled): return .failure(Failure("Cancelled. Nothing was changed."))
        case .failure(.noKey): return .failure(Failure("Touch ID is not set up in the companion on this Mac."))
        case .failure(.failed(let why)): return .failure(Failure("Touch ID did not sign: \(why)"))
        }
        stage("Sending…")
        let input = presenceLine(challengeId: challenge.id, signature: signature) + "\n" + (valueLine ?? "")
        switch cli.run(args + ["--presence-stdin"], input: input) {
        case .success: return .success(())
        case .failure(let e): return .failure(e)
        }
    }

    /// A change that only takes access away, already confirmed in the island.
    func runConfirmed(_ action: Action) {
        guard let args = action.cliArgs else { return perform(action) }
        guard case .success(let cli) = CLI.locate() else {
            return say("agent-vault is not available right now.", failed: true)
        }
        let snap = snapshot
        let ending: [String]
        switch action {
        case .revoke(let sid): ending = [sid]
        case .panic: ending = snap.sessions.map(\.id)
        default: ending = []
        }
        memo.endedByUser(ending)
        working = "Working…"
        let limit = action == .testKeys ? CLI.slow : CLI.timeout
        actionQueue.async { [weak self] in
            let reply = cli.run(args, timeout: limit)
            DispatchQueue.main.async {
                guard let self else { return }
                self.working = nil
                switch reply {
                case .failure(let e):
                    self.memo.notEnded(ending)
                    self.say(e.message, failed: true)
                case .success(let v):
                    if action == .testKeys {
                        self.say(parseKeyTest(v).map(keyReport) ?? "The check ran, but its results could not be read.", failed: false)
                    } else {
                        let said: String
                        switch action {
                        case .lock: said = "The vault is locked. Agents cannot use any key until you unlock it."
                        case .stopKey(let slug): said = "Stopped “\(slug)”. No agent can use it."
                        default: said = action.done(snap) ?? "Done."
                        }
                        self.say(said, failed: false)
                    }
                }
                self.poke()
            }
        }
    }

    /// Check one key against its own service, and say how it went.
    func checkKey(_ slug: String) {
        guard !checking.contains(slug), let args = Action.testKey(slug).cliArgs,
              case .success(let cli) = CLI.locate() else { return }
        checking.insert(slug)
        // Its own queue: a slow service never holds up anything else.
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let reply = cli.run(args, timeout: 30)
            DispatchQueue.main.async {
                guard let self else { return }
                self.checking.remove(slug)
                switch reply {
                case .failure(let e): self.say(e.message, failed: true)
                case .success(let v): self.say(parseKeyTest(v).map(keyReport) ?? "The check ran, but its results could not be read.", failed: false)
                }
                self.poke()
            }
        }
    }

    /// What a template would start, for the island to show before Touch ID.
    func template(_ name: String, done: @escaping (Result<[Fact], Failure>) -> Void) {
        guard safeId(name), case .success(let cli) = CLI.locate() else {
            return done(.failure(Failure("That template cannot be read.")))
        }
        actionQueue.async {
            let reply = cli.run(["template", "show", name]).map { v -> [Fact] in
                let spec = v["spec"] ?? v["template"] ?? v
                return pendingFacts("session", .object(["proposal": spec]))
            }
            DispatchQueue.main.async { done(reply) }
        }
    }

    /// Set up Touch ID in the island: make this Mac's Secure Enclave key, then
    /// open Terminal on `companion enroll`, where the passphrase is typed.
    func setUpTouchId() {
        guard Enclave.available else {
            return say("This Mac has no fingerprint reader with a finger enrolled, so approvals stay in the vault page or Terminal.", failed: true)
        }
        do {
            let spki = try Enclave.ensureKey()
            let label = plainLabel(Host.current().localizedName ?? "Mac")
            perform(.enrollTouchIdInTerminal(base64url(spki), label))
        } catch {
            say("The Secure Enclave key could not be made: \(error.localizedDescription)", failed: true)
        }
    }

    /// Turn Touch ID in the island off: with Touch ID, the vault forgets this
    /// Mac's key; then the key itself is deleted.
    func turnOffTouchId() {
        guard touchId == .ready else {
            Enclave.remove()
            poke()
            return
        }
        runSigned(.removeTouchId) { ok in
            if ok { Enclave.remove() }
        }
    }

    /// Put a result or a failure where the user is looking: the island, or
    /// for the menu bar a notification or a dialog.
    func say(_ text: String, failed: Bool) {
        if placement == .island {
            banner = Banner(text: text, failed: failed)
        } else if failed {
            fail(text)
        } else {
            tell(text)
        }
    }

    // MARK: Telling the user

    /// The first time the companion ever runs, say where it lives and what it
    /// found, and offer the one next step (setting the vault up, if it is missing).
    private func welcomeOnce() {
        guard !prefs.welcomed, let w = welcome(snapshot, placement: placement) else { return }
        prefs.welcomed = true
        Preferences.save(prefs)
        DispatchQueue.main.async { [self] in
            let a = NSAlert()
            a.messageText = w.title
            a.informativeText = w.body
            a.alertStyle = .informational
            if let next = w.next {
                a.addButton(withTitle: next.label)
                a.addButton(withTitle: "Later")
                if run(a) == .alertFirstButtonReturn {
                    perform(next.action)
                    poke()
                }
            } else {
                a.addButton(withTitle: "OK")
                _ = run(a)
            }
        }
    }

    private func confirm(_ ask: Confirm) -> Bool {
        let a = NSAlert()
        a.messageText = ask.title
        a.informativeText = ask.body
        a.alertStyle = .warning
        a.addButton(withTitle: ask.ok)
        a.addButton(withTitle: "Cancel")
        return run(a) == .alertFirstButtonReturn
    }

    /// A dialog, for results and errors the user must not miss whatever their
    /// notification settings are.
    private func alert(_ title: String, _ body: String, style: NSAlert.Style) {
        let a = NSAlert()
        a.messageText = title
        a.informativeText = body
        a.alertStyle = style
        a.addButton(withTitle: "OK")
        _ = run(a)
    }

    private func fail(_ why: String) {
        alert("That did not work", why, style: .critical)
    }

    private func run(_ alert: NSAlert) -> NSApplication.ModalResponse {
        beforeDialog?()
        if #available(macOS 14, *) {
            NSApp.activate()
        } else {
            NSApp.activate(ignoringOtherApps: true)
        }
        return alert.runModal()
    }

    /// A notification, when the user has them on.
    private func tell(_ body: String) {
        guard prefs.notifications else { return }
        Notifier.post(body)
    }
}
