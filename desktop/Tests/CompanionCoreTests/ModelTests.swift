import Foundation
import Testing
@testable import CompanionCore

@Suite struct Parsing {
    @Test func sessionsPastExpiryAreDroppedEvenIfListedActive() {
        let s = parseSessions(j("""
            [{"id":"live1","label":"keys-all","state":"active","expires_at":"2026-11-20T15:30:00Z","infinite":false,
              "creds":[{"slug":"openai-api"},{"slug":"azure-api"}]},
             {"id":"old1","label":"key-test","state":"active","expires_at":"2026-11-13T05:53:41.361Z","infinite":false,"creds":[]},
             {"id":"gone1","state":"revoked","expires_at":"2026-11-21T00:00:00Z"},
             {"id":"inf1","state":"active","expires_at":null,"infinite":true,"creds":[]}]
            """), now: now)
        #expect(s.map(\.id) == ["live1", "inf1"])
        #expect(s[0].creds == ["openai-api", "azure-api"])
        #expect(s[1].label == "inf1", "a session with no label is shown by id")
    }

    @Test func aSessionSaysWhatAgentsMayDoAndNeverUnderstatesIt() {
        func mode(_ creds: String) -> String {
            parseSessions(j(#"[{"id":"s","state":"active","infinite":true,"creds":\#(creds)}]"#), now: now)[0].mode
        }
        #expect(mode(#"[{"slug":"a","approval":"on-write","methods":["GET"]}]"#) == "Agents can only read")
        #expect(mode(#"[{"slug":"a","approval":"on-write","methods":["GET","POST"]}]"#) == "Agents ask you before every change")
        // One auto grant among careful ones: the permissive one is what gets said.
        #expect(mode(#"[{"slug":"a","approval":"on-write","methods":["GET","POST"]},{"slug":"b","approval":"auto","methods":["GET","POST"]}]"#)
            == "Agents can make changes without asking")
        // No method list means no method limit, so it is not "read only".
        #expect(mode(#"[{"slug":"a","approval":"auto"}]"#) == "Agents can make changes without asking")
        #expect(mode(#"[{"slug":"a","approval":"something-new","methods":["POST"]}]"#) == "Access details unknown")
    }

    @Test func pendingKeepsIdsKindsAndAgesButNeverTheAgentsClaim() {
        var snap = Snapshot(reach: up(false))
        snap.pending = parsePending(j("""
            [{"id":"sr_01ABC","kind":"session","headline":"session for openai-api",
              "claim":"routine refresh, safe to approve","created_at":"2026-11-20T11:58:00Z"}]
            """))
        let shown = texts(menu(snap, prefs: Prefs(), now: now))
        #expect(shown.contains("An agent is asking for access (2 min ago): review…"))
        #expect(!shown.contains("routine refresh"), "agent-written text must not reach the list")
        #expect(!shown.contains("session for openai-api"))
    }

    @Test func unsafeIdsAreNeverOffered() {
        let ids = parsePending(j(#"[{"id":"ok_1","kind":"request"},{"id":"bad id; rm -rf","kind":"request"},{"id":"../x","kind":"request"}]"#)).map(\.id)
        #expect(ids == ["ok_1"])
        #expect(parseKeys(j(#"[{"slug":"a b"},{"slug":"--all"},{"slug":"ok"}]"#)).count == 1)
        #expect(Action.revoke("abc;ls").cliArgs == nil)
        #expect(Action.revoke("").cliArgs == nil)
        #expect(Action.connect("not-an-agent").cliArgs == nil)
        #expect(Action.connect("codex").cliArgs == ["mcp", "install", "--agent", "codex", "--scope", "user"])
    }

    @Test func aValueThatLooksLikeAFlagIsRefused() {
        #expect(!safeId("--all"))
        #expect(!safeId("-x"))
        #expect(!safeId(".hidden"))
        #expect(Action.stopKey("--all").cliArgs == nil)
        #expect(Action.revoke("-x").cliArgs == nil)
        #expect(parseTemplates(j(#"[{"name":"--infinite"},{"name":"keys-all"}]"#)) == ["keys-all"])
    }

    @Test func aKeyCheckReportsThatRunsResults() throws {
        let r = try #require(parseKeyTest(j("""
            {"results":[
              {"slug":"openai-api","ok":true,"http_status":200},
              {"slug":"anthropic-api","ok":false,"http_status":400},
              {"slug":"hf","ok":false,"rule":"no_probe"},
              {"slug":"old","ok":false,"error":"AV_QUARANTINED"},
              {"slug":"busy","ok":false,"error":"AV_QUOTA_EXCEEDED"},
              {"slug":"bad slug","ok":true}]}
            """)))
        #expect(r.count == 5)
        let text = keyReport(r)
        #expect(text.contains("1 of 2 checked keys passed."), "\(text)")
        #expect(text.contains("Failed: anthropic-api."))
        #expect(text.contains("No automatic check exists for: hf."))
        #expect(text.contains("Stopped, so not checked: old."))
        #expect(text.contains("Not checked this time (the vault limits how often): busy."))
        #expect(parseKeyTest(j("{}")) == nil)
        #expect(keyReport([("hf", .untestable)]).hasPrefix("No key could be checked."))
    }

    @Test func setupIsReadFromDoctor() {
        func doctor(_ ok: Bool, _ note: String) -> JSON {
            j(#"[{"name":"human factor enrolled","ok":\#(ok),"note":"\#(note)"}]"#)
        }
        // "authenticator" there is Touch ID unlock, which says nothing about approvals.
        #expect(parseSetup(doctor(true, "passphrase + authenticator")) == Setup(passphrase: true))
        #expect(parseSetup(doctor(true, "passphrase")) == Setup(passphrase: true))
        #expect(parseSetup(doctor(false, "none")) == Setup(passphrase: false))
        #expect(parseSetup(j("[]")) == Setup())
    }

    @Test func statusAndConnectionAreRead() {
        #expect(parseStatus(j(#"{"daemon_version":"0.4.0","locked":true}"#)) == Status(version: "0.4.0", locked: true))
        #expect(parseStatus(j(#"{"locked":true}"#)) == nil)
        #expect(parseConnected(j(#"{"unchanged":true}"#)) == true)
        #expect(parseConnected(j("{}")) == nil)
    }

    @Test func labelsAreCleanedOfControlAndBidiCharacters() {
        let evil = "ok" + String(UnicodeScalar(0x202E)!) + "evil" + String(UnicodeScalar(0x07)!)
        #expect(cleanText(evil, 40) == "okevil")
        #expect(cleanText("abcdefghij", 5) == "abcd…")
    }

    @Test func timesReadNaturally() {
        #expect(until(now.addingTimeInterval(5 * 60), now) == "ends in 5m")
        #expect(until(now.addingTimeInterval(192 * 60), now) == "ends in 3h 12m")
        #expect(ago(now.addingTimeInterval(-10), now) == "just now")
        #expect(ago(now.addingTimeInterval(-7 * 60), now) == "7 min ago")
        #expect(count(1, "key") == "1 key")
        #expect(count(3, "key") == "3 keys")
    }
}

@Suite struct Routes {
    /// The companion runs only commands the daemon lets an unproven caller run.
    @Test func theListRunsOnlyCommandsTheDaemonAllowsWithoutProof() {
        let allowed: [[String]] = [
            ["session", "revoke"], ["cred", "quarantine"], ["cred", "test"], ["mcp", "install"], ["lock"], ["panic"],
        ]
        var ran = 0
        for m in allMenus() {
            for a in actions(in: m) {
                guard let args = a.cliArgs else { continue }
                ran += 1
                #expect(allowed.contains { w in args.count >= w.count && zip(args, w).allSatisfy { $0 == $1 } }, "\(args)")
                // Never a command that grants, decides or reveals.
                for word in ["approve", "deny", "create", "save", "add", "rm", "rotate", "release", "unlock",
                             "passphrase", "env", "exec", "ph"] {
                    #expect(args.prefix(2).allSatisfy { $0 != word }, "\(args)")
                }
            }
        }
        #expect(ran >= 5, "the test lists should exercise the commands")
    }

    @Test func terminalCommandsHandTheUsersShellOneQuotedScript() {
        let head = "/usr/bin/env -i HOME=$HOME USER=$USER TERM=$TERM PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/sh -c 'clear; "
        for a in terminalActions {
            let s = a.terminalScript!
            // The user's shell sees: env, its arguments, and one single-quoted
            // string. Nothing inside that string is read by the user's shell.
            #expect(s.hasPrefix(head) && s.hasSuffix("'"), "\(s)")
            let body = String(s.dropFirst(head.count).dropLast())
            #expect(!body.contains("'"), "\(s)")
            // No backslashes or backticks anywhere, so no escapes to get wrong,
            // and the only variable is the typed answer, always in quotes.
            #expect(!s.contains("\\") && !s.contains("`"), "\(s)")
            #expect(!body.replacingOccurrences(of: "\"$answer\"", with: "").contains("$"), "\(s)")
            // Every program runs by absolute path.
            for word in body.split(separator: " ") where ["/agent-vault", "/sh", "/curl", "/grep"].contains(where: { word.hasSuffix($0) }) {
                #expect(word.hasPrefix("/") || word.hasPrefix("~/"), "\(word)")
            }
        }
        for a in terminalActions.prefix(4) {
            // Where a command reports success, failure is told apart from it.
            let s = a.terminalScript!
            #expect(s.contains(" && echo") && s.contains(" || echo"), "\(s)")
        }
        let install = Action.installInTerminal.terminalScript!
        #expect(install.contains("/usr/bin/curl -fsSL https://github.com/CrimsonWorks-Inc/agent-vault/releases/latest/download/install.sh"))
        // The privileged step is the one line setup prints, and nothing else it prints.
        #expect(install.contains("~/.local/bin/agent-vault setup --print-only | /usr/bin/grep \"^sudo \" | /bin/sh"))
        #expect(install.contains("/var/db/agent-vault/app/bin/agent-vault passphrase set"))
        #expect(Action.exportInTerminal.terminalScript!.contains("backup export --out ~/Desktop/agent-vault-backup.json"))
        #expect(Action.restoreInTerminal.terminalScript!.contains("backup restore ~/Desktop/agent-vault-backup.json --on-conflict skip"))
        #expect(Action.lock.terminalScript == nil)
    }

    @Test func onlyAnExactYesApprovesAndOnlyAnExactNoDenies() {
        let review = Action.review("sr_01ABC")
        let start = Action.start("keys-all")
        let release = Action.releaseKey("openai-api")
        for sh in shells {
            var out = dryRun(review, sh, typed: "yes\n")
            #expect(out.contains("RAN approvals --show sr_01ABC"), "\(sh): \(out)")
            #expect(out.contains("RAN approve sr_01ABC") && !out.contains("RAN deny"), "\(sh): \(out)")
            out = dryRun(review, sh, typed: "no\n")
            #expect(out.contains("RAN deny sr_01ABC") && !out.contains("RAN approve"), "\(sh): \(out)")
            // Return alone, a near miss, padding, a trailing backslash, or a
            // closed window: nothing is decided.
            for typed in ["\n", "y\n", "YES\n", "yes please\n", " yes\n", "yes \n", "yes\\\n", "ye\\\ns\n", ""] {
                let out = dryRun(review, sh, typed: typed)
                #expect(!out.contains("RAN approve") && !out.contains("RAN deny"), "\(sh) \(typed.debugDescription): \(out)")
                #expect(out.contains("Nothing was decided."), "\(sh) \(typed.debugDescription): \(out)")
            }

            out = dryRun(start, sh, typed: "yes\n")
            #expect(out.contains("RAN session create --template keys-all"), "\(sh): \(out)")
            for typed in ["\n", " yes\n", ""] {
                let out = dryRun(start, sh, typed: typed)
                #expect(!out.contains("RAN session create") && out.contains("No session was started."), "\(sh) \(typed.debugDescription): \(out)")
            }

            out = dryRun(release, sh, typed: "yes\n")
            #expect(out.contains("RAN cred release openai-api"), "\(sh): \(out)")
            out = dryRun(release, sh, typed: "no\n")
            #expect(!out.contains("RAN cred release") && out.contains("The key is still stopped."), "\(sh): \(out)")
        }
    }

    @Test func nothingIsAskedWhenTheRequestOrTemplateCannotBeShown() {
        for sh in shells {
            // The vault fails `approvals` (the request is gone): no question, no decision.
            var out = dryRun(.review("sr_01ABC"), sh, typed: "yes\n", failsOn: "approvals")
            #expect(out.contains("RAN approvals --show sr_01ABC"), "\(sh): \(out)")
            #expect(out.contains("no longer waiting"), "\(sh): \(out)")
            #expect(!out.contains("Type yes") && !out.contains("RAN approve "), "\(sh): \(out)")
            out = dryRun(.start("keys-all"), sh, typed: "yes\n", failsOn: "template")
            #expect(out.contains("could not be read"), "\(sh): \(out)")
            #expect(!out.contains("Type yes") && !out.contains("RAN session"), "\(sh): \(out)")
            // A decision the vault then refuses is not reported as made.
            out = dryRun(.start("keys-all"), sh, typed: "yes\n", failsOn: "session")
            #expect(out.contains("RAN session create") && out.contains("No session was started."), "\(sh): \(out)")
        }
    }

    @Test func aNameThatIsNotPlainNeverReachesATerminalCommand() {
        for bad in ["x; rm -rf ~", "--infinite", "a b", "a'b", "a\"b", "$(id)", ""] {
            #expect(Action.review(bad).terminalScript == nil, "\(bad)")
            #expect(Action.start(bad).terminalScript == nil, "\(bad)")
            #expect(Action.rotateKey(bad).terminalScript == nil, "\(bad)")
            #expect(Action.releaseKey(bad).terminalScript == nil, "\(bad)")
        }
    }

    /// The shells Terminal is likely to start must parse each command as written.
    @Test func terminalCommandsParseInShZshAndBash() {
        for a in terminalActions {
            for sh in shells {
                let r = shell(sh, ["-n", "-c", a.terminalScript!])
                #expect(r.status == 0, "\(sh) rejects \(a): \(r.err)")
            }
        }
    }

    /// AppleScript itself must read every Terminal command back unchanged.
    @Test func appleScriptReadsEachTerminalCommandBackExactly() {
        var scripts = terminalActions.map { $0.terminalScript! }
        scripts.append(#"a "quoted" \ backslash"#)
        for script in scripts {
            let r = shell("/usr/bin/osascript", ["-e", "return \"\(applescriptString(script))\""])
            #expect(r.status == 0, "\(r.err)")
            #expect(r.out.hasSuffix("\n") ? String(r.out.dropLast()) == script : r.out == script)
        }
        let full = terminalAppleScript("echo hi")
        #expect(full.contains("tell application \"Terminal\"") && full.contains("do script \"echo hi\""))
    }

    @Test func anItemsLabelAndItsRouteAreBoundTogether() {
        let snap = busy()
        var m = menu(snap, prefs: Prefs(), now: now)
        var shown = texts(m)
        // By default the human's actions go to the web UI.
        #expect(shown.contains("An agent is asking for access (2 min ago): review…\n"))
        #expect(shown.contains("Add a key…\n"))
        #expect(actions(in: m).contains(.addKey))
        #expect(!actions(in: m).contains { if case .terminal = $0 { return true }; return false })
        // Actions with no web page say they open Terminal either way.
        #expect(shown.contains("Save my keys to an encrypted file… (opens Terminal)"))

        let chosen = Prefs(terminal: true)
        m = menu(snap, prefs: chosen, now: now)
        shown = texts(m)
        for line in [
            "An agent is asking for access (2 min ago): review… (opens Terminal)",
            "Add a key… (opens Terminal)",
            "Replace this key's value… (opens Terminal)",
            "Allow this key again… (opens Terminal)",
            "From “keys-all”… (opens Terminal)",
            "Choose keys and limits… (opens Terminal)",
        ] {
            #expect(shown.contains(line), "\(line)")
        }
        // Setting Touch ID up is a browser job, and things the companion does
        // itself are not marked.
        for line in ["Set up Touch ID approvals…\n", "Lock the vault\n", "Stop all use of this key…\n", "Open the vault…\n"] {
            #expect(shown.contains(line), "\(line)")
        }
        // The route is in the item itself: an item marked for Terminal is a
        // Terminal action, and one that is not, is not.
        func check(_ items: [Item]) {
            for i in items {
                switch i {
                case .action(let action, let text):
                    #expect(text.hasSuffix("(opens Terminal)") == action.opensTerminal, "\(text)")
                    if case .terminal(let inner) = action {
                        #expect(inner.hasBothRoutes, "\(text)")
                    }
                case .submenu(_, let children):
                    check(children)
                default:
                    break
                }
            }
        }
        for m in allMenus() { check(m) }
        let wrapped = Action.terminal(.addKey)
        #expect(wrapped.opensTerminal && wrapped.uiFragment == nil)
        #expect(wrapped.terminalScript == Action.addKey.terminalScript)
        // Only an action with both routes can go to Terminal this way.
        #expect(Action.terminal(.lock).terminalScript == nil)
        #expect(Action.terminal(.openUi).terminalScript == nil)
        #expect(Action.terminal(.terminal(.addKey)).terminalScript == nil)
        #expect(Action.terminal(.review("--x")).terminalScript == nil)

        var locked = snap
        locked.reach = up(true)
        #expect(texts(menu(locked, prefs: chosen, now: now)).contains("Unlock… (opens Terminal)"))
        #expect(texts(menu(locked, prefs: Prefs(), now: now)).contains("Unlock…\n"))
    }

    @Test func uiFragmentsMatchTheWebRoutersFormat() {
        #expect(Action.review("sr_01ABC").uiFragment == "#approvals/sr_01ABC")
        // formatHash('sessions', `new:${name}`) in web/src/lib/router.js
        #expect(Action.start("keys-all").uiFragment == "#sessions/new%3Akeys-all")
        #expect(Action.newSession.uiFragment == "#sessions/new")
        #expect(Action.addKey.uiFragment == "#credentials")
        #expect(Action.openUi.uiFragment == "")
        #expect(Action.panic.uiFragment == nil)
    }
}

@Suite struct Lists {
    @Test func keysShowTheirStateAndTheRightAction() {
        let m = menu(busy(), prefs: Prefs(), now: now)
        let shown = texts(m)
        #expect(shown.contains("openai-api · OpenAI · in use"))
        #expect(shown.contains("⚠ anthropic-api · Anthropic · last check failed"))
        #expect(shown.contains("⏸ hf · huggingface.co · stopped"))
        let a = actions(in: m)
        #expect(a.contains(.stopKey("openai-api")))
        #expect(!a.contains(.stopKey("hf")), "a stopped key is not stopped again")
        #expect(a.contains(.releaseKey("hf")))
        #expect(a.contains(.rotateKey("openai-api")))
    }

    @Test func setupStepsLeadWithThePassphrase() {
        var snap = Snapshot(reach: up(false))
        snap.setup = Setup(passphrase: false)
        snap.agents = [AgentLink(id: "codex", name: "Codex", connected: false)]
        #expect(actions(in: setupSteps(snap)) == [.passphraseInTerminal, .addKey, .connect("codex")])
        #expect(setupSteps(busy()).isEmpty, "a finished setup shows no checklist")
        // Unknown is not "missing": no nagging when doctor could not be read.
        var unknown = busy()
        unknown.setup = Setup()
        #expect(setupSteps(unknown).isEmpty)
    }

    @Test func aMissingVaultOffersSetupAndAnUntrustedOneDoesNot() {
        #expect(actions(in: menu(Snapshot(reach: .missing(.notInstalled)), prefs: Prefs(), now: now)).contains(.installInTerminal))
        #expect(!actions(in: menu(Snapshot(reach: .missing(.untrusted("x"))), prefs: Prefs(), now: now)).contains(.installInTerminal))
    }

    @Test func theFirstRunWelcomeSaysWhatWasFoundAndWhatToDo() throws {
        let missing = try #require(welcome(Snapshot(reach: .missing(.notInstalled)), placement: .island))
        #expect(missing.next?.action == .installInTerminal)
        let w = try #require(welcome(busy(), placement: .island))
        #expect(w.body.contains("with 3 keys"))
        #expect(w.body.contains("notch"))
        #expect(w.next == nil, "nothing left to set up")
        #expect(try #require(welcome(busy(), placement: .menuBar)).body.contains("menu bar"))
        var fresh = Snapshot(reach: up(false))
        fresh.setup = Setup(passphrase: false)
        let f = try #require(welcome(fresh, placement: .island))
        #expect(f.body.contains("no keys yet"))
        #expect(f.next?.action == .passphraseInTerminal)
        #expect(f.next?.label == "Set your passphrase")
        #expect(welcome(.loading(), placement: .island) == nil)
    }

    @Test func aLockedVaultOffersUnlockNotLock() {
        var a = actions(in: menu(Snapshot(reach: up(true)), prefs: Prefs(), now: now))
        #expect(a.contains(.unlock) && !a.contains(.lock))
        a = actions(in: menu(Snapshot(reach: up(false)), prefs: Prefs(), now: now))
        #expect(a.contains(.lock) && !a.contains(.unlock))
    }

    @Test func theMenuBarCountsWhatIsWaiting() {
        var snap = Snapshot(reach: up(false))
        #expect(trayTitle(snap) == nil)
        snap.pending = parsePending(j(#"[{"id":"a"},{"id":"b"}]"#))
        #expect(trayTitle(snap) == "2")
    }

    @Test func aFailedReadIsNeverShownAsAnEmptyList() {
        var snap = Snapshot(reach: up(false))
        snap.unread = Unread(sessions: true, pending: true, templates: true, keys: true)
        let shown = texts(menu(snap, prefs: Prefs(), now: now))
        #expect(shown.contains("Couldn't read open sessions"))
        #expect(shown.contains("Couldn't check what is waiting"))
        #expect(shown.contains("Couldn't read your keys"))
        #expect(!shown.contains("No open sessions"))
        #expect(!shown.contains("Nothing waiting"))
        #expect(!shown.contains("No keys stored"))
        #expect(!shown.contains("Add your first key"))
        #expect(trayTitle(snap) == "?")
        #expect(badge(snap, now: now) == .unknownWaiting)
    }

    @Test func settingsReflectTheUsersChoices() {
        let m = menu(busy(), prefs: Prefs(notifications: false, autostart: true, welcomed: true, terminal: false), now: now)
        let c = checks(m)
        #expect(c.contains { $0.0 == .toggleNotifications && $0.1 == false })
        #expect(c.contains { $0.0 == .toggleAutostart && $0.1 == true })
        let shown = texts(m)
        #expect(shown.contains("Claude Code · connected"))
        #expect(shown.contains("Connect Codex"))
    }

    @Test func anUnreachableVaultStillOffersSettingsRefreshAndQuit() {
        let a = actions(in: menu(Snapshot(reach: .down("the daemon is not running")), prefs: Prefs(), now: now))
        #expect(a == [.toggleNotifications, .toggleAutostart, .toggleTerminal, .refresh, .quit])
    }
}

@Suite struct TheIsland {
    /// The island shows the very list the menu bar menu shows: every item, in
    /// the same order, none dropped and none added.
    @Test func theIslandShowsEveryItemOfTheList() {
        for m in allMenus() {
            let layout = islandLayout(m)
            var rebuilt: [Item] = []
            for g in layout.groups {
                if let h = g.heading { rebuilt.append(.text(h)) }
                rebuilt += g.entries
            }
            let flat = m.filter { if case .separator = $0 { return false }; return true }
            let settings = flat.first { if case .submenu("Settings", _) = $0 { return true }; return false }
            #expect(settings != nil)
            let rest = flat.filter { $0 != settings && !layout.chrome.contains($0) }
            #expect(rebuilt == rest)
            #expect(actions(in: layout.chrome) == [.refresh, .quit])
            if case .submenu(_, let children) = settings! {
                #expect(layout.settings == children)
            }
        }
    }

    @Test func headingsAreAGroupsFirstLine() {
        let layout = islandLayout(menu(busy(), prefs: Prefs(), now: now))
        let headings = layout.groups.compactMap(\.heading)
        #expect(headings.contains("Waiting for you (2)"))
        #expect(headings.contains("Open sessions (1): what agents can use now"))
        #expect(headings.contains("Keys (3)"))
        // The first line, alone in its group, is the vault's version and state.
        #expect(layout.groups.first == IslandGroup(heading: nil, entries: [.text("agent-vault 0.4.0 · Unlocked")]))
    }

    @Test func theClosedIslandSaysOnlyWhatMatters() {
        var snap = busy()
        #expect(badge(snap, now: now) == .waiting(2))
        snap.pending = []
        #expect(badge(snap, now: now) == nil, "nothing waiting, unlocked, no session ending soon")
        #expect(badge(snap, now: at("2026-11-20T15:03:00Z")) == .ending(minutes: 9))
        #expect(badge(snap, now: at("2026-11-20T15:13:00Z")) == nil, "a session past its end is not ending soon")
        snap.reach = up(true)
        #expect(badge(snap, now: now) == .locked)
        #expect(badge(Snapshot(reach: .down("x")), now: now) == .unreachable)
        #expect(badge(Snapshot(reach: .missing(.notInstalled)), now: now) == .notSetUp)
        #expect(badge(Snapshot(reach: .missing(.untrusted("x"))), now: now) == .untrusted)
        #expect(badge(.loading(), now: now) == nil)
    }
}
