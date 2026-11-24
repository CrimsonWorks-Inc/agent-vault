import Foundation
import Testing
@testable import CompanionCore

@Suite struct TalkingToTheCLI {
    @Test func envelopesYieldDataOrTheErrorMessage() throws {
        #expect(try parseEnvelope(#"{"ok":true,"data":[1]}"#).get() == j("[1]"))
        #expect(parseEnvelope(#"{"ok":false,"error":{"code":"AV_LOCKED","message":"the vault is locked"}}"#)
            == .failure(Failure("the vault is locked")))
        #expect(parseEnvelope("not json") == .failure(Failure("agent-vault gave no readable answer")))
    }

    @Test func longLinesAreSkippedNotHeld() {
        var lines = LineSplitter(cap: 50)
        let data = Data(("short\n" + String(repeating: "x", count: 200) + "\nafter\nlast").utf8)
        var got: [String] = []
        // In small pieces, as a pipe delivers them.
        var i = data.startIndex
        while i < data.endIndex {
            let end = data.index(i, offsetBy: 16, limitedBy: data.endIndex) ?? data.endIndex
            got += lines.feed(data[i..<end])
            i = end
        }
        if let last = lines.finish() { got.append(last) }
        #expect(got == ["short", "", "after", "last"])
        #expect(lines.finish() == nil, "nothing more after the end")
    }

    @Test func jsonIsGatheredAcrossPrettyPrintedLines() {
        var json = JSONLines()
        #expect(json.push("{") == nil)
        #expect(json.push(#"  "ok": true"#) == nil)
        #expect(json.push("}") == j(#"{"ok": true}"#))
        #expect(json.push(#"{"ok":true,"data":{"event":"pending"}}"#)?["data"]?["event"]?.string == "pending")
    }

    @Test func thePortIsReadFromTheLink() {
        #expect(uiPort("http://localhost:7412/?t=abc") == 7412)
        #expect(uiPort("http://localhost:/?t=abc") == nil)
    }

    @Test func onlyTheVaultsOwnLoopbackLinkIsOpened() {
        #expect(checkedUIURL("http://localhost:7412/?t=abc_DEF-123") != nil)
        for bad in [
            "https://localhost:7412/?t=abc",
            "http://127.0.0.1:7412/?t=abc",
            "http://localhost.evil.com:7412/?t=abc",
            "http://localhost:7412/?t=",
            "http://localhost:7412/?t=abc&next=http://evil",
            "http://localhost:/?t=abc",
            "file:///etc/passwd",
        ] {
            #expect(checkedUIURL(bad) == nil, "\(bad)")
        }
    }

    @Test func listenersAreReadFromLsof() {
        #expect(listenerPids("p123\nf4\np456\n") == [123, 456])
        #expect(listenerPids("").isEmpty)
    }

    /// The CLI's children get a fixed environment, whatever the companion was
    /// started with.
    @Test func childProcessesGetAFixedEnvironment() {
        let env = CLI.cleanEnvironment([
            "HOME": "/Users/x", "USER": "x", "AGENT_VAULT_DIR": "/tmp/evil", "PATH": "/tmp/evil:/usr/bin",
            "DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib",
        ])
        #expect(env == ["HOME": "/Users/x", "USER": "x", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"])
    }

    /// Only a root-owned install is ever run: not one the user (or an agent
    /// running as the user) could have written.
    @Test func anInstallTheUserCouldWriteIsRefused() throws {
        #expect(try #require(CLI.locate(at: nil).failure) == .unsupported)
        #expect(try #require(CLI.locate(at: "/nonexistent/agent-vault").failure) == .notInstalled)
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("av-fake-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let fake = dir.appendingPathComponent("agent-vault")
        try "#!/bin/sh\necho '{\"ok\":true,\"data\":{}}'\n".write(to: fake, atomically: true, encoding: .utf8)
        guard case .untrusted(let why) = try #require(CLI.locate(at: fake.path).failure) else {
            Issue.record("a user-owned CLI was accepted")
            return
        }
        #expect(why.contains("not a root-owned install"))
        // A root-owned file in a root-owned folder passes the check.
        #expect(CLI.rootOwnedProblem("/bin/sh") == nil)
        #expect(CLI.rootOwnedProblem("/bin") == nil)
    }
}

extension Result {
    var failure: Failure? {
        if case .failure(let e) = self { return e }
        return nil
    }
}
