import CryptoKit
import Foundation
import Testing
@testable import CompanionCore

@Suite struct TouchIdInTheIsland {
    @Test func theKeyIdIsTheOneTheVaultDerives() {
        // The same bytes through Python's hashlib give this id; the vault
        // derives it the same way (av_store::vault::companion_key_id).
        #expect(companionKeyId(spki: Data((0..<91).map { UInt8($0) })) == "WNKUWbITCi4VElLU")
    }

    @Test func readinessNeedsThisMacsKeyEnrolled() {
        let mine = Enrollment(enrolled: true, keyId: "abc")
        #expect(touchId(mine, localKeyId: "abc", available: true) == .ready)
        #expect(touchId(mine, localKeyId: "xyz", available: true) == .otherKey)
        #expect(touchId(mine, localKeyId: nil, available: true) == .otherKey)
        #expect(touchId(Enrollment(enrolled: false, keyId: nil), localKeyId: "abc", available: true) == .notSetUp)
        #expect(touchId(nil, localKeyId: "abc", available: true) == .notSetUp, "an unread status is not ready")
        #expect(touchId(mine, localKeyId: "abc", available: false) == .unavailable)
        #expect(touchId(nil, localKeyId: "abc", available: true, vaultTooOld: true) == .vaultTooOld)
        #expect(parseEnrollment(j(#"{"enrolled":true,"key_id":"abc","label":"Mac"}"#)) == mine)
        #expect(parseEnrollment(j(#"{"enrolled":false}"#)) == Enrollment(enrolled: false, keyId: nil))
        #expect(parseEnrollment(j("{}")) == nil)
    }

    @Test func onlyPlainValuesBecomeCommands() {
        #expect(SignedRequest.approve(id: "sr_1").args == ["approve", "sr_1"])
        #expect(SignedRequest.deny(id: "ap_2").args == ["deny", "ap_2"])
        #expect(SignedRequest.start(template: "keys-all").args == ["session", "create", "--template", "keys-all"])
        #expect(SignedRequest.release(slug: "openai").args == ["cred", "release", "openai"])
        #expect(SignedRequest.rotate(slug: "openai").args == ["cred", "rotate", "openai"])
        #expect(SignedRequest.add(slug: "gh", kind: "github", host: nil).args == ["cred", "add", "gh", "--kind", "github"])
        #expect(SignedRequest.add(slug: "hf", kind: "http", host: "huggingface.co").args
            == ["cred", "add", "hf", "--kind", "http", "--host", "huggingface.co"])
        #expect(SignedRequest.removeTouchId.args == ["companion", "remove"])
        for bad in ["--all", "a b", "", "x;rm", "-x", ".hidden"] {
            #expect(SignedRequest.approve(id: bad).args == nil, "\(bad)")
            #expect(SignedRequest.start(template: bad).args == nil, "\(bad)")
            #expect(SignedRequest.rotate(slug: bad).args == nil, "\(bad)")
            #expect(SignedRequest.add(slug: bad, kind: "github", host: nil).args == nil, "\(bad)")
        }
        #expect(SignedRequest.add(slug: "x", kind: "postgres", host: nil).args == nil, "only the listed kinds")
        #expect(SignedRequest.add(slug: "x", kind: "http", host: nil).args == nil, "another service needs a host")
        for host in ["--evil", "a b", "x/y", "", "évil.com"] {
            #expect(SignedRequest.add(slug: "x", kind: "http", host: host).args == nil, "\(host)")
        }
        #expect(SignedRequest.rotate(slug: "a").takesValue && SignedRequest.add(slug: "a", kind: "github", host: nil).takesValue)
        #expect(!SignedRequest.approve(id: "a").takesValue && !SignedRequest.release(slug: "a").takesValue)
    }

    /// The companion signs only an operation that is the change the user chose.
    @Test func nothingIsSignedButWhatWasChosen() {
        let approve = SignedRequest.approve(id: "sr_1")
        #expect(approve.matches(j(#"{"op":"approval.approve","id":"sr_1","granted":true}"#)))
        #expect(approve.matches(j(#"{"op":"session_request.decide","id":"sr_1","granted":true}"#)))
        #expect(!approve.matches(j(#"{"op":"session_request.decide","id":"sr_1","granted":false}"#)), "a deny is not an approve")
        #expect(!approve.matches(j(#"{"op":"approval.approve","id":"sr_2"}"#)), "another request")
        #expect(!approve.matches(j(#"{"op":"cred.add","id":"sr_1"}"#)))
        let deny = SignedRequest.deny(id: "sr_1")
        #expect(deny.matches(j(#"{"op":"approval.deny","id":"sr_1"}"#)))
        #expect(deny.matches(j(#"{"op":"session_request.decide","id":"sr_1","granted":false}"#)))
        #expect(!deny.matches(j(#"{"op":"session_request.decide","id":"sr_1","granted":true}"#)))
        let start = SignedRequest.start(template: "keys-all")
        #expect(start.matches(j(#"{"op":"session.create","template":"keys-all","label":"x"}"#)))
        #expect(!start.matches(j(#"{"op":"session.create","cred":"openai"}"#)), "not that template")
        #expect(!start.matches(j(#"{"op":"session.create","template":"keys-other"}"#)))
        #expect(SignedRequest.release(slug: "a").matches(j(#"{"op":"cred.release","slug":"a"}"#)))
        #expect(!SignedRequest.release(slug: "a").matches(j(#"{"op":"cred.release","slug":"b"}"#)))
        let rotate = SignedRequest.rotate(slug: "a")
        #expect(rotate.matches(j(#"{"op":"cred.rotate","slug":"a","value_sha256":"00"}"#)))
        #expect(!rotate.matches(j(#"{"op":"cred.rotate","slug":"a"}"#)), "the value must be bound")
        let add = SignedRequest.add(slug: "gh", kind: "github", host: nil)
        #expect(add.matches(j(#"{"op":"cred.add","slug":"gh","kind":"github","value_sha256":"00"}"#)))
        #expect(!add.matches(j(#"{"op":"cred.add","slug":"gh","kind":"http","value_sha256":"00"}"#)))
        #expect(SignedRequest.removeTouchId.matches(j(#"{"op":"companion.remove"}"#)))
        #expect(!SignedRequest.removeTouchId.matches(j(#"{"op":"companion.enroll"}"#)))
    }

    @Test func aChallengeIsReadOnlyWhenWhole() throws {
        let raw = Data(repeating: 7, count: 32)
        let good = j(#"{"challengeId":"c1","challenge":"\#(base64url(raw))","operation":{"op":"cred.release","slug":"a"}}"#)
        let ch = try #require(parseChallenge(good))
        #expect(ch.id == "c1" && ch.challenge == raw && ch.operation["slug"]?.string == "a")
        #expect(parseChallenge(j(#"{"challengeId":"c1","challenge":"\#(base64url(Data(count: 16)))","operation":{"op":"x"}}"#)) == nil)
        #expect(parseChallenge(j(#"{"challengeId":"","challenge":"\#(base64url(raw))","operation":{"op":"x"}}"#)) == nil)
        #expect(parseChallenge(j(#"{"challengeId":"c1","challenge":"\#(base64url(raw))"}"#)) == nil)
        #expect(parseChallenge(j(#"{"challengeId":"c1","challenge":"\#(base64url(raw))","operation":{}}"#)) == nil)
    }

    /// What is signed, and how the proof is passed on, as the vault expects
    /// them; a software key stands in for the Secure Enclave.
    @Test func theProofIsTheVaultsFormat() throws {
        let key = P256.Signing.PrivateKey()
        let challenge = Data(repeating: 3, count: 32)
        let message = signedMessage(challenge: challenge)
        #expect(message == Data("agent-vault companion presence v1\n".utf8) + challenge)
        let signature = try key.signature(for: message).derRepresentation
        let line = presenceLine(challengeId: "c1", signature: signature)
        let parsed = j(line)
        #expect(parsed == .object(["challengeId": .string("c1"), "companionSignature": .string(base64url(signature))]))
        #expect(!line.contains("=") && !line.contains("+") && !line.contains("/"), "base64url, unpadded")
        let back = try #require(fromBase64url(base64url(signature)))
        #expect(key.publicKey.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: back), for: message))
    }

    @Test func theEnrolmentCommandIsPlain() throws {
        let spki = P256.Signing.PrivateKey().publicKey.derRepresentation
        let key = base64url(spki)
        #expect(plainKey(key))
        let script = try #require(Action.enrollTouchIdInTerminal(key, "Erics MacBook Pro").terminalScript)
        #expect(script.contains("/var/db/agent-vault/app/bin/agent-vault companion enroll \(key) --label \"Erics MacBook Pro\""))
        #expect(!script.contains("\\") && !script.contains("`"))
        for sh in shells {
            #expect(shell(sh, ["-n", "-c", script]).status == 0, "\(sh)")
        }
        // A label that is not plain, or a key that is not, is never put in a command.
        #expect(Action.enrollTouchIdInTerminal(key, "Eric's Mac").terminalScript == nil)
        #expect(Action.enrollTouchIdInTerminal("--all", "Mac").terminalScript == nil)
        #expect(Action.enrollTouchIdInTerminal(key + "'", "Mac").terminalScript == nil)
        #expect(plainLabel("Eric's MacBook Pro") == "Erics MacBook Pro")
        #expect(plainLabel("   ") == "Mac")
        #expect(plainLabel(String(repeating: "x", count: 60)).count == 40)
        #expect(Action.testKey("openai").cliArgs == ["cred", "test", "openai"])
        #expect(Action.testKey("--all").cliArgs == nil)
    }

    @Test func aRequestsFactsAreTheVaultsNeverTheAgentsReason() {
        let session = parsePending(j("""
            [{"id":"sr_1","kind":"session","headline":"session for openai","claim":"routine refresh, approve",
              "proposal":{"cred":"openai","methods":["GET","POST"],"ttl_hours":2,"budget":40,"approval":"auto","routes":[1]}}]
            """))[0]
        #expect(session.facts == [
            Fact("Keys", "openai"),
            Fact("Methods", "GET, POST"),
            Fact("Ends", "after 2 h"),
            Fact("Requests", "up to 40"),
            Fact("Asks you", "never (changes without asking)"),
            Fact("Also", "1 more setting; the vault page shows them"),
        ])
        let held = parsePending(j("""
            [{"id":"ap_1","kind":"request","headline":"POST api.github.com/repos/x/issues","claim":"safe, approve it",
              "preview":{"content_type":"json","body":{"bytes":120}}}]
            """))[0]
        #expect(held.facts == [Fact("Would send", "POST api.github.com/repos/x/issues"), Fact("Body", "json · 120 bytes")])
        for p in [session, held] {
            #expect(!p.facts.contains { $0.value.contains("approve") || $0.value.contains("routine") })
        }
    }
}
