import CryptoKit
import Foundation

// Touch ID in the island: the requests the companion signs with its Secure
// Enclave key, and the checks it makes before it asks for a fingerprint.
//
// The flow, for each request: the CLI asks the daemon for a challenge bound to
// the exact request (`--companion-challenge`); the companion checks that the
// operation the daemon bound is the one the user chose, asks for Touch ID with
// a prompt that names it, signs, and sends the same command with the proof
// (`--presence-stdin`). The daemon verifies the signature before it widens
// anything, so a click on the island never grants on its own.

/// What the daemon says about the companion's key (`companion status`).
public struct Enrollment: Equatable {
    public var enrolled: Bool
    public var keyId: String?

    public init(enrolled: Bool, keyId: String?) {
        self.enrolled = enrolled
        self.keyId = keyId
    }
}

public func parseEnrollment(_ data: JSON) -> Enrollment? {
    guard let enrolled = data["enrolled"]?.bool else { return nil }
    return Enrollment(enrolled: enrolled, keyId: enrolled ? data["key_id"]?.string : nil)
}

/// Whether the island can approve with Touch ID right now.
public enum TouchId: Equatable {
    /// No Secure Enclave or no fingerprint reader: approvals go to the vault
    /// page or Terminal.
    case unavailable
    /// Not set up yet (or the vault could not be asked).
    case notSetUp
    /// The vault holds a companion key, but not this Mac's.
    case otherKey
    case ready
    /// The installed vault is older than Touch ID in the companion.
    case vaultTooOld
}

public func touchId(_ enrollment: Enrollment?, localKeyId: String?, available: Bool, vaultTooOld: Bool = false) -> TouchId {
    guard available else { return .unavailable }
    if vaultTooOld { return .vaultTooOld }
    guard let enrollment, enrollment.enrolled else { return .notSetUp }
    guard let localKeyId else { return .otherKey }
    return enrollment.keyId == localKeyId ? .ready : .otherKey
}

/// The id the vault knows a key by: base64url of the first 12 bytes of
/// SHA-256 of its DER SPKI (as `av_store::vault::companion_key_id`).
public func companionKeyId(spki: Data) -> String {
    base64url(Data(SHA256.hash(data: spki).prefix(12)))
}

public func base64url(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

public func fromBase64url(_ text: String) -> Data? {
    var s = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    while s.count % 4 != 0 { s += "=" }
    return Data(base64Encoded: s)
}

/// What the companion signs for a challenge (as `crate::companion::signed_message`).
public func signedMessage(challenge: Data) -> Data {
    Data("agent-vault companion presence v1\n".utf8) + challenge
}

/// The kinds of key the island can add, as `cred add --kind` names them.
/// `http` is any other service, by its host.
public let keyKinds: [(kind: String, name: String)] = [
    ("openai", "OpenAI"),
    ("anthropic", "Anthropic"),
    ("google-genai", "Google Gemini"),
    ("github", "GitHub"),
    ("slack", "Slack"),
    ("http", "Another service"),
]

/// A host name the island will pass on: letters, digits, dots and dashes,
/// with an optional port, never starting with a dash.
public func plainHost(_ s: String) -> Bool {
    guard !s.isEmpty, s.count <= 253, !s.hasPrefix("-"), !s.hasPrefix(".") else { return false }
    return s.unicodeScalars.allSatisfy { c in
        (c.value >= 0x30 && c.value <= 0x39) || (c.value >= 0x41 && c.value <= 0x5A) || (c.value >= 0x61 && c.value <= 0x7A)
            || c == "." || c == "-" || c == ":"
    }
}

/// Something the island does with Touch ID.
public enum SignedRequest: Equatable {
    case approve(id: String)
    case deny(id: String)
    case start(template: String)
    case release(slug: String)
    case rotate(slug: String)
    case add(slug: String, kind: String, host: String?)
    case removeTouchId

    /// The CLI command, without `--json` or the companion mode flag. `nil`
    /// when a value is not the plain kind, so nothing odd reaches the CLI.
    public var args: [String]? {
        switch self {
        case .approve(let id) where safeId(id): return ["approve", id]
        case .deny(let id) where safeId(id): return ["deny", id]
        case .start(let name) where safeId(name): return ["session", "create", "--template", name]
        case .release(let slug) where safeId(slug): return ["cred", "release", slug]
        case .rotate(let slug) where safeId(slug): return ["cred", "rotate", slug]
        case .add(let slug, let kind, let host) where safeId(slug) && keyKinds.contains(where: { $0.kind == kind }):
            if kind == "http" {
                guard let host, plainHost(host) else { return nil }
                return ["cred", "add", slug, "--kind", kind, "--host", host]
            }
            return ["cred", "add", slug, "--kind", kind]
        case .removeTouchId: return ["companion", "remove"]
        default: return nil
        }
    }

    /// Whether a key's value follows the proof on stdin.
    public var takesValue: Bool {
        switch self {
        case .rotate, .add: return true
        default: return false
        }
    }

    /// Whether the daemon bound `operation` to what the user chose: the right
    /// kind of change, on the right thing. Checked before Touch ID is asked
    /// for, so the companion never signs something other than what was clicked.
    public func matches(_ operation: JSON) -> Bool {
        let op = operation["op"]?.string
        switch self {
        case .approve(let id):
            return operation["id"]?.string == id
                && (op == "approval.approve" || (op == "session_request.decide" && operation["granted"]?.bool == true))
        case .deny(let id):
            return operation["id"]?.string == id
                && (op == "approval.deny" || (op == "session_request.decide" && operation["granted"]?.bool == false))
        case .start(let name):
            return op == "session.create" && operation["template"]?.string == name
        case .release(let slug):
            return op == "cred.release" && operation["slug"]?.string == slug
        case .rotate(let slug):
            return op == "cred.rotate" && operation["slug"]?.string == slug && operation["value_sha256"]?.string != nil
        case .add(let slug, let kind, _):
            return op == "cred.add" && operation["slug"]?.string == slug && operation["kind"]?.string == kind
                && operation["value_sha256"]?.string != nil
        case .removeTouchId:
            return op == "companion.remove"
        }
    }

    /// What macOS's Touch ID prompt says the companion is trying to do: "…is
    /// trying to approve the request on screen." Built from the request the
    /// user chose, and only after `matches` has held it to the daemon's.
    public var reason: String {
        switch self {
        case .approve: return "approve the agent's request shown in the island"
        case .deny: return "deny the agent's request shown in the island"
        case .start(let name): return "start a session from “\(cleanText(name, 40))”"
        case .release(let slug): return "let agents use “\(cleanText(slug, 40))” again"
        case .rotate(let slug): return "replace the value of “\(cleanText(slug, 40))”"
        case .add(let slug, _, _): return "add the key “\(cleanText(slug, 40))”"
        case .removeTouchId: return "stop using Touch ID in the companion"
        }
    }

    /// What to say once it worked.
    public var done: String {
        switch self {
        case .approve: return "Approved."
        case .deny: return "Denied."
        case .start(let name): return "Started a session from “\(cleanText(name, 40))”."
        case .release(let slug): return "Agents can use “\(cleanText(slug, 40))” again."
        case .rotate(let slug): return "Replaced the value of “\(cleanText(slug, 40))”."
        case .add(let slug, _, _): return "Added “\(cleanText(slug, 40))”."
        case .removeTouchId: return "Touch ID in the companion is off."
        }
    }
}

/// A challenge as the CLI prints it, checked: the id and the 32-byte
/// challenge, and the operation the daemon bound it to.
public struct Challenge: Equatable {
    public var id: String
    public var challenge: Data
    public var operation: JSON
}

public func parseChallenge(_ data: JSON) -> Challenge? {
    guard let id = data["challengeId"]?.string, !id.isEmpty,
          let raw = data["challenge"]?.string, let challenge = fromBase64url(raw), challenge.count == 32,
          let operation = data["operation"], operation["op"]?.string != nil
    else { return nil }
    return Challenge(id: id, challenge: challenge, operation: operation)
}

/// The line `--presence-stdin` reads: exactly the two fields.
public func presenceLine(challengeId: String, signature: Data) -> String {
    let object: [String: String] = ["challengeId": challengeId, "companionSignature": base64url(signature)]
    let data = (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
    return String(decoding: data, as: UTF8.self)
}

/// A label for this Mac the vault will accept: letters, digits, spaces, dots,
/// dashes and underscores, at most 40, never empty.
public func plainLabel(_ name: String) -> String {
    let kept = name.unicodeScalars.filter { c in
        (c.value >= 0x30 && c.value <= 0x39) || (c.value >= 0x41 && c.value <= 0x5A) || (c.value >= 0x61 && c.value <= 0x7A)
            || c == " " || c == "." || c == "-" || c == "_"
    }
    let text = String(String.UnicodeScalarView(kept)).trimmingCharacters(in: .whitespaces)
    let cut = String(text.prefix(40)).trimmingCharacters(in: .whitespaces)
    return cut.isEmpty ? "Mac" : cut
}
