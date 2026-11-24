import CompanionCore
import CryptoKit
import Foundation
import LocalAuthentication

/// The companion's presence key: a P-256 key made in this Mac's Secure
/// Enclave that signs only after Touch ID with the fingerprints enrolled now.
/// The private key never leaves the Secure Enclave; what is kept on disk is
/// an encrypted handle only this Mac's Secure Enclave can use, and using it
/// still takes a fingerprint, so a copy of the file is no use to anyone.
enum Enclave {
    /// Whether this Mac can make and use such a key: a Secure Enclave and a
    /// fingerprint reader with at least one finger enrolled.
    static var available: Bool {
        var error: NSError?
        return SecureEnclave.isAvailable
            && LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    private static var file: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("agent-vault companion", isDirectory: true)
            .appendingPathComponent("presence-key")
    }

    /// The key's handle, if one was made on this Mac.
    private static func handle() -> Data? {
        try? Data(contentsOf: file)
    }

    /// The public key (DER SPKI) of the key made here, if any.
    static var publicKey: Data? {
        guard let data = handle(),
              let key = try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data)
        else { return nil }
        return key.publicKey.derRepresentation
    }

    static var keyId: String? {
        publicKey.map { companionKeyId(spki: $0) }
    }

    /// The key made here, or a new one. Making a key asks for nothing; only
    /// signing does.
    static func ensureKey() throws -> Data {
        if let existing = publicKey { return existing }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet], &error
        ) else {
            throw error?.takeRetainedValue() ?? CocoaError(.featureUnsupported)
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        let dir = file.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        try key.dataRepresentation.write(to: file, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        return key.publicKey.derRepresentation
    }

    /// Forget the key made here.
    static func remove() {
        try? FileManager.default.removeItem(at: file)
    }

    enum SignError: Error {
        case noKey
        case cancelled
        case failed(String)
    }

    // MARK: Touch ID unlock

    /// A second Secure Enclave key, for key agreement, beside a public key
    /// whose private half was thrown away once used. The agreement between
    /// the two, which only this Secure Enclave can repeat and only after
    /// Touch ID, gives the unlock secret. Neither file is secret: the handle
    /// works only in this Mac's Secure Enclave, and the public key alone
    /// gives nothing.
    private static var unlockFile: URL {
        file.deletingLastPathComponent().appendingPathComponent("unlock-key")
    }

    private static var peerFile: URL {
        file.deletingLastPathComponent().appendingPathComponent("unlock-peer")
    }

    /// Whether this Mac holds an unlock key (the vault decides whether it
    /// still opens anything).
    static var hasUnlockKey: Bool {
        guard let handle = try? Data(contentsOf: unlockFile),
              let peer = try? Data(contentsOf: peerFile),
              (try? P256.KeyAgreement.PublicKey(x963Representation: peer)) != nil
        else { return false }
        return (try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: handle)) != nil
    }

    /// Make a new unlock key and return its secret, after Touch ID. Replaces
    /// any unlock key made before. Blocks; never on the main thread.
    static func newUnlockSecret(reason: String) -> Result<String, SignError> {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet], &error
        ) else {
            return .failure(.failed(error.map { "\($0.takeRetainedValue())" } ?? "no access control"))
        }
        let context = LAContext()
        context.localizedReason = reason
        return attempt {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access, authenticationContext: context)
            let peer = P256.KeyAgreement.PrivateKey()
            let secret = unlockSecret(agreement: try key.sharedSecretFromKeyAgreement(with: peer.publicKey))
            let dir = file.deletingLastPathComponent()
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
            for (data, url) in [(key.dataRepresentation, unlockFile), (peer.publicKey.x963Representation, peerFile)] {
                try data.write(to: url, options: [.atomic])
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            }
            return secret
        }
    }

    /// The unlock secret again, after Touch ID. Blocks; never on the main
    /// thread.
    static func unlockSecretNow(reason: String) -> Result<String, SignError> {
        guard let handle = try? Data(contentsOf: unlockFile),
              let peerData = try? Data(contentsOf: peerFile),
              let peer = try? P256.KeyAgreement.PublicKey(x963Representation: peerData)
        else { return .failure(.noKey) }
        let context = LAContext()
        context.localizedReason = reason
        return attempt {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: handle, authenticationContext: context)
            return unlockSecret(agreement: try key.sharedSecretFromKeyAgreement(with: peer))
        }
    }

    /// Forget the unlock key made here.
    static func removeUnlockKey() {
        try? FileManager.default.removeItem(at: unlockFile)
        try? FileManager.default.removeItem(at: peerFile)
    }

    /// Run a Secure Enclave operation, telling a cancelled prompt from a
    /// failure.
    private static func attempt<T>(_ body: () throws -> T) -> Result<T, SignError> {
        do {
            return .success(try body())
        } catch let error as LAError where [.userCancel, .appCancel, .systemCancel, .userFallback].contains(error.code) {
            return .failure(.cancelled)
        } catch {
            let ns = error as NSError
            if ns.domain == NSOSStatusErrorDomain && ns.code == Int(errSecUserCanceled) {
                return .failure(.cancelled)
            }
            return .failure(.failed(error.localizedDescription))
        }
    }

    /// Sign `message` after Touch ID. macOS shows the prompt, with `reason`
    /// as what the companion is trying to do. Blocks until the human answers,
    /// so never call it on the main thread.
    static func sign(_ message: Data, reason: String) -> Result<Data, SignError> {
        guard let data = handle() else { return .failure(.noKey) }
        let context = LAContext()
        context.localizedReason = reason
        do {
            let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data, authenticationContext: context)
            return .success(try key.signature(for: message).derRepresentation)
        } catch let error as LAError where [.userCancel, .appCancel, .systemCancel, .userFallback].contains(error.code) {
            return .failure(.cancelled)
        } catch {
            let ns = error as NSError
            // The Secure Enclave reports a cancelled prompt as an OSStatus.
            if ns.domain == NSOSStatusErrorDomain && ns.code == Int(errSecUserCanceled) {
                return .failure(.cancelled)
            }
            return .failure(.failed(error.localizedDescription))
        }
    }
}
