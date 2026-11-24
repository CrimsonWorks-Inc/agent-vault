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
