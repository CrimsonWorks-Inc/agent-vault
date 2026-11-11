//! The operation a WebAuthn presence proof binds to: the pure parts of
//! `src/ui/webauthn.js`. Signature verification stays in av-daemon.

use crate::errors::Result;

/// Request fields that carry a secret and are bound by SHA-256 digest
/// (`<key>_sha256`) rather than in clear. Ports `DIGESTED` in
/// `src/ui/webauthn.js`.
pub const DIGESTED: &[&str] = &[
    "value",
    "prf_secret",
    "recovery_passphrase",
    "bundle",
    "webhook_url",
];

/// The operation object a presence proof signs: `params` with keys sorted,
/// `presence` and undefined values dropped, [`DIGESTED`] fields replaced by
/// `<key>_sha256` (hex of the string's bytes, or of the canonical form of a
/// non-string), then `op`. Refuses (`AV_POLICY_DENIED`, rule
/// `reserved_operation_field`) a param named `op` that differs from `op`, or
/// any `*_sha256`. `params` may hold secrets; the result does not. Ports
/// `operationFor` in `src/ui/webauthn.js`.
pub fn operation_for(
    op: &str,
    params: &serde_json::Map<String, serde_json::Value>,
) -> Result<serde_json::Map<String, serde_json::Value>> {
    todo!()
}

/// Stable-key-order JSON text of an operation, so the signed and executed
/// operations compare exactly (`null` for null). Ports `canonicalOperation`
/// in `src/ui/webauthn.js`.
pub fn canonical_operation(value: &serde_json::Value) -> String {
    todo!()
}

/// The WebAuthn challenge for an operation: SHA-256 of `nonce` followed by
/// the UTF-8 of `canonical_operation(operation)`. Ports
/// `challengeForOperation` in `src/ui/webauthn.js`.
pub fn challenge_for_operation(nonce: &[u8], operation: &serde_json::Value) -> [u8; 32] {
    todo!()
}
