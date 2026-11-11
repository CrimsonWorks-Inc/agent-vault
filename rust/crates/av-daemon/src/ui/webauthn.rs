//! WebAuthn (ES256 only): a strict minimal CBOR reader, authenticator data
//! parsing, and registration/assertion verification. Ports
//! `src/ui/webauthn.js`.
//!
//! The pure operation-binding half of `webauthn.js` (`operationFor`,
//! `DIGESTED`, `canonicalOperation`, `challengeForOperation`) lives in
//! `av_core::operation`, because the daemon and the UI server must derive the
//! same challenge, and will be re-exported here once that module is settled.

/// COSE algorithm id for ES256, the only one accepted. Ports `ES256` in
/// `src/ui/webauthn.js`.
pub const ES256: i64 = -7;

/// Deepest CBOR nesting read. Ports `CBOR_MAX_DEPTH` (module-private) in
/// `src/ui/webauthn.js`.
pub const CBOR_MAX_DEPTH: usize = 16;

/// The failure codes a verification can report (never the message). Ports
/// `FAILURES` in `src/ui/webauthn.js`.
pub const FAILURES: [&str; 8] = [
    "client_data_type",
    "origin",
    "challenge",
    "signature",
    "credential",
    "malformed",
    "size",
    "other",
];

/// A decoded CBOR item: just enough for attestation objects and COSE keys.
/// Ports the values `readItem` produces in `src/ui/webauthn.js`.
#[derive(Debug, Clone, PartialEq)]
pub enum Cbor {
    /// Major types 0 and 1.
    Int(i128),
    /// Major type 2.
    Bytes(Vec<u8>),
    /// Major type 3.
    Text(String),
    /// Major type 4.
    Array(Vec<Cbor>),
    /// Major type 5, in encoded order.
    Map(Vec<(Cbor, Cbor)>),
    /// `true` / `false`.
    Bool(bool),
    /// `null`.
    Null,
}

/// A verification failure: one of [`FAILURES`] and a message for stderr.
/// Ports the errors made by `fail(code, message)` (module-private) in
/// `src/ui/webauthn.js`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct WebauthnError {
    /// One of [`FAILURES`].
    pub failure: &'static str,
    /// Detail (may quote client data; never sent to the agent).
    pub message: String,
}

/// Decode one CBOR item at `start`; returns the item and the end offset.
/// Lengths bounded by the buffer, depth by [`CBOR_MAX_DEPTH`]. Ports
/// `decodeCbor(buf, start)` in `src/ui/webauthn.js`.
pub fn decode_cbor(buf: &[u8], start: usize) -> Result<(Cbor, usize), WebauthnError> {
    todo!()
}

/// Parsed authenticator data. Ports the result of `parseAuthData` in
/// `src/ui/webauthn.js`.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthData {
    /// SHA-256 of the RP id.
    pub rp_id_hash: [u8; 32],
    /// UP flag.
    pub user_present: bool,
    /// UV flag.
    pub user_verified: bool,
    /// Signature counter.
    pub sign_count: u32,
    /// Present when the AT flag is set.
    pub attested_credential_data: bool,
    /// Credential id, when attested.
    pub credential_id: Option<Vec<u8>>,
    /// COSE public key, when attested.
    pub cose_key: Option<Cbor>,
}

/// Ports `parseAuthData(authData)` in `src/ui/webauthn.js`.
pub fn parse_auth_data(auth_data: &[u8]) -> Result<AuthData, WebauthnError> {
    todo!()
}

/// An ES256 COSE key as a SEC1 P-256 public key (uncompressed point).
/// Ports `coseToPublicKey(cose)` in `src/ui/webauthn.js`.
pub fn cose_to_public_key(cose: &Cbor) -> Result<Vec<u8>, WebauthnError> {
    todo!()
}

/// 32 random bytes. Ports `newChallenge()` in `src/ui/webauthn.js`.
pub fn new_challenge() -> [u8; 32] {
    todo!()
}

/// Unpadded base64url. Ports `b64url(buf)` in `src/ui/webauthn.js`.
pub fn b64url(buf: &[u8]) -> String {
    todo!()
}

/// The failure code of an error, or `other`. Ports `failureOf(e)` in
/// `src/ui/webauthn.js`.
pub fn failure_of(e: &(dyn std::error::Error + 'static)) -> &'static str {
    todo!()
}

/// Input to [`verify_registration`]. Ports the argument of
/// `verifyRegistration({ attestationObject, clientDataJSON,
/// expectedChallenge, expectedOrigins, rpId })` in `src/ui/webauthn.js`.
#[derive(Debug, Clone)]
pub struct RegistrationInput<'a> {
    /// base64url attestation object.
    pub attestation_object: &'a str,
    /// base64url client data JSON.
    pub client_data_json: &'a str,
    /// The challenge issued.
    pub expected_challenge: &'a [u8],
    /// Origins accepted.
    pub expected_origins: &'a [String],
    /// Relying party id.
    pub rp_id: &'a str,
}

/// An enrolled credential. Ports the `{ credentialId, publicKeySpki,
/// signCount, enrolledAt }` result of `verifyRegistration` (and the
/// `enrolled` input of `verifyAssertion`) in `src/ui/webauthn.js`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolledCredential {
    /// base64url credential id.
    pub credential_id: String,
    /// base64 DER SPKI.
    pub public_key_spki: String,
    /// Last seen signature counter.
    pub sign_count: u32,
    /// ISO 8601.
    pub enrolled_at: String,
}

/// Verify a `webauthn.create` registration. Ports
/// `verifyRegistration(...)` in `src/ui/webauthn.js`.
pub fn verify_registration(
    input: &RegistrationInput<'_>,
) -> Result<EnrolledCredential, WebauthnError> {
    todo!()
}

/// Input to [`verify_assertion`]. Ports the argument of
/// `verifyAssertion({ credentialId, authenticatorData, clientDataJSON,
/// signature, expectedChallenge, expectedOrigins, rpId, enrolled })` in
/// `src/ui/webauthn.js`.
#[derive(Debug, Clone)]
pub struct AssertionInput<'a> {
    /// base64url credential id.
    pub credential_id: &'a str,
    /// base64url authenticator data.
    pub authenticator_data: &'a str,
    /// base64url client data JSON.
    pub client_data_json: &'a str,
    /// base64url DER signature.
    pub signature: &'a str,
    /// The operation-derived challenge.
    pub expected_challenge: &'a [u8],
    /// Origins accepted.
    pub expected_origins: &'a [String],
    /// Relying party id.
    pub rp_id: &'a str,
    /// The enrolled credential.
    pub enrolled: &'a EnrolledCredential,
}

/// Verify an assertion; returns the new signature counter. Refuses a
/// counter that did not advance. Ports `verifyAssertion(...)` in
/// `src/ui/webauthn.js`.
pub fn verify_assertion(input: &AssertionInput<'_>) -> Result<u32, WebauthnError> {
    todo!()
}
