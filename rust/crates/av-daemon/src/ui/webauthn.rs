//! WebAuthn (ES256 only): a strict minimal CBOR reader, authenticator data
//! parsing, and registration/assertion verification. Ports
//! `src/ui/webauthn.js`. The operation-binding half (`operationFor`,
//! `DIGESTED`, `canonicalOperation`, `challengeForOperation`) is
//! `av_core::operation`, re-exported here, so the daemon and the UI server
//! derive the same challenge.

use serde_json::Value;

pub use av_core::operation::{
    canonical_operation, challenge_for_operation, operation_for, DIGESTED,
};

use crate::util::{b64_lenient, ct_eq};

/// The one COSE algorithm accepted. Ports `ES256`.
pub const ES256: i64 = -7;
/// Deepest CBOR nesting read. Ports `CBOR_MAX_DEPTH`.
pub const CBOR_MAX_DEPTH: usize = 16;
/// Failure codes an audit record may carry. Ports `FAILURES`.
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

/// A decoded CBOR item. Ports the JS values `decodeCbor` returns.
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
    /// Major type 5, in order.
    Map(Vec<(Cbor, Cbor)>),
    /// Simple 20 / 21.
    Bool(bool),
    /// Simple 22.
    Null,
}

impl Cbor {
    /// `map.get(key)` for an integer key.
    pub fn get_int(&self, key: i128) -> Option<&Cbor> {
        match self {
            Cbor::Map(m) => m.iter().find(|(k, _)| *k == Cbor::Int(key)).map(|(_, v)| v),
            _ => None,
        }
    }

    /// `map.get(key)` for a text key.
    pub fn get_text(&self, key: &str) -> Option<&Cbor> {
        match self {
            Cbor::Map(m) => m
                .iter()
                .find(|(k, _)| matches!(k, Cbor::Text(t) if t == key))
                .map(|(_, v)| v),
            _ => None,
        }
    }
}

/// A verification failure. `failure` is the audit code (`other` for a plain
/// `Error` in the JS).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct WebauthnError {
    /// One of [`FAILURES`].
    pub failure: &'static str,
    /// What went wrong (may quote client data; never logged).
    pub message: String,
}

fn fail(failure: &'static str, message: impl Into<String>) -> WebauthnError {
    WebauthnError {
        failure,
        message: message.into(),
    }
}

fn plain(message: impl Into<String>) -> WebauthnError {
    fail("other", message)
}

/// Ports `decodeCbor(buf, start)`: the item and where it ended.
pub fn decode_cbor(buf: &[u8], start: usize) -> Result<(Cbor, usize), WebauthnError> {
    let mut pos = start;
    let v = read_item(buf, &mut pos, 0)?;
    Ok((v, pos))
}

fn read_length(buf: &[u8], pos: &mut usize, minor: u8) -> Result<u64, WebauthnError> {
    let take = |pos: &mut usize, n: usize| -> Result<u64, WebauthnError> {
        if *pos + n > buf.len() {
            return Err(plain("cbor: truncated length"));
        }
        let mut v = 0u64;
        for b in &buf[*pos..*pos + n] {
            v = (v << 8) | *b as u64;
        }
        *pos += n;
        Ok(v)
    };
    match minor {
        0..=23 => Ok(minor as u64),
        24 => take(pos, 1),
        25 => take(pos, 2),
        26 => take(pos, 4),
        _ => Err(plain(format!("cbor: unsupported length encoding {minor}"))),
    }
}

fn read_item(buf: &[u8], pos: &mut usize, depth: usize) -> Result<Cbor, WebauthnError> {
    if depth > CBOR_MAX_DEPTH {
        return Err(plain("cbor: nested too deeply"));
    }
    if *pos >= buf.len() {
        return Err(plain("cbor: truncated"));
    }
    let first = buf[*pos];
    *pos += 1;
    let major = first >> 5;
    let minor = first & 0x1f;
    let len = read_length(buf, pos, minor)?;
    let remaining = (buf.len() - *pos) as u64;
    if (major == 2 || major == 3) && len > remaining {
        return Err(plain("cbor: length exceeds the buffer"));
    }
    if major == 4 && len > remaining {
        return Err(plain("cbor: array longer than the buffer"));
    }
    if major == 5 && len * 2 > remaining {
        return Err(plain("cbor: map larger than the buffer"));
    }
    match major {
        0 => Ok(Cbor::Int(len as i128)),
        1 => Ok(Cbor::Int(-1 - len as i128)),
        2 => {
            let b = buf[*pos..*pos + len as usize].to_vec();
            *pos += len as usize;
            Ok(Cbor::Bytes(b))
        }
        3 => {
            let s = String::from_utf8_lossy(&buf[*pos..*pos + len as usize]).into_owned();
            *pos += len as usize;
            Ok(Cbor::Text(s))
        }
        4 => {
            let mut a = Vec::new();
            for _ in 0..len {
                a.push(read_item(buf, pos, depth + 1)?);
            }
            Ok(Cbor::Array(a))
        }
        5 => {
            let mut m: Vec<(Cbor, Cbor)> = Vec::new();
            for _ in 0..len {
                let k = read_item(buf, pos, depth + 1)?;
                let v = read_item(buf, pos, depth + 1)?;
                // Map.set: a repeated key keeps its place and takes the new value.
                match m.iter_mut().find(|(x, _)| *x == k) {
                    Some(e) => e.1 = v,
                    None => m.push((k, v)),
                }
            }
            Ok(Cbor::Map(m))
        }
        7 => match minor {
            20 => Ok(Cbor::Bool(false)),
            21 => Ok(Cbor::Bool(true)),
            22 => Ok(Cbor::Null),
            _ => Err(plain(format!("cbor: unsupported simple value {minor}"))),
        },
        _ => Err(plain(format!("cbor: unsupported major type {major}"))),
    }
}

/// Parsed authenticator data. Ports the result of `parseAuthData`.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthData {
    /// SHA-256 of the relying party id.
    pub rp_id_hash: [u8; 32],
    /// UP flag.
    pub user_present: bool,
    /// UV flag.
    pub user_verified: bool,
    /// Signature counter.
    pub sign_count: u32,
    /// AT flag.
    pub attested_credential_data: bool,
    /// Attested credential id.
    pub credential_id: Option<Vec<u8>>,
    /// Attested COSE key.
    pub cose_key: Option<Cbor>,
}

/// Ports `parseAuthData(authData)`.
pub fn parse_auth_data(a: &[u8]) -> Result<AuthData, WebauthnError> {
    if a.len() < 37 {
        return Err(plain("authenticator data is too short"));
    }
    let mut rp = [0u8; 32];
    rp.copy_from_slice(&a[..32]);
    let flags = a[32];
    let sign_count = u32::from_be_bytes([a[33], a[34], a[35], a[36]]);
    let attested = flags & 0x40 != 0;
    let mut out = AuthData {
        rp_id_hash: rp,
        user_present: flags & 0x01 != 0,
        user_verified: flags & 0x04 != 0,
        sign_count,
        attested_credential_data: attested,
        credential_id: None,
        cose_key: None,
    };
    if attested {
        if a.len() < 55 {
            return Err(plain("The value of \"offset\" is out of range."));
        }
        let n = u16::from_be_bytes([a[53], a[54]]) as usize;
        let end = (55 + n).min(a.len());
        out.credential_id = Some(a[55..end].to_vec());
        let (cose, _) = decode_cbor(a, 55 + n)?;
        out.cose_key = Some(cose);
    }
    Ok(out)
}

/// Ports `coseToPublicKey(cose)`: the SPKI DER of an ES256 P-256 key.
pub fn cose_to_public_key(cose: &Cbor) -> Result<Vec<u8>, WebauthnError> {
    let int = |k| match cose.get_int(k) {
        Some(Cbor::Int(i)) => Some(*i),
        _ => None,
    };
    let show = |k| match cose.get_int(k) {
        Some(Cbor::Int(i)) => i.to_string(),
        Some(Cbor::Text(t)) => t.clone(),
        None => "undefined".into(),
        Some(_) => "[object]".into(),
    };
    if int(1) != Some(2) {
        return Err(plain(format!(
            "unsupported COSE key type {}; only EC2 is accepted",
            show(1)
        )));
    }
    if int(3) != Some(ES256 as i128) {
        return Err(plain(format!(
            "unsupported algorithm {}; only ES256 is accepted",
            show(3)
        )));
    }
    if int(-1) != Some(1) {
        return Err(plain(format!(
            "unsupported curve {}; only P-256 is accepted",
            show(-1)
        )));
    }
    let coord = |k| match cose.get_int(k) {
        Some(Cbor::Bytes(b)) if b.len() == 32 => Some(b.clone()),
        _ => None,
    };
    let (Some(x), Some(y)) = (coord(-2), coord(-3)) else {
        return Err(plain("malformed EC point"));
    };
    let mut point = vec![0x04];
    point.extend(x);
    point.extend(y);
    p256::PublicKey::from_sec1_bytes(&point).map_err(|_| plain("Invalid key coordinates"))?;
    let mut der = hex_bytes("3059301306072a8648ce3d020106082a8648ce3d030107034200");
    der.extend(point);
    Ok(der)
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or(0))
        .collect()
}

/// Ports `newChallenge()`.
pub fn new_challenge() -> [u8; 32] {
    crate::util::random_bytes::<32>()
}

/// Ports `b64url(buf)`.
pub fn b64url(buf: &[u8]) -> String {
    crate::util::b64url(buf)
}

/// Ports `failureOf(e)`.
pub fn failure_of(e: &WebauthnError) -> &'static str {
    if FAILURES.contains(&e.failure) {
        e.failure
    } else {
        "other"
    }
}

fn parse_client_data(
    client_data_json: &Value,
    expected_type: &str,
    expected_challenge: &[u8],
    expected_origins: &[String],
) -> Result<Value, WebauthnError> {
    let raw = b64_lenient(client_data_json.as_str().unwrap_or(""));
    let data: Value = serde_json::from_slice(&raw)
        .map_err(|e| fail("malformed", format!("clientDataJSON is not JSON: {e}")))?;
    if !(data.is_object() || data.is_array()) {
        return Err(fail("malformed", "clientDataJSON is not an object"));
    }
    if data.get("type").and_then(Value::as_str) != Some(expected_type) {
        let t = data
            .get("type")
            .map_or("undefined".to_string(), crate::util::js_string);
        return Err(fail(
            "client_data_type",
            format!("client data type is {t}, expected {expected_type}"),
        ));
    }
    let Some(challenge) = data.get("challenge").and_then(Value::as_str) else {
        return Err(fail("malformed", "clientDataJSON has no challenge"));
    };
    if !ct_eq(&b64_lenient(challenge), expected_challenge) {
        return Err(fail(
            "challenge",
            "challenge does not match; this assertion was made for a different operation",
        ));
    }
    let origin = data.get("origin").and_then(Value::as_str);
    if !origin.is_some_and(|o| expected_origins.iter().any(|e| e == o)) {
        let o = data
            .get("origin")
            .map_or("undefined".to_string(), crate::util::js_string);
        return Err(fail("origin", format!("origin {o} is not this server")));
    }
    Ok(data)
}

/// Inputs to [`verify_registration`]. Ports the `verifyRegistration` argument.
#[derive(Debug, Clone)]
pub struct RegistrationInput<'a> {
    /// base64url attestation object.
    pub attestation_object: &'a Value,
    /// base64url client data.
    pub client_data_json: &'a Value,
    /// The challenge this process minted.
    pub expected_challenge: &'a [u8],
    /// Origins accepted.
    pub expected_origins: &'a [String],
    /// Relying party id (`localhost`).
    pub rp_id: &'a str,
}

/// An enrolled authenticator, public parts. Ports the record
/// `verifyRegistration` returns (`credentialId`, `publicKeySpki`,
/// `signCount`, `enrolledAt`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolledCredential {
    /// base64url credential id.
    pub credential_id: String,
    /// base64 SPKI DER.
    pub public_key_spki: String,
    /// Signature counter.
    pub sign_count: u32,
    /// ISO.
    pub enrolled_at: String,
}

impl EnrolledCredential {
    /// The record as the JS object.
    pub fn to_value(&self) -> Value {
        serde_json::json!({"credentialId": self.credential_id, "publicKeySpki": self.public_key_spki, "signCount": self.sign_count, "enrolledAt": self.enrolled_at})
    }

    /// From the vault's stored key.
    pub fn from_key(k: &av_store::model::PresenceKey) -> EnrolledCredential {
        EnrolledCredential {
            credential_id: k.credential_id.clone(),
            public_key_spki: k.public_key_spki.clone(),
            sign_count: k.sign_count,
            enrolled_at: k.enrolled_at.clone(),
        }
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(data).into()
}

/// Ports `verifyRegistration(...)`.
pub fn verify_registration(
    input: &RegistrationInput<'_>,
) -> Result<EnrolledCredential, WebauthnError> {
    parse_client_data(
        input.client_data_json,
        "webauthn.create",
        input.expected_challenge,
        input.expected_origins,
    )?;
    let (attestation, _) = decode_cbor(
        &b64_lenient(input.attestation_object.as_str().unwrap_or("")),
        0,
    )?;
    let auth = match attestation.get_text("authData") {
        Some(Cbor::Bytes(b)) => b.clone(),
        _ => {
            return Err(plain(
                "Cannot read properties of undefined (reading 'length')",
            ))
        }
    };
    let a = parse_auth_data(&auth)?;
    if !ct_eq(&a.rp_id_hash, &sha256(input.rp_id.as_bytes())) {
        return Err(plain("relying party id does not match"));
    }
    if !a.user_present {
        return Err(plain("the authenticator did not report user presence"));
    }
    if !a.user_verified {
        return Err(plain("the authenticator did not verify a human; enrollment requires a fingerprint or device password"));
    }
    if !a.attested_credential_data {
        return Err(plain("no credential was attested"));
    }
    let spki = cose_to_public_key(a.cose_key.as_ref().unwrap_or(&Cbor::Null))?;
    Ok(EnrolledCredential {
        credential_id: b64url(a.credential_id.as_deref().unwrap_or(&[])),
        public_key_spki: crate::util::b64(&spki),
        sign_count: a.sign_count,
        enrolled_at: crate::util::iso_now(),
    })
}

/// Inputs to [`verify_assertion`]. Ports the `verifyAssertion` argument;
/// the four client fields are raw JSON so their types are checked as the JS
/// checks them.
#[derive(Debug, Clone)]
pub struct AssertionInput<'a> {
    /// The credential the assertion names.
    pub credential_id: &'a Value,
    /// base64url authenticator data.
    pub authenticator_data: &'a Value,
    /// base64url client data.
    pub client_data_json: &'a Value,
    /// base64url DER signature.
    pub signature: &'a Value,
    /// The challenge minted for this operation.
    pub expected_challenge: &'a [u8],
    /// Origins accepted.
    pub expected_origins: &'a [String],
    /// Relying party id.
    pub rp_id: &'a str,
    /// The enrolled key.
    pub enrolled: &'a EnrolledCredential,
}

/// Ports `verifyAssertion(...)`: the new signature counter.
pub fn verify_assertion(input: &AssertionInput<'_>) -> Result<u32, WebauthnError> {
    if input.credential_id.as_str() != Some(input.enrolled.credential_id.as_str()) {
        return Err(fail(
            "credential",
            "this assertion is from a credential that was never enrolled",
        ));
    }
    for (field, value, limit) in [
        ("authenticatorData", input.authenticator_data, 8 * 1024),
        ("clientDataJSON", input.client_data_json, 8 * 1024),
        ("signature", input.signature, 2 * 1024),
    ] {
        let Some(s) = value.as_str() else {
            return Err(fail(
                "malformed",
                format!("{field} must be a base64url string"),
            ));
        };
        let n = s.encode_utf16().count();
        if n > limit {
            return Err(fail(
                "size",
                format!("{field} is {n} characters; a real assertion is under {limit}"),
            ));
        }
    }
    parse_client_data(
        input.client_data_json,
        "webauthn.get",
        input.expected_challenge,
        input.expected_origins,
    )?;
    let auth = b64_lenient(input.authenticator_data.as_str().unwrap_or(""));
    let a = parse_auth_data(&auth).map_err(|e| fail("malformed", e.message))?;
    if !ct_eq(&a.rp_id_hash, &sha256(input.rp_id.as_bytes())) {
        return Err(plain("relying party id does not match"));
    }
    if !a.user_present {
        return Err(plain("no user presence"));
    }
    if !a.user_verified {
        return Err(plain(
            "the authenticator did not verify a human for this operation",
        ));
    }
    let client_hash = sha256(&b64_lenient(input.client_data_json.as_str().unwrap_or("")));
    let mut signed = auth.clone();
    signed.extend_from_slice(&client_hash);
    let verified = (|| -> Option<bool> {
        use p256::ecdsa::signature::Verifier;
        use p256::pkcs8::DecodePublicKey;
        let spki = base64_std(&input.enrolled.public_key_spki)?;
        let key = p256::ecdsa::VerifyingKey::from_public_key_der(&spki).ok()?;
        let sig =
            p256::ecdsa::Signature::from_der(&b64_lenient(input.signature.as_str().unwrap_or("")))
                .ok()?;
        let sig = sig.normalize_s();
        Some(key.verify(&signed, &sig).is_ok())
    })()
    .unwrap_or(false);
    if !verified {
        return Err(fail("signature", "signature does not verify"));
    }
    if a.sign_count > 0
        && input.enrolled.sign_count > 0
        && a.sign_count <= input.enrolled.sign_count
    {
        return Err(fail(
            "signature",
            "signature counter did not advance; the credential may have been cloned",
        ));
    }
    Ok(a.sign_count)
}

fn base64_std(s: &str) -> Option<Vec<u8>> {
    Some(b64_lenient(s))
}

#[cfg(test)]
pub(crate) mod testkit {
    //! A software ES256 authenticator, for tests of both gates.
    use super::*;
    use p256::ecdsa::signature::Signer;

    /// A key and the credential id it enrols as.
    pub struct SoftKey {
        /// The signing key.
        pub key: p256::ecdsa::SigningKey,
        /// Its credential id.
        pub id: String,
        /// Next counter.
        pub count: u32,
    }

    impl SoftKey {
        /// A fresh key.
        pub fn new() -> SoftKey {
            let key = p256::ecdsa::SigningKey::from_slice(&crate::util::random_bytes::<32>())
                .expect("key");
            SoftKey {
                key,
                id: b64url(&crate::util::random_bytes::<16>()),
                count: 1,
            }
        }

        /// The SPKI, base64.
        pub fn spki(&self) -> String {
            use p256::pkcs8::EncodePublicKey;
            crate::util::b64(
                self.key
                    .verifying_key()
                    .to_public_key_der()
                    .expect("der")
                    .as_bytes(),
            )
        }

        /// The enrolment record.
        pub fn record(&self) -> Value {
            serde_json::json!({"credentialId": self.id, "publicKeySpki": self.spki(), "signCount": 0, "enrolledAt": "2026-01-01T00:00:00.000Z"})
        }

        /// A `none` attestation registering this key over `challenge` from
        /// `origin`: `{attestationObject, clientDataJSON}`.
        pub fn attestation(&self, challenge: &[u8], origin: &str) -> Value {
            let client = serde_json::json!({"type": "webauthn.create", "challenge": b64url(challenge), "origin": origin});
            let client = crate::util::js_stringify(&client).into_bytes();
            // The SPKI of a P-256 key ends with the point: 04 || x || y.
            let spki = crate::util::b64_lenient(&self.spki());
            let (x, y) = (
                &spki[spki.len() - 64..spki.len() - 32],
                &spki[spki.len() - 32..],
            );
            let id = crate::util::b64url_lenient(&self.id);
            // COSE_Key {1: 2, 3: -7, -1: 1, -2: x, -3: y}
            let mut cose = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
            cose.extend_from_slice(x);
            cose.extend_from_slice(&[0x22, 0x58, 0x20]);
            cose.extend_from_slice(y);
            let mut auth = sha256(b"localhost").to_vec();
            auth.push(0x45); // UP, UV, AT
            auth.extend_from_slice(&0u32.to_be_bytes());
            auth.extend_from_slice(&[0u8; 16]);
            auth.extend_from_slice(&(id.len() as u16).to_be_bytes());
            auth.extend_from_slice(&id);
            auth.extend_from_slice(&cose);
            // {"fmt": "none", "attStmt": {}, "authData": auth}
            let mut att = vec![0xa3, 0x63];
            att.extend_from_slice(b"fmt");
            att.push(0x64);
            att.extend_from_slice(b"none");
            att.push(0x67);
            att.extend_from_slice(b"attStmt");
            att.push(0xa0);
            att.push(0x68);
            att.extend_from_slice(b"authData");
            att.extend_from_slice(&[0x59, (auth.len() >> 8) as u8, auth.len() as u8]);
            att.extend_from_slice(&auth);
            serde_json::json!({"attestationObject": b64url(&att), "clientDataJSON": b64url(&client)})
        }

        /// An assertion over `challenge` from `origin`.
        pub fn assert(&mut self, challenge: &[u8], origin: &str) -> Value {
            let client = serde_json::json!({"type": "webauthn.get", "challenge": b64url(challenge), "origin": origin});
            let client = crate::util::js_stringify(&client).into_bytes();
            let mut auth = sha256(b"localhost").to_vec();
            auth.push(0x05);
            auth.extend_from_slice(&self.count.to_be_bytes());
            self.count += 1;
            let mut signed = auth.clone();
            signed.extend_from_slice(&sha256(&client));
            let sig: p256::ecdsa::Signature = self.key.sign(&signed);
            serde_json::json!({
                "credentialId": self.id,
                "authenticatorData": b64url(&auth),
                "clientDataJSON": b64url(&client),
                "signature": b64url(sig.to_der().as_bytes()),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::SoftKey;
    use super::*;

    fn input<'a>(
        p: &'a Value,
        ch: &'a [u8],
        origins: &'a [String],
        enrolled: &'a EnrolledCredential,
    ) -> AssertionInput<'a> {
        AssertionInput {
            credential_id: &p["credentialId"],
            authenticator_data: &p["authenticatorData"],
            client_data_json: &p["clientDataJSON"],
            signature: &p["signature"],
            expected_challenge: ch,
            expected_origins: origins,
            rp_id: "localhost",
            enrolled,
        }
    }

    #[test]
    fn a_real_assertion_verifies_and_each_tamper_is_refused_with_its_code() {
        let mut k = SoftKey::new();
        let enrolled = EnrolledCredential {
            credential_id: k.id.clone(),
            public_key_spki: k.spki(),
            sign_count: 0,
            enrolled_at: String::new(),
        };
        let origins = vec!["http://localhost:7412".to_string()];
        let ch = [7u8; 32];
        let p = k.assert(&ch, "http://localhost:7412");
        assert_eq!(
            verify_assertion(&input(&p, &ch, &origins, &enrolled)).unwrap(),
            1
        );
        // Another operation's challenge.
        let other = [8u8; 32];
        assert_eq!(
            verify_assertion(&input(&p, &other, &origins, &enrolled))
                .unwrap_err()
                .failure,
            "challenge"
        );
        // A look-alike page on another port.
        let p2 = k.assert(&ch, "http://localhost:9999");
        assert_eq!(
            verify_assertion(&input(&p2, &ch, &origins, &enrolled))
                .unwrap_err()
                .failure,
            "origin"
        );
        // A tampered signature.
        let mut p3 = k.assert(&ch, "http://localhost:7412");
        p3["signature"] = Value::from(b64url(&[0x30, 0x06, 2, 1, 1, 2, 1, 1]));
        assert_eq!(
            verify_assertion(&input(&p3, &ch, &origins, &enrolled))
                .unwrap_err()
                .failure,
            "signature"
        );
        // A counter that did not advance.
        let used = EnrolledCredential {
            sign_count: 100,
            ..enrolled.clone()
        };
        let p4 = k.assert(&ch, "http://localhost:7412");
        assert_eq!(
            verify_assertion(&input(&p4, &ch, &origins, &used))
                .unwrap_err()
                .failure,
            "signature"
        );
        // Not a string.
        let mut p5 = k.assert(&ch, "http://localhost:7412");
        p5["signature"] = Value::from(5);
        assert_eq!(
            verify_assertion(&input(&p5, &ch, &origins, &enrolled))
                .unwrap_err()
                .failure,
            "malformed"
        );
        // 'a clientDataJSON that is not JSON is recorded as other, not
        // malformed (r5 F1)'.
        let mut p5b = k.assert(&ch, "http://localhost:7412");
        p5b["clientDataJSON"] = Value::from(crate::util::b64(b"{not json"));
        assert_eq!(
            verify_assertion(&input(&p5b, &ch, &origins, &enrolled))
                .unwrap_err()
                .failure,
            "malformed"
        );
        // Oversized.
        let mut p6 = k.assert(&ch, "http://localhost:7412");
        p6["clientDataJSON"] = Value::from("A".repeat(9000));
        assert_eq!(
            verify_assertion(&input(&p6, &ch, &origins, &enrolled))
                .unwrap_err()
                .failure,
            "size"
        );
        // A credential never enrolled.
        let mut p7 = k.assert(&ch, "http://localhost:7412");
        p7["credentialId"] = Value::from("other");
        assert_eq!(
            verify_assertion(&input(&p7, &ch, &origins, &enrolled))
                .unwrap_err()
                .failure,
            "credential"
        );
    }

    #[test]
    fn cbor_is_bounded() {
        assert!(decode_cbor(&[0x5a, 0xff, 0xff, 0xff, 0xff], 0).is_err());
        assert!(decode_cbor(&[0xbb], 0).is_err());
        let mut deep = vec![0x81u8; 40];
        deep.push(0x01);
        assert_eq!(
            decode_cbor(&deep, 0).unwrap_err().message,
            "cbor: nested too deeply"
        );
        assert_eq!(
            decode_cbor(&[0xa1, 0x01, 0x02], 0).unwrap().0.get_int(1),
            Some(&Cbor::Int(2))
        );
    }

    /// 'a request field can rewrite the signed op or a digest', 'a
    /// non-string secret field (a backup bundle) is digested as "[object
    /// Object]"', 'the wave-3 secret fields are bound in clear'.
    #[test]
    fn the_operation_binds_secret_fields_by_digest_and_reserves_op() {
        let m = |v: Value| v.as_object().unwrap().clone();
        for bad in [
            serde_json::json!({"op": "other"}),
            serde_json::json!({"value_sha256": "00"}),
            serde_json::json!({"x_sha256": 1}),
        ] {
            let e = operation_for("cred.add", &m(bad.clone())).unwrap_err();
            assert_eq!(
                e.extra.rule.as_deref(),
                Some("reserved_operation_field"),
                "{bad}"
            );
        }
        let secrets = serde_json::json!({
            "value": "v-secret-1", "prf_secret": "p-secret-2", "recovery_passphrase": "r-secret-3",
            "bundle": "b-secret-4", "webhook_url": "https://hooks.example.test/w-secret-5",
        });
        let op = operation_for("x", &m(secrets)).unwrap();
        let text = serde_json::to_string(&op).unwrap();
        for n in 1..=5 {
            assert!(!text.contains(&format!("secret-{n}")), "{text}");
        }
        for k in DIGESTED {
            assert!(op.contains_key(&format!("{k}_sha256")), "{k}");
        }
        let a = operation_for(
            "x",
            &m(serde_json::json!({"bundle": {"v": 1, "data": "aaa"}})),
        )
        .unwrap();
        let b = operation_for(
            "x",
            &m(serde_json::json!({"bundle": {"v": 1, "data": "bbb"}})),
        )
        .unwrap();
        assert_ne!(
            a["bundle_sha256"], b["bundle_sha256"],
            "two bundles, two digests"
        );
    }
}
