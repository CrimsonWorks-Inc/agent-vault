//! Ports `src/store/crypto.js`: the key hierarchy, sealing, and the
//! passphrase KDF, with the changes rust/PLAN.md "Crypto contract" makes
//! (XChaCha20-Poly1305 sealed value v2, Argon2id passphrase factor). The
//! legacy v1 format (ChaCha20-Poly1305, 12-byte nonce) and scrypt are kept
//! read-only, for `agent-vault migrate` and backup restore.
//!
//! ```text
//! device.key (32 random bytes)                 -> K_dev
//! presence factor                              -> K_factor
//! KEK = HKDF-SHA256(K_dev || K_factor, "av/kek/v1")
//! KEK -AEAD-> VMK (one wrap per enrolled factor, AAD "av/vmk/<factor>")
//! VMK -HKDF-> K_ph, K_fingerprint, K_audit, K_token, DEK_<credId>
//! field ciphertext = AEAD(DEK, nonce, AAD = "<credId>|<field>|<version>")
//! ```

use av_core::secret::{Key32, SecretBytes, SecretString};
use serde::{Deserialize, Serialize};

use crate::error::Result;

// ------------------------------------------------------------ HKDF labels

/// HKDF info for the key-encryption key. Ports the `'av/kek/v1'` literal in
/// `deriveKek` in `src/store/crypto.js`.
pub const LABEL_KEK: &str = "av/kek/v1";
/// HKDF info prefix for a per-credential DEK; the credential id follows.
/// Ports the `` `av/dek/${credId}` `` template in `dek` in
/// `src/store/crypto.js`.
pub const LABEL_DEK_PREFIX: &str = "av/dek/";
/// HKDF info for the placeholder checksum key. Ports `kPh` in
/// `src/store/crypto.js`.
pub const LABEL_PH: &str = "av/ph";
/// HKDF info for the fingerprint key. Ports `kFingerprint` in
/// `src/store/crypto.js`.
pub const LABEL_FINGERPRINT: &str = "av/fingerprint";
/// HKDF info for the audit-log key. Ports `kAudit` in `src/store/crypto.js`.
pub const LABEL_AUDIT: &str = "av/audit";
/// HKDF info for the session-token key. Ports `kToken` in
/// `src/store/crypto.js`.
pub const LABEL_TOKEN: &str = "av/token";
/// AAD of the sealed notify webhook URL. Ports `NOTIFY_AAD` in
/// `src/store/vault.js`.
pub const NOTIFY_AAD: &str = "av/notify/webhook";
/// The "credential id" the notify webhook's DEK is derived from
/// (`crypt.dek(this.vmk, 'notify')`). Ports the `'notify'` literal in
/// `Vault.prototype.setNotifyWebhook` in `src/store/vault.js`.
pub const NOTIFY_DEK_ID: &str = "notify";
/// AAD prefix of a VMK wrap; the factor class follows. Ports the
/// `` `av/vmk/${factor}` `` template in `#wrapVmk` / `#openWith` in
/// `src/store/vault.js`.
pub const VMK_AAD_PREFIX: &str = "av/vmk/";

// --------------------------------------------------------- sealed formats

/// The legacy cipher name. Ports `ALG` in `src/store/crypto.js`.
pub const V1_ALG: &str = "chacha20-poly1305";
/// Legacy nonce length. Ports `NONCE_LEN` in `src/store/crypto.js`.
pub const V1_NONCE_LEN: usize = 12;
/// Poly1305 tag length, both formats. Ports `TAG_LEN` in
/// `src/store/crypto.js`.
pub const TAG_LEN: usize = 16;
/// The `v` of a sealed value v2. No JS source: rust/PLAN.md, "Crypto
/// contract".
pub const SEALED_V2: u8 = 2;
/// The `alg` of a sealed value v2. No JS source: rust/PLAN.md, "Crypto
/// contract".
pub const V2_ALG: &str = "xchacha20poly1305";
/// XChaCha20 nonce length. No JS source: rust/PLAN.md, "Crypto contract".
pub const V2_NONCE_LEN: usize = 24;
/// Salt length for the passphrase factor (both KDFs). Ports the
/// `randomBytes(16)` in `#wrapVmk` in `src/store/vault.js`.
pub const SALT_LEN: usize = 16;

/// A sealed value, format v2:
/// `{"v":2,"alg":"xchacha20poly1305","n":<b64 24-byte nonce>,"c":<b64
/// ciphertext+tag>}`. Ciphertext only, so `Debug` is safe. No JS source:
/// rust/PLAN.md, "Crypto contract" (replaces the `{ct, nonce}` that `seal`
/// in `src/store/crypto.js` returns).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedV2 {
    /// Always [`SEALED_V2`].
    pub v: u8,
    /// Always [`V2_ALG`].
    pub alg: String,
    /// Standard base64 of the 24-byte nonce.
    pub n: String,
    /// Standard base64 of ciphertext followed by the 16-byte tag.
    pub c: String,
}

/// A sealed value as the JS writes it: `{ct, nonce}`, ChaCha20-Poly1305 with
/// a 12-byte nonce, `ct` being base64 of ciphertext+tag. Read only, inside
/// `migrate` and backup restore. Ports the return value of `seal` in
/// `src/store/crypto.js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedV1 {
    /// Base64 of ciphertext followed by the 16-byte tag.
    pub ct: String,
    /// Base64 of the 12-byte nonce.
    pub nonce: String,
}

// ------------------------------------------------------------------- KDFs

/// Argon2id parameters, stored next to each passphrase wrap so they can be
/// raised later. No JS source: rust/PLAN.md, "Crypto contract" (replaces
/// `SCRYPT_PARAMS` for the passphrase factor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Always `"argon2id"`.
    pub alg: ArgonAlg,
    /// Memory cost in KiB.
    pub m: u32,
    /// Time cost (iterations).
    pub t: u32,
    /// Parallelism.
    pub p: u32,
}

/// The one Argon2 variant used. No JS source: rust/PLAN.md, "Crypto
/// contract".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArgonAlg {
    /// Argon2id.
    Argon2id,
}

/// The passphrase factor's KDF: Argon2id, m = 64 MiB, t = 3, p = 1, 32-byte
/// output. No JS source: rust/PLAN.md, "Crypto contract".
pub const PASSPHRASE_ARGON2: Argon2Params = Argon2Params {
    alg: ArgonAlg::Argon2id,
    m: 64 * 1024,
    t: 3,
    p: 1,
};

/// Argon2id output length. No JS source: rust/PLAN.md, "Crypto contract".
pub const ARGON2_OUT_LEN: usize = 32;

/// scrypt parameters, legacy. Ports the `{N, r, p, keylen, maxmem}` objects
/// of `src/store/crypto.js` and `src/store/backup.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScryptParams {
    /// log2(N).
    pub log_n: u8,
    /// Block size.
    pub r: u32,
    /// Parallelism.
    pub p: u32,
    /// Output length in bytes.
    pub keylen: usize,
    /// Node's `maxmem` ceiling in bytes (informational in Rust).
    pub maxmem: usize,
}

/// The JS passphrase factor's scrypt: N = 2^16, r = 8, p = 2, 32 bytes,
/// maxmem 256 MiB. Read only, by `migrate`. Ports `SCRYPT_PARAMS` in
/// `src/store/crypto.js`.
pub const SCRYPT_PARAMS: ScryptParams = ScryptParams {
    log_n: 16,
    r: 8,
    p: 2,
    keylen: 32,
    maxmem: 256 * 1024 * 1024,
};

// -------------------------------------------------------------- functions

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use hmac::{Hmac, Mac};
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::error::CryptoError;

/// 32 random bytes from the OS. Ports `randomKey` in `src/store/crypto.js`.
pub fn random_key() -> Result<Key32> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    fill_random(bytes.as_mut())?;
    Ok(Key32::from_bytes(*bytes))
}

/// Fill `buf` from the OS random source (salts, nonces, token secrets). No
/// JS function: ports the `randomBytes(n)` calls across `src/store/*.js`.
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| CryptoError::Rng)?;
    Ok(())
}

/// HKDF-SHA256 with an empty salt and `info`, 32 bytes out. Ports `hkdf` in
/// `src/store/crypto.js` (every caller uses the default length 32).
pub fn hkdf(ikm: &[u8], info: &str) -> Key32 {
    // Node's hkdfSync with a zero-length salt is RFC 5869 with the salt
    // defaulting to HashLen zeros, which is what `None` means here too.
    let hk = hkdf::Hkdf::<Sha256>::new(None, ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info.as_bytes(), out.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    Key32::from_bytes(*out)
}

/// The key-encryption key: `HKDF(device_key || factor_key, "av/kek/v1")`.
/// `factor_key` is empty for the `none` factor. Ports `deriveKek` in
/// `src/store/crypto.js`.
pub fn derive_kek(device_key: &Key32, factor_key: &[u8]) -> Key32 {
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 + factor_key.len()));
    ikm.extend_from_slice(device_key.expose());
    ikm.extend_from_slice(factor_key);
    hkdf(&ikm, LABEL_KEK)
}

/// The passphrase factor key: Argon2id over the passphrase and the wrap's
/// 16-byte salt, with the parameters stored beside the wrap. Deliberately
/// slow: call it off the async runtime (`spawn_blocking`). Ports
/// `passphraseFactor` in `src/store/crypto.js`, with Argon2id per
/// rust/PLAN.md, "Crypto contract".
pub fn passphrase_factor(
    passphrase: &SecretString,
    salt: &[u8],
    params: &Argon2Params,
) -> Result<Key32> {
    argon2_key(passphrase, salt, params)
}

/// The JS passphrase factor key: scrypt with [`SCRYPT_PARAMS`]. Read only:
/// `migrate` uses it once to open the JS wrap, then re-wraps under Argon2id.
/// Ports `passphraseFactor` in `src/store/crypto.js` as the JS runs it.
pub fn passphrase_factor_v1(passphrase: &SecretString, salt: &[u8]) -> Result<Key32> {
    scrypt_key(passphrase, salt, &SCRYPT_PARAMS)
}

/// scrypt with explicit parameters (a v1 backup's N = 2^17). Blocking; call
/// it off the async runtime. Ports `scryptAsync` in `src/store/crypto.js`.
pub fn scrypt_key(passphrase: &SecretString, salt: &[u8], params: &ScryptParams) -> Result<Key32> {
    if params.keylen != 32 {
        return Err(CryptoError::KeyLength.into());
    }
    let p = scrypt::Params::new(params.log_n, params.r, params.p).map_err(|_| CryptoError::Kdf)?;
    let mut out = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(
        passphrase.expose_secret().as_bytes(),
        salt,
        &p,
        out.as_mut(),
    )
    .map_err(|_| CryptoError::Kdf)?;
    Ok(Key32::from_bytes(*out))
}

/// Argon2id with explicit parameters, for keys other than the passphrase
/// factor (a v2 backup's m = 256 MiB). Blocking. No JS source: rust/PLAN.md,
/// "Crypto contract".
pub fn argon2_key(passphrase: &SecretString, salt: &[u8], params: &Argon2Params) -> Result<Key32> {
    let p = argon2::Params::new(params.m, params.t, params.p, Some(ARGON2_OUT_LEN))
        .map_err(|_| CryptoError::Kdf)?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; 32]);
    a.hash_password_into(passphrase.expose_secret().as_bytes(), salt, out.as_mut())
        .map_err(|_| CryptoError::Kdf)?;
    Ok(Key32::from_bytes(*out))
}

/// Seal `plaintext` under `key` with XChaCha20-Poly1305, a random 24-byte
/// nonce and `aad` (UTF-8; empty means none). The caller zeroizes its
/// plaintext. Ports `seal` in `src/store/crypto.js`, in format v2.
pub fn seal(key: &Key32, plaintext: &[u8], aad: &str) -> Result<SealedV2> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| CryptoError::KeyLength)?;
    let mut nonce = [0u8; V2_NONCE_LEN];
    fill_random(&mut nonce)?;
    let ct = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| CryptoError::Open)?;
    Ok(SealedV2 {
        v: SEALED_V2,
        alg: V2_ALG.to_string(),
        n: B64.encode(nonce),
        c: B64.encode(ct),
    })
}

/// Open a v2 sealed value to bytes the caller cannot leak by accident.
/// Ports `openBytes` in `src/store/crypto.js`, in format v2.
pub fn open(key: &Key32, sealed: &SealedV2, aad: &str) -> Result<SecretBytes> {
    if sealed.v != SEALED_V2 || sealed.alg != V2_ALG {
        return Err(CryptoError::Malformed.into());
    }
    let nonce = B64.decode(&sealed.n).map_err(|_| CryptoError::Malformed)?;
    let nonce: [u8; V2_NONCE_LEN] = nonce.try_into().map_err(|_| CryptoError::Malformed)?;
    let ct = B64.decode(&sealed.c).map_err(|_| CryptoError::Malformed)?;
    if ct.len() < TAG_LEN {
        return Err(CryptoError::Malformed.into());
    }
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| CryptoError::KeyLength)?;
    let plain = cipher
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: &ct,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| CryptoError::Open)?;
    Ok(SecretBytes::from(plain))
}

/// Open a v2 sealed value that holds UTF-8 text (a field value, a webhook
/// URL). Ports `open` in `src/store/crypto.js`, in format v2.
pub fn open_string(key: &Key32, sealed: &SealedV2, aad: &str) -> Result<SecretString> {
    let bytes = open(key, sealed, aad)?;
    bytes_to_secret_string(bytes)
}

/// Bytes to text without leaving a copy behind. Not UTF-8 is malformed.
pub(crate) fn bytes_to_secret_string(bytes: SecretBytes) -> Result<SecretString> {
    let mut v = bytes.expose_secret().to_vec();
    match String::from_utf8(std::mem::take(&mut v)) {
        Ok(s) => Ok(SecretString::from(s)),
        Err(e) => {
            let mut raw = e.into_bytes();
            raw.zeroize();
            Err(CryptoError::Malformed.into())
        }
    }
}

/// Open a legacy v1 sealed value (ChaCha20-Poly1305, 12-byte nonce). Only
/// `migrate` and backup restore call this. Ports `openBytes` in
/// `src/store/crypto.js` as the JS runs it.
pub fn open_v1(key: &Key32, sealed: &SealedV1, aad: &str) -> Result<SecretBytes> {
    let nonce = B64
        .decode(&sealed.nonce)
        .map_err(|_| CryptoError::Malformed)?;
    let nonce: [u8; V1_NONCE_LEN] = nonce.try_into().map_err(|_| CryptoError::Malformed)?;
    let ct = B64.decode(&sealed.ct).map_err(|_| CryptoError::Malformed)?;
    if ct.len() < TAG_LEN {
        return Err(CryptoError::Malformed.into());
    }
    let cipher =
        ChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| CryptoError::KeyLength)?;
    let plain = cipher
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: &ct,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| CryptoError::Open)?;
    Ok(SecretBytes::from(plain))
}

/// Seal in the legacy v1 format. Test-only: nothing in the port writes v1,
/// but the tests need JS-shaped values to read back.
#[cfg(test)]
pub(crate) fn seal_v1(key: &Key32, plaintext: &[u8], aad: &str) -> Result<SealedV1> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| CryptoError::KeyLength)?;
    let mut nonce = [0u8; V1_NONCE_LEN];
    fill_random(&mut nonce)?;
    let ct = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| CryptoError::Open)?;
    Ok(SealedV1 {
        ct: B64.encode(ct),
        nonce: B64.encode(nonce),
    })
}

/// Per-credential data-encryption key: `HKDF(vmk, "av/dek/<cred_id>")`.
/// Ports `dek` in `src/store/crypto.js`.
pub fn dek(vmk: &Key32, cred_id: &str) -> Key32 {
    hkdf(vmk.expose(), &[LABEL_DEK_PREFIX, cred_id].concat())
}

/// Placeholder checksum key. Ports `kPh` in `src/store/crypto.js`.
pub fn k_ph(vmk: &Key32) -> Key32 {
    hkdf(vmk.expose(), LABEL_PH)
}

/// Fingerprint key, kept apart from `k_ph` because a fingerprint is taken
/// over caller-chosen text. Ports `kFingerprint` in `src/store/crypto.js`.
pub fn k_fingerprint(vmk: &Key32) -> Key32 {
    hkdf(vmk.expose(), LABEL_FINGERPRINT)
}

/// Audit-log key. Ports `kAudit` in `src/store/crypto.js`.
pub fn k_audit(vmk: &Key32) -> Key32 {
    hkdf(vmk.expose(), LABEL_AUDIT)
}

/// Session-token key. Ports `kToken` in `src/store/crypto.js`.
pub fn k_token(vmk: &Key32) -> Key32 {
    hkdf(vmk.expose(), LABEL_TOKEN)
}

/// The AAD of a VMK wrap: `"av/vmk/<factor>"`. No JS function: ports the
/// template literal in `#wrapVmk` / `#openWith` in `src/store/vault.js`.
pub fn vmk_aad(factor: &str) -> String {
    [VMK_AAD_PREFIX, factor].concat()
}

/// The AAD of a credential field: `"<cred_id>|<field>|<key_version>"`. No JS
/// function: ports the template literal in `#sealCredential`, `#unseal` and
/// `rotateCredential` in `src/store/vault.js`.
pub fn field_aad(cred_id: &str, field: &str, key_version: u32) -> String {
    [cred_id, "|", field, "|", &key_version.to_string()].concat()
}

/// First 8 hex characters of `HMAC-SHA256(key, value)`. Ports `fingerprint8`
/// in `src/store/crypto.js`.
pub fn fingerprint8(key: &Key32, value: &[u8]) -> String {
    let mut h = hex(&hmac_sha256(key, value));
    h.truncate(8);
    h
}

/// `HMAC-SHA256(key, msg)`. No JS function: ports the `createHmac('sha256',
/// key)` calls in `src/store/audit.js`.
pub fn hmac_sha256(key: &Key32, msg: &[u8]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key.expose())
        .expect("HMAC takes a key of any length");
    m.update(msg);
    m.finalize().into_bytes().into()
}

/// Lowercase hex SHA-256. No JS function: ports the
/// `createHash('sha256').update(x).digest('hex')` calls in
/// `src/store/vault.js` (token hash, policy hash, template hash, scrub
/// pattern digest) and `src/store/backup.js`.
pub fn sha256_hex(data: &[u8]) -> String {
    let d: [u8; 32] = Sha256::digest(data).into();
    hex(&d)
}

/// Lowercase hex of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 15) as usize] as char);
    }
    s
}

/// Constant-time equality: false for different lengths (which leaks only the
/// length), otherwise compares every byte with `subtle`. Use for MACs, token
/// hashes, nonce hashes and placeholders. Ports `constantTimeEqual` in
/// `src/store/crypto.js`.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// Zero a buffer in a way the optimiser keeps (`zeroize`). Ports `wipe` in
/// `src/store/crypto.js`; most Rust code gets this from `Zeroizing` on drop.
pub fn wipe(buf: &mut [u8]) {
    buf.zeroize();
}

/// Standard base64 (with padding), as Node's `toString('base64')`.
pub(crate) fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

/// Decode standard base64 strictly: only text that is exactly what
/// [`b64`] would write for the bytes, as the JS `isB64` round trip.
pub(crate) fn b64_strict(s: &str) -> Option<Vec<u8>> {
    let bytes = B64.decode(s).ok()?;
    (B64.encode(&bytes) == s).then_some(bytes)
}

/// Decode standard base64 the lenient way Node's `Buffer.from(s, 'base64')`
/// does for a well-formed value (padding optional).
pub(crate) fn b64_decode(s: &str) -> Option<Vec<u8>> {
    B64.decode(s).ok().or_else(|| {
        base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(s.trim_end_matches('='))
            .ok()
    })
}

/// `serde(with = ...)` helpers for a [`SecretString`] field in a JSON
/// document that must carry a plaintext (a backup bundle's decrypted
/// contents). No JS source: secrecy has no serde feature in this workspace.
pub mod serde_secret_string {
    use av_core::secret::SecretString;
    use secrecy::ExposeSecret;
    use serde::Deserialize;

    /// Serialize the exposed string. Only for a document that is sealed
    /// straight after. No JS source.
    pub fn serialize<S: serde::Serializer>(
        value: &SecretString,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(value.expose_secret())
    }

    /// Deserialize a string straight into a [`SecretString`]. No JS source.
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<SecretString, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(SecretString::from(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> Key32 {
        Key32::from_bytes([b; 32])
    }

    #[test]
    fn hkdf_kek_and_fingerprint_match_node() {
        // Vectors from Node's hkdfSync/createHmac, as src/store/crypto.js
        // calls them, so the same VMK gives the same keys after migrate.
        assert_eq!(
            hex(hkdf(&[7u8; 32], LABEL_PH).expose()),
            "e3034b0376956d63bd7776ae3afc63f425feb2c0df4533547e54ec0035842bad"
        );
        assert_eq!(
            hex(derive_kek(&key(1), b"x").expose()),
            "452dae28d069680fa6564d77fa6c391f2f37c289cc43787f857695695202e3db"
        );
        assert_eq!(fingerprint8(&k_fingerprint(&key(9)), b"value"), "167764e8");
    }

    #[test]
    fn labels_are_the_js_labels() {
        assert_eq!(LABEL_KEK, "av/kek/v1");
        assert_eq!(LABEL_DEK_PREFIX, "av/dek/");
        assert_eq!(LABEL_PH, "av/ph");
        assert_eq!(LABEL_FINGERPRINT, "av/fingerprint");
        assert_eq!(LABEL_AUDIT, "av/audit");
        assert_eq!(LABEL_TOKEN, "av/token");
        assert_eq!(NOTIFY_AAD, "av/notify/webhook");
        assert_eq!(vmk_aad("passphrase"), "av/vmk/passphrase");
        assert_eq!(field_aad("cred_1", "token", 3), "cred_1|token|3");
    }

    #[test]
    fn seal_round_trips_and_binds_the_aad() {
        let k = key(1);
        let s = seal(&k, b"test-secret-value", "cred_1|token|1").unwrap();
        assert_eq!(s.v, 2);
        assert_eq!(s.alg, "xchacha20poly1305");
        assert_eq!(B64.decode(&s.n).unwrap().len(), 24);
        let back = open_string(&k, &s, "cred_1|token|1").unwrap();
        assert_eq!(back.expose_secret(), "test-secret-value");
        assert!(matches!(
            open(&k, &s, "cred_2|token|1"),
            Err(crate::error::Error::Crypto(CryptoError::Open))
        ));
        assert!(open(&key(2), &s, "cred_1|token|1").is_err());
    }

    #[test]
    fn a_tampered_or_malformed_seal_is_refused() {
        let k = key(3);
        let mut s = seal(&k, b"abc", "").unwrap();
        let mut ct = B64.decode(&s.c).unwrap();
        ct[0] ^= 1;
        s.c = B64.encode(&ct);
        assert!(open(&k, &s, "").is_err());
        let mut short = seal(&k, b"abc", "").unwrap();
        short.n = B64.encode([0u8; 12]);
        assert!(matches!(
            open(&k, &short, ""),
            Err(crate::error::Error::Crypto(CryptoError::Malformed))
        ));
        let mut v1 = seal(&k, b"abc", "").unwrap();
        v1.v = 1;
        assert!(open(&k, &v1, "").is_err());
    }

    #[test]
    fn two_seals_of_one_value_differ() {
        let k = key(4);
        let a = seal(&k, b"same", "x").unwrap();
        let b = seal(&k, b"same", "x").unwrap();
        assert_ne!(a.n, b.n);
        assert_ne!(a.c, b.c);
    }

    #[test]
    fn the_v1_format_is_still_readable() {
        let k = key(5);
        let s = seal_v1(&k, b"legacy", "av/vmk/none").unwrap();
        assert_eq!(B64.decode(&s.nonce).unwrap().len(), 12);
        let back = open_v1(&k, &s, "av/vmk/none").unwrap();
        assert_eq!(back.expose_secret(), b"legacy");
        assert!(open_v1(&k, &s, "av/vmk/passphrase").is_err());
    }

    #[test]
    fn keys_are_separated_by_label() {
        let vmk = key(9);
        let all = [
            hex(k_ph(&vmk).expose()),
            hex(k_fingerprint(&vmk).expose()),
            hex(k_audit(&vmk).expose()),
            hex(k_token(&vmk).expose()),
            hex(dek(&vmk, "cred_a").expose()),
            hex(dek(&vmk, "cred_b").expose()),
        ];
        let set: std::collections::BTreeSet<_> = all.iter().collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn kek_depends_on_both_halves() {
        let d = key(1);
        assert_ne!(
            hex(derive_kek(&d, b"").expose()),
            hex(derive_kek(&d, b"x").expose())
        );
        assert_ne!(
            hex(derive_kek(&d, b"").expose()),
            hex(derive_kek(&key(2), b"").expose())
        );
    }

    #[test]
    fn fingerprint_is_eight_hex() {
        let f = fingerprint8(&key(1), b"value");
        assert_eq!(f.len(), 8);
        assert!(f.bytes().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn constant_time_eq_is_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn sha256_hex_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hmac_known_vector() {
        // RFC 4231 test case 2.
        let mut k = [0u8; 32];
        k[..4].copy_from_slice(b"Jefe");
        // HMAC pads a short key with zeros, so a 32-byte zero-padded key is
        // the same key.
        let mac = hmac_sha256(&Key32::from_bytes(k), b"what do ya want for nothing?");
        assert_eq!(
            hex(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn argon2_is_deterministic_per_salt_and_small_params_work() {
        let small = Argon2Params {
            alg: ArgonAlg::Argon2id,
            m: 64,
            t: 1,
            p: 1,
        };
        let pw = SecretString::from("correct horse".to_string());
        let a = argon2_key(&pw, &[1u8; 16], &small).unwrap();
        let b = argon2_key(&pw, &[1u8; 16], &small).unwrap();
        let c = argon2_key(&pw, &[2u8; 16], &small).unwrap();
        assert_eq!(a.expose(), b.expose());
        assert_ne!(a.expose(), c.expose());
    }

    #[test]
    fn scrypt_known_vector() {
        // RFC 7914 section 12, second vector, first 32 bytes.
        let p = ScryptParams {
            log_n: 10,
            r: 8,
            p: 16,
            keylen: 32,
            maxmem: 0,
        };
        let k = scrypt_key(&SecretString::from("password".to_string()), b"NaCl", &p).unwrap();
        assert_eq!(
            hex(k.expose()),
            "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162"
        );
    }

    #[test]
    fn the_passphrase_kdf_is_the_planned_argon2id() {
        assert_eq!(PASSPHRASE_ARGON2.m, 64 * 1024);
        assert_eq!(PASSPHRASE_ARGON2.t, 3);
        assert_eq!(PASSPHRASE_ARGON2.p, 1);
        assert_eq!(SALT_LEN, 16);
        assert_eq!(
            serde_json::to_value(PASSPHRASE_ARGON2).unwrap(),
            serde_json::json!({"alg":"argon2id","m":65536,"t":3,"p":1})
        );
    }

    #[test]
    fn strict_base64_refuses_lenient_spellings() {
        assert_eq!(b64_strict("YWJj").unwrap(), b"abc");
        assert!(b64_strict("YWJ").is_none());
        assert!(b64_strict("YW Jj").is_none());
    }

    #[test]
    fn wipe_zeroes() {
        let mut b = [1u8, 2, 3];
        wipe(&mut b);
        assert_eq!(b, [0, 0, 0]);
    }
}
