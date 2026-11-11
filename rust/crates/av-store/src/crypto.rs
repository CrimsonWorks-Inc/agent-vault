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

/// 32 random bytes from the OS. Ports `randomKey` in `src/store/crypto.js`.
pub fn random_key() -> Result<Key32> {
    todo!()
}

/// Fill `buf` from the OS random source (salts, nonces, token secrets). No
/// JS function: ports the `randomBytes(n)` calls across `src/store/*.js`.
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    todo!()
}

/// HKDF-SHA256 with an empty salt and `info`, 32 bytes out. Ports `hkdf` in
/// `src/store/crypto.js` (every caller uses the default length 32).
pub fn hkdf(ikm: &[u8], info: &str) -> Key32 {
    todo!()
}

/// The key-encryption key: `HKDF(device_key || factor_key, "av/kek/v1")`.
/// `factor_key` is empty for the `none` factor. Ports `deriveKek` in
/// `src/store/crypto.js`.
pub fn derive_kek(device_key: &Key32, factor_key: &[u8]) -> Key32 {
    todo!()
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
    todo!()
}

/// The JS passphrase factor key: scrypt with [`SCRYPT_PARAMS`]. Read only:
/// `migrate` uses it once to open the JS wrap, then re-wraps under Argon2id.
/// Ports `passphraseFactor` in `src/store/crypto.js` as the JS runs it.
pub fn passphrase_factor_v1(passphrase: &SecretString, salt: &[u8]) -> Result<Key32> {
    todo!()
}

/// scrypt with explicit parameters (a v1 backup's N = 2^17). Blocking; call
/// it off the async runtime. Ports `scryptAsync` in `src/store/crypto.js`.
pub fn scrypt_key(passphrase: &SecretString, salt: &[u8], params: &ScryptParams) -> Result<Key32> {
    todo!()
}

/// Argon2id with explicit parameters, for keys other than the passphrase
/// factor (a v2 backup's m = 256 MiB). Blocking. No JS source: rust/PLAN.md,
/// "Crypto contract".
pub fn argon2_key(passphrase: &SecretString, salt: &[u8], params: &Argon2Params) -> Result<Key32> {
    todo!()
}

/// Seal `plaintext` under `key` with XChaCha20-Poly1305, a random 24-byte
/// nonce and `aad` (UTF-8; empty means none). The caller zeroizes its
/// plaintext. Ports `seal` in `src/store/crypto.js`, in format v2.
pub fn seal(key: &Key32, plaintext: &[u8], aad: &str) -> Result<SealedV2> {
    todo!()
}

/// Open a v2 sealed value to bytes the caller cannot leak by accident.
/// Ports `openBytes` in `src/store/crypto.js`, in format v2.
pub fn open(key: &Key32, sealed: &SealedV2, aad: &str) -> Result<SecretBytes> {
    todo!()
}

/// Open a v2 sealed value that holds UTF-8 text (a field value, a webhook
/// URL). Ports `open` in `src/store/crypto.js`, in format v2.
pub fn open_string(key: &Key32, sealed: &SealedV2, aad: &str) -> Result<SecretString> {
    todo!()
}

/// Open a legacy v1 sealed value (ChaCha20-Poly1305, 12-byte nonce). Only
/// `migrate` and backup restore call this. Ports `openBytes` in
/// `src/store/crypto.js` as the JS runs it.
pub fn open_v1(key: &Key32, sealed: &SealedV1, aad: &str) -> Result<SecretBytes> {
    todo!()
}

/// Per-credential data-encryption key: `HKDF(vmk, "av/dek/<cred_id>")`.
/// Ports `dek` in `src/store/crypto.js`.
pub fn dek(vmk: &Key32, cred_id: &str) -> Key32 {
    todo!()
}

/// Placeholder checksum key. Ports `kPh` in `src/store/crypto.js`.
pub fn k_ph(vmk: &Key32) -> Key32 {
    todo!()
}

/// Fingerprint key, kept apart from `k_ph` because a fingerprint is taken
/// over caller-chosen text. Ports `kFingerprint` in `src/store/crypto.js`.
pub fn k_fingerprint(vmk: &Key32) -> Key32 {
    todo!()
}

/// Audit-log key. Ports `kAudit` in `src/store/crypto.js`.
pub fn k_audit(vmk: &Key32) -> Key32 {
    todo!()
}

/// Session-token key. Ports `kToken` in `src/store/crypto.js`.
pub fn k_token(vmk: &Key32) -> Key32 {
    todo!()
}

/// The AAD of a VMK wrap: `"av/vmk/<factor>"`. No JS function: ports the
/// template literal in `#wrapVmk` / `#openWith` in `src/store/vault.js`.
pub fn vmk_aad(factor: &str) -> String {
    todo!()
}

/// The AAD of a credential field: `"<cred_id>|<field>|<key_version>"`. No JS
/// function: ports the template literal in `#sealCredential`, `#unseal` and
/// `rotateCredential` in `src/store/vault.js`.
pub fn field_aad(cred_id: &str, field: &str, key_version: u32) -> String {
    todo!()
}

/// First 8 hex characters of `HMAC-SHA256(key, value)`. Ports `fingerprint8`
/// in `src/store/crypto.js`.
pub fn fingerprint8(key: &Key32, value: &[u8]) -> String {
    todo!()
}

/// `HMAC-SHA256(key, msg)`. No JS function: ports the `createHmac('sha256',
/// key)` calls in `src/store/audit.js`.
pub fn hmac_sha256(key: &Key32, msg: &[u8]) -> [u8; 32] {
    todo!()
}

/// Lowercase hex SHA-256. No JS function: ports the
/// `createHash('sha256').update(x).digest('hex')` calls in
/// `src/store/vault.js` (token hash, policy hash, template hash, scrub
/// pattern digest) and `src/store/backup.js`.
pub fn sha256_hex(data: &[u8]) -> String {
    todo!()
}

/// Constant-time equality: false for different lengths (which leaks only the
/// length), otherwise compares every byte with `subtle`. Use for MACs, token
/// hashes, nonce hashes and placeholders. Ports `constantTimeEqual` in
/// `src/store/crypto.js`.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    todo!()
}

/// Zero a buffer in a way the optimiser keeps (`zeroize`). Ports `wipe` in
/// `src/store/crypto.js`; most Rust code gets this from `Zeroizing` on drop.
pub fn wipe(buf: &mut [u8]) {
    todo!()
}

/// `serde(with = ...)` helpers for a [`SecretString`] field in a JSON
/// document that must carry a plaintext (a backup bundle's decrypted
/// contents). No JS source: secrecy has no serde feature in this workspace.
pub mod serde_secret_string {
    use av_core::secret::SecretString;

    /// Serialize the exposed string. Only for a document that is sealed
    /// straight after. No JS source.
    pub fn serialize<S: serde::Serializer>(
        value: &SecretString,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        todo!()
    }

    /// Deserialize a string straight into a [`SecretString`]. No JS source.
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<SecretString, D::Error> {
        todo!()
    }
}
