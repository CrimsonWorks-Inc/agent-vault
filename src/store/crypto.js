// The key hierarchy.
//
//   device.key (32 random bytes, 0600, created at setup)  ->  K_dev
//   presence factor                                       ->  K_factor
//   KEK = HKDF-SHA256(K_dev || K_factor, "av/kek/v1")
//   KEK  -AEAD->  VMK (32 random bytes, one wrap per enrolled factor)
//   VMK  -HKDF->  K_ph, K_audit, DEK_cred_<id>
//   field ciphertext = AEAD(DEK, random nonce, AAD = credId|field|version)
//
// Per-field keys mean reading one credential never brings the whole vault into
// memory, and the AAD binds a ciphertext to the exact field it belongs to, so a
// blob cannot be moved between credentials.
//
// Deviations from the spec, deliberate and documented: ChaCha20-Poly1305 with a
// 96-bit nonce instead of XChaCha20 with 192 bits (Node exposes the IETF
// construction; per-field keys keep each key's record count far below the
// birthday bound), and scrypt instead of Argon2id for the passphrase factor
// (Node has no Argon2 without a native dependency). Both are called out in the
// README as items the Rust port fixes.

import { createCipheriv, createDecipheriv, randomBytes, hkdfSync, scryptSync, createHmac, timingSafeEqual } from 'node:crypto'

const ALG = 'chacha20-poly1305'
const NONCE_LEN = 12
const TAG_LEN = 16

export const SCRYPT_PARAMS = { N: 1 << 16, r: 8, p: 2, keylen: 32, maxmem: 256 * 1024 * 1024 }

export function randomKey() { return randomBytes(32) }

export function hkdf(ikm, info, length = 32) {
  return Buffer.from(hkdfSync('sha256', ikm, Buffer.alloc(0), info, length))
}

/** Derive the key-encryption key from the device key and an optional factor. */
export function deriveKek(deviceKey, factorKey = Buffer.alloc(0)) {
  return hkdf(Buffer.concat([deviceKey, factorKey]), 'av/kek/v1')
}

/** Derive a passphrase factor key. Deliberately slow. */
export function passphraseFactor(passphrase, salt) {
  return scryptSync(passphrase, salt, SCRYPT_PARAMS.keylen, SCRYPT_PARAMS)
}

export function seal(key, plaintext, aad = '') {
  const nonce = randomBytes(NONCE_LEN)
  const cipher = createCipheriv(ALG, key, nonce, { authTagLength: TAG_LEN })
  if (aad) cipher.setAAD(Buffer.from(aad, 'utf8'))
  const body = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()])
  return { ct: Buffer.concat([body, cipher.getAuthTag()]).toString('base64'), nonce: nonce.toString('base64') }
}

export function open(key, sealed, aad = '') {
  const raw = Buffer.from(sealed.ct, 'base64')
  const nonce = Buffer.from(sealed.nonce, 'base64')
  const body = raw.subarray(0, raw.length - TAG_LEN)
  const tag = raw.subarray(raw.length - TAG_LEN)
  const decipher = createDecipheriv(ALG, key, nonce, { authTagLength: TAG_LEN })
  if (aad) decipher.setAAD(Buffer.from(aad, 'utf8'))
  decipher.setAuthTag(tag)
  return Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8')
}

/** Per-credential data-encryption key. */
export function dek(vmk, credId) { return hkdf(vmk, `av/dek/${credId}`) }
export function kPh(vmk) { return hkdf(vmk, 'av/ph') }
/**
 * A separate key for the fingerprints shown in the UI and CLI.
 *
 * These used to be HMACs under K_ph — the same key the placeholder checksum
 * uses. A fingerprint is computed over a value the CALLER chooses and then
 * displayed, so that was a chosen-message oracle for K_ph: add a credential
 * whose value is `av1.<sid>.<label>.<nonce>`, read the fingerprint back from
 * `cred list`, and you have the first 32 bits of the same HMAC the 30-bit
 * checksum is taken from. Any placeholder's checksum, forged, without the key.
 */
export function kFingerprint(vmk) { return hkdf(vmk, 'av/fingerprint') }
export function kAudit(vmk) { return hkdf(vmk, 'av/audit') }
export function kToken(vmk) { return hkdf(vmk, 'av/token') }

/**
 * Short fingerprint shown in the UI and CLI in place of a value. Keyed
 * separately from the placeholder checksum: see kFingerprint above.
 */
export function fingerprint8(key, value) {
  return createHmac('sha256', key).update(value).digest('hex').slice(0, 8)
}

export function constantTimeEqual(a, b) {
  const ba = Buffer.from(a)
  const bb = Buffer.from(b)
  return ba.length === bb.length && timingSafeEqual(ba, bb)
}

/** Best-effort zeroing. Node can copy buffers behind our back, so this reduces
 *  the window rather than closing it; the Rust daemon uses real zeroize+mlock. */
export function wipe(buf) {
  if (Buffer.isBuffer(buf)) buf.fill(0)
}
