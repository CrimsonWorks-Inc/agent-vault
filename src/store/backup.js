// Encrypted backup and controlled restore (F8).
//
// The bundle holds every credential value, protected only by a recovery
// passphrase chosen by whoever runs the export, so exporting needs a fresh
// proof of presence (the daemon's job) and the bundle itself is never logged:
// only its digest is. Everything here is the vault's own cryptography — the
// same scrypt and the same ChaCha20-Poly1305 seal (src/store/crypto.js) — at
// the parameters F8 fixes, and nothing is ever written to disk in the clear:
// export writes nothing but its audit record, and restore goes through the
// vault's restoreEntries, which seals each value as it stores it.
//
// What a bundle carries is a closed list. Sessions, grants, placeholders,
// approvals, listeners, factors, wraps, settings and the audit log are not in
// it, so a restore gives no capability back, and a bundle that carries
// anything else — a factor, a wrap, a session — is refused whole rather than
// partly read. Restore is all or nothing, never touches the vault's factors,
// and checks the factor invariant (assertFactorInvariant) before it writes.

import { createHash, randomBytes } from 'node:crypto'
import * as crypt from './crypto.js'
import * as ph from '../core/placeholder.js'
import { deny } from '../core/errors.js'
import { canonicalOperation } from '../ui/webauthn.js'

export const BACKUP_FORMAT = 'agent-vault-backup'
export const BACKUP_VERSION = 1
// The bundle's KDF is fixed, not chosen by the bundle: a bundle that named
// its own work factor could make inspecting it cost whatever it liked.
export const BACKUP_KDF = Object.freeze({ name: 'scrypt', N: 131072, r: 8, p: 1 })
const CIPHER = 'chacha20-poly1305'
const MAXMEM = 256 * 1024 * 1024
const MAX_BUNDLE_BYTES = 16 * 1024 * 1024
const MIN_RECOVERY = 12
const CONFLICT_MODES = new Set(['skip', 'rename', 'fail'])

const CRED_KEYS = new Set(['slug', 'kind', 'connector', 'created_at', 'fields', 'scrub_patterns', 'pins', 'expires_at'])
const FIELD_KEYS = new Set(['name', 'value', 'sites'])
const PATTERN_KEYS = new Set(['id', 'source', 'added_at'])
const TEMPLATE_KEYS = new Set(['name', 'spec'])

const aadOf = (b) => `${b.format}|${b.version}|${b.created_at}`

/** The digest a bundle is logged by: over its canonical form, so key order does not change it. */
export function bundleDigest(bundle) {
  return createHash('sha256').update(canonicalOperation(bundle)).digest('hex')
}

function formatError(why) {
  return deny('AV_POLICY_DENIED', `not a usable backup: ${why}`, { rule: 'backup_format' })
}

function checkRecovery(recoveryPassphrase) {
  if (typeof recoveryPassphrase !== 'string' || recoveryPassphrase.length < MIN_RECOVERY) {
    throw deny('AV_POLICY_DENIED', `the recovery passphrase must be at least ${MIN_RECOVERY} characters`, { rule: 'recovery_passphrase' })
  }
}

function requireUnlocked(vault) {
  if (vault.locked) throw deny('AV_LOCKED', 'the vault is locked')
}

function keyFor(recoveryPassphrase, salt) {
  return crypt.scryptAsync(recoveryPassphrase, salt, { ...BACKUP_KDF, keylen: 32, maxmem: MAXMEM })
}

const isB64 = (s, bytes) => typeof s === 'string' && Buffer.from(s, 'base64').toString('base64') === s &&
  (bytes === undefined || Buffer.from(s, 'base64').length === bytes)
const plainObject = (o) => !!o && typeof o === 'object' && !Array.isArray(o)
const onlyKeys = (o, allowed) => Object.keys(o).every((k) => allowed.has(k))

/** The envelope, checked before any key is derived from it. */
function checkEnvelope(bundle) {
  if (!plainObject(bundle)) throw formatError('a bundle is a JSON object')
  if (bundle.format !== BACKUP_FORMAT || bundle.version !== BACKUP_VERSION) throw formatError(`expected ${BACKUP_FORMAT} version ${BACKUP_VERSION}`)
  let size
  try { size = Buffer.byteLength(JSON.stringify(bundle)) } catch { throw formatError('it is not JSON') }
  if (size > MAX_BUNDLE_BYTES) throw formatError('it is over 16 MiB')
  const k = bundle.kdf
  if (!plainObject(k) || k.name !== BACKUP_KDF.name || k.N !== BACKUP_KDF.N || k.r !== BACKUP_KDF.r || k.p !== BACKUP_KDF.p || !isB64(k.salt, 16)) {
    throw formatError('its key derivation is not the one this format uses')
  }
  if (bundle.cipher !== CIPHER || !isB64(bundle.nonce, 12) || !isB64(bundle.ct) || typeof bundle.created_at !== 'string') {
    throw formatError('its cipher, nonce or ciphertext is malformed')
  }
}

/** The plaintext, checked against the closed list of what a bundle may carry. */
function checkPlaintext(plain) {
  if (!plainObject(plain) || !onlyKeys(plain, new Set(['credentials', 'templates'])) ||
    !Array.isArray(plain.credentials) || !Array.isArray(plain.templates)) {
    throw formatError('it carries something other than credentials and templates')
  }
  for (const c of plain.credentials) {
    if (!plainObject(c) || !onlyKeys(c, CRED_KEYS) || !ph.isValidSlug(c.slug) || typeof c.kind !== 'string' ||
      (c.connector != null && !plainObject(c.connector)) || !Array.isArray(c.fields) || !c.fields.length) {
      throw formatError('a credential entry is malformed')
    }
    for (const f of c.fields) {
      if (!plainObject(f) || !onlyKeys(f, FIELD_KEYS) || !ph.isValidField(f.name) || typeof f.value !== 'string' || !f.value ||
        (f.sites != null && (!Array.isArray(f.sites) || !f.sites.every((s) => typeof s === 'string')))) {
        throw formatError(`a field of ${c.slug} is malformed`)
      }
    }
    if (new Set(c.fields.map((f) => f.name)).size !== c.fields.length) throw formatError(`${c.slug} names a field twice`)
    if (c.scrub_patterns != null && (!Array.isArray(c.scrub_patterns) ||
      !c.scrub_patterns.every((p) => plainObject(p) && onlyKeys(p, PATTERN_KEYS) && typeof p.source === 'string'))) {
      throw formatError(`the scrub patterns of ${c.slug} are malformed`)
    }
    if (c.pins != null && (!plainObject(c.pins) || !Object.values(c.pins).every((l) => Array.isArray(l) && l.every((p) => typeof p === 'string')))) {
      throw formatError(`the pins of ${c.slug} are malformed`)
    }
    if (c.expires_at != null && (typeof c.expires_at !== 'string' || Number.isNaN(Date.parse(c.expires_at)))) {
      throw formatError(`the expiry of ${c.slug} is malformed`)
    }
  }
  for (const t of plain.templates) {
    // The same rules saveTemplate applies, so a restore cannot stop halfway on one.
    if (!plainObject(t) || !onlyKeys(t, TEMPLATE_KEYS) || typeof t.name !== 'string' || !/^[a-z0-9][a-z0-9-]{0,31}$/.test(t.name) ||
      !plainObject(t.spec) || ['template', 'template_hash', 'presence'].some((k) => Object.hasOwn(t.spec, k)) ||
      Buffer.byteLength(JSON.stringify(t.spec)) > 16 * 1024) {
      throw formatError('a template entry is malformed')
    }
  }
  return plain
}

/** Decrypt and check a bundle. Wrong passphrase and tampering are one answer. */
async function openBundle(bundle, recoveryPassphrase) {
  checkEnvelope(bundle)
  checkRecovery(recoveryPassphrase)
  const key = await keyFor(recoveryPassphrase, Buffer.from(bundle.kdf.salt, 'base64'))
  let bytes = null
  try {
    try {
      bytes = crypt.openBytes(key, { ct: bundle.ct, nonce: bundle.nonce }, aadOf(bundle))
    } catch {
      throw deny('AV_PRESENCE_DENIED', 'the recovery passphrase is wrong, or the bundle was altered', { rule: 'backup_auth' })
    }
    let plain
    try { plain = JSON.parse(bytes.toString('utf8')) } catch { throw formatError('its contents are not JSON') }
    return checkPlaintext(plain)
  } finally {
    crypt.wipe(bytes)
    crypt.wipe(key)
  }
}

/**
 * Seal every credential (current values only), its scrub patterns, pins and
 * expiry, and every template, under a key derived from the recovery
 * passphrase. Recorded by digest, after it is built: a vault that locked while
 * the key was being derived cannot record it, so it hands nothing out.
 */
export async function exportBackup(vault, { recoveryPassphrase } = {}) {
  checkRecovery(recoveryPassphrase)
  requireUnlocked(vault)
  const createdAt = new Date().toISOString()
  const credentials = vault.backupCredentials()
  const templates = vault.listTemplates().map(({ name, spec }) => ({ name, spec }))
  const salt = randomBytes(16)
  const key = await keyFor(recoveryPassphrase, salt)
  const bytes = Buffer.from(JSON.stringify({ credentials, templates }), 'utf8')
  let sealed
  try {
    sealed = crypt.seal(key, bytes, aadOf({ format: BACKUP_FORMAT, version: BACKUP_VERSION, created_at: createdAt }))
  } finally {
    crypt.wipe(bytes)
    crypt.wipe(key)
  }
  requireUnlocked(vault)
  const bundle = {
    format: BACKUP_FORMAT, version: BACKUP_VERSION, created_at: createdAt,
    kdf: { ...BACKUP_KDF, salt: salt.toString('base64') },
    cipher: CIPHER, nonce: sealed.nonce, ct: sealed.ct,
  }
  const digest = bundleDigest(bundle)
  vault.audit.write('backup.exported', { credentials: credentials.length, templates: templates.length, bundle_sha256: digest })
  return { bundle, summary: { credentials: credentials.length, templates: templates.length, created_at: createdAt }, bundle_sha256: digest }
}

/** What a bundle holds, without its values, and without touching any vault. */
export async function inspectBackup(bundle, { recoveryPassphrase } = {}) {
  const plain = await openBundle(bundle, recoveryPassphrase)
  return {
    created_at: bundle.created_at,
    credentials: plain.credentials.map((c) => ({
      slug: c.slug, kind: c.kind, host: c.connector?.host ?? null,
      fields: c.fields.map((f) => f.name),
      has_scrub_patterns: !!c.scrub_patterns?.length,
      has_pins: Object.values(c.pins ?? {}).some((l) => l.length),
      expires_at: c.expires_at ?? null,
    })),
    templates: plain.templates.map((t) => t.name),
  }
}

/** `<slug>-restored`, then `-restored-2`, …, trimmed so the slug stays within 24 characters. */
function renamed(slug, taken) {
  for (let i = 1; ; i++) {
    const suffix = i === 1 ? '-restored' : `-restored-${i}`
    const candidate = `${slug.slice(0, 24 - suffix.length)}${suffix}`
    if (!taken.has(candidate)) return candidate
  }
}

/**
 * Put a bundle's credentials and templates back. This decides only what the
 * conflict mode does with a taken slug; the vault's restoreEntries checks
 * every credential, pattern, expiry, template and the factor invariant
 * against its own rules before it writes anything, then stores all of it in
 * one write. So `fail`, any refusal, and a write that fails leave the vault
 * as it was, and the log holds one `backup.refused` for it.
 */
export async function restoreBackup(vault, bundle, { recoveryPassphrase, onConflict = 'skip' } = {}) {
  if (!CONFLICT_MODES.has(onConflict)) {
    throw deny('AV_POLICY_DENIED', 'on_conflict must be skip, rename or fail', { rule: 'backup_conflict' })
  }
  requireUnlocked(vault)
  // Every refusal from here on is recorded, once: a locked vault cannot record.
  const refused = (e) => {
    if (e?.code && e.code !== 'AV_LOCKED' && !vault.locked) {
      vault.audit.write('backup.refused', { reason: e.rule ?? e.code })
    }
    return e
  }
  let plain
  try { plain = await openBundle(bundle, recoveryPassphrase) } catch (e) { throw refused(e) }
  requireUnlocked(vault)

  // The plan, decided in full before anything is checked against the vault.
  const taken = new Set(Object.values(vault.db.credentials).map((c) => c.slug))
  const plan = []
  const skipped = []
  const renames = []
  for (const c of plain.credentials) {
    let slug = c.slug
    if (taken.has(slug)) {
      if (onConflict === 'fail') throw refused(deny('AV_POLICY_DENIED', `a credential named ${slug} already exists`, { rule: 'backup_conflict' }))
      if (onConflict === 'skip') { skipped.push(slug); continue }
      slug = renamed(c.slug, taken)
      renames.push({ from: c.slug, to: slug })
    }
    taken.add(slug)
    plan.push({ ...c, slug })
  }
  let out
  try { out = vault.restoreEntries({ credentials: plan, templates: plain.templates }) } catch (e) { throw refused(e) }
  vault.audit.write('backup.restored', { restored: out.restored, skipped, renamed: renames, bundle_sha256: bundleDigest(bundle) })
  return { restored: out.restored, skipped, renamed: renames, templates: out.templates }
}
