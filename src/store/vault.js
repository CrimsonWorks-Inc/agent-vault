// The vault: entities, encrypted credential fields, and the placeholder ledger.
//
// Production per the spec is SQLite with WAL and insert-only triggers. This
// implementation keeps the same entity model and invariants in a single
// atomically-rewritten JSON document, which is honest for a single-daemon
// M0/M1 and keeps the package dependency-free. Everything security-relevant
// lives in the same places: field values are sealed per credential, the
// placeholder ledger is the only thing that authorizes an injection, and
// consume() happens before any upstream byte.

import { mkdirSync, existsSync, readFileSync, writeFileSync, renameSync, chmodSync, openSync, closeSync, fsyncSync, fchmodSync } from 'node:fs'
import { join } from 'node:path'
import { createHash, createPublicKey, randomBytes } from 'node:crypto'
import * as crypt from './crypto.js'
import { id } from './ids.js'
import { AuditLog } from './audit.js'
import * as ph from '../core/placeholder.js'
import * as policyMod from '../core/policy.js'
import { deny } from '../core/errors.js'
import { PROFILES } from '../connectors/profiles.js'

export const SCHEMA_VERSION = 1

export function expiryMs(iso) {
  if (iso === null || iso === undefined) return Infinity;
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? -Infinity : ms;
}

export function sessionExpiryMs(s) {
  if (s.infinite === true && s.expires_at === null) return Infinity;
  if (s.expires_at == null && !s.infinite) return -Infinity;
  return expiryMs(s.expires_at);
}

// How many placeholder rows the ledger keeps. Active ones are capped per grant
// by `max_active`; this bounds the dead ones, which nothing used to remove.
const MAX_PLACEHOLDER_ROWS = 512

const EMPTY = {
  schema_version: SCHEMA_VERSION,
  kv: { vmk_wraps: [], presence_factors: [], settings: {} },
  workspaces: {},
  credentials: {},
  sessions: {},
  grants: {},
  placeholders: {},
  approvals: {},
  clients: {},
  listeners: {},
}

// The unlock factors a vault can be created with. A Touch ID (PRF) wrap is
// not one of them on its own: it needs the passphrase beside it, so it is
// added afterwards, by addWebauthnUnlock, and the factor invariant holds it
// to that.
const FACTOR_CLASSES = new Set(['none', 'passphrase', 'webauthn-prf'])

/**
 * A presence authenticator as the vault stores it, or a refusal.
 *
 * Whatever is stored here becomes the key every presence gate checks against,
 * and the gate counts it as a human factor for as long as it is there. A record
 * that cannot verify an assertion therefore still closes the gate — to
 * everyone, the owner included. So nothing is stored that the daemon could not
 * verify a signature against: a credential id the authenticator could have
 * produced, an ES256 public key (the only algorithm verifyAssertion accepts)
 * that actually parses as one, and a counter the authenticator could report.
 * Only those fields are kept; nothing else the caller sent is.
 */
export function presenceKeyRecord(input) {
  const refuse = (why) => deny('AV_POLICY_DENIED', `not a usable presence authenticator: ${why}`, {
    rule: 'presence_key',
    hint: 'Nothing was changed, and the authenticator already enrolled (if any) still works. Enrol the new one from the web UI: agent-vault ui',
    next: 'agent-vault ui',
  })
  if (!input || typeof input !== 'object') throw refuse('no credential was given')
  const { credentialId, publicKeySpki, signCount = 0 } = input
  if (typeof credentialId !== 'string' || !/^[A-Za-z0-9_-]+$/.test(credentialId)) {
    throw refuse('credentialId must be a base64url string')
  }
  const rawId = Buffer.from(credentialId, 'base64url')
  // WebAuthn credential ids are 16 to 1023 bytes. The round trip refuses an
  // id that only decodes by being read leniently.
  if (rawId.length < 16 || rawId.length > 1023 || rawId.toString('base64url') !== credentialId) {
    throw refuse('credentialId is not a WebAuthn credential id')
  }
  if (typeof publicKeySpki !== 'string' || !publicKeySpki) throw refuse('publicKeySpki is missing')
  const der = Buffer.from(publicKeySpki, 'base64')
  if (der.toString('base64') !== publicKeySpki) throw refuse('publicKeySpki is not base64')
  let key
  try {
    key = createPublicKey({ key: der, format: 'der', type: 'spki' })
  } catch {
    throw refuse('publicKeySpki is not a public key')
  }
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
    throw refuse('only ES256 (P-256) authenticators can be verified')
  }
  if (!Number.isSafeInteger(signCount) || signCount < 0 || signCount > 0xffffffff) {
    throw refuse('signCount must be a 32-bit counter')
  }
  return { credentialId, publicKeySpki, signCount, enrolledAt: new Date().toISOString() }
}

function usablePresenceKey(record) {
  try { presenceKeyRecord(record); return true } catch { return false }
}

/** The human factors a factor state holds: what the presence gates can check. */
function humanFactors({ vmk_wraps: wraps, webauthn }) {
  const factors = []
  if (wraps.some((w) => w.class === 'passphrase')) factors.push('passphrase')
  if (webauthn && usablePresenceKey(webauthn)) factors.push('authenticator')
  return factors
}

function recoveryRefusal() {
  return deny('AV_POLICY_DENIED', 'set a passphrase first; it is the recovery factor if the authenticator is lost', {
    rule: 'factor_order',
    hint: 'Touch ID unlock needs a passphrase to fall back on if the authenticator is lost. Set one, then enable Touch ID unlock again: agent-vault passphrase set',
    next: 'agent-vault passphrase set',
  })
}

/**
 * The factor invariant, owner-decided, and the one place it is enforced:
 *
 *   1. A vault that has a usable human factor is never left without one. With
 *      neither a passphrase nor an authenticator the control socket is open
 *      to whoever reaches it, which is the fresh-install state, and nothing
 *      may put a vault back into it.
 *   2. A Touch ID (PRF) unlock wrap never exists without the passphrase
 *      wrap. The passphrase is its recovery: without it, losing the
 *      authenticator loses every credential in the vault.
 *   3. A presence authenticator is only ever replaced by one the daemon can
 *      verify signatures from (presenceKeyRecord).
 *
 * `prev` and `next` are factor states: `{ vmk_wraps, webauthn }`. Every
 * construction and every factor change calls this on the state it is about to
 * commit, before anything is written, so a refusal leaves memory and disk as
 * they were. A vault that never had a human factor (a fresh one, on the
 * 'none' wrap) is allowed to stay that way; it just cannot be returned there.
 */
export function assertFactorInvariant(prev, next) {
  // Not a policy, a precondition: with no wrap at all nothing opens the vault.
  if (!next.vmk_wraps.length) throw new Error('a factor change must leave at least one way to open the vault')
  if (next.webauthn && next.webauthn !== prev.webauthn) presenceKeyRecord(next.webauthn)
  const hasPassphrase = (s) => s.vmk_wraps.some((w) => w.class === 'passphrase')
  if (next.vmk_wraps.some((w) => w.class === 'webauthn-prf') && !hasPassphrase(next)) {
    if (!hasPassphrase(prev)) throw recoveryRefusal()
    throw deny('AV_POLICY_DENIED', 'remove Touch ID unlock first; the passphrase is its recovery factor', {
      rule: 'last_factor',
      hint: 'Touch ID unlock needs the passphrase to recover the vault if the authenticator is lost. Turn off Touch ID unlock in the web UI first (agent-vault ui), then remove the passphrase.',
      next: 'agent-vault ui',
    })
  }
  const had = humanFactors(prev)
  if (had.length && !humanFactors(next).length) {
    const losing = had.join(' and ')
    throw deny('AV_POLICY_DENIED', `the ${losing} is this vault's last human factor; enrol another before removing it`, {
      rule: 'last_factor',
      hint: had.includes('passphrase')
        ? 'Without a passphrase or an authenticator, anyone who reaches the control socket could widen access. Enrol a presence authenticator in the web UI first (agent-vault ui), then remove the passphrase.'
        : 'Without an authenticator or a passphrase, anyone who reaches the control socket could widen access. Set a passphrase first: agent-vault passphrase set',
      next: had.includes('passphrase') ? 'agent-vault ui' : 'agent-vault passphrase set',
    })
  }
}

export class Vault {
  constructor(dir) {
    this.dir = dir
    this.dbPath = join(dir, 'vault.json')
    this.deviceKeyPath = join(dir, 'device.key')
    this.auditPath = join(dir, 'audit.jsonl')
    this.db = null
    this.vmk = null // null means locked
    this.audit = null
  }

  get locked() { return this.vmk === null }

  // ------------------------------------------------------------------ setup

  /** Create the vault directory and its root key material. */
  static create(dir, { factor = 'none', passphrase = null } = {}) {
    if (!FACTOR_CLASSES.has(factor)) throw new Error(`unknown unlock factor ${JSON.stringify(factor)}`)
    // Checked before anything touches the disk. The only class this can refuse
    // is a Touch ID wrap, which on its own would be a vault with no recovery.
    assertFactorInvariant({ vmk_wraps: [], webauthn: null }, { vmk_wraps: [{ class: factor }], webauthn: null })
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    chmodSync(dir, 0o700)
    const v = new Vault(dir)
    if (existsSync(v.dbPath)) throw new Error(`a vault already exists at ${dir}`)

    const deviceKey = crypt.randomKey()
    // Flushed before vault.json, which #persist flushes: every wrap in it is
    // sealed under a key derived from this one, so vault.json surviving a
    // power cut that this did not would leave a vault nothing can open.
    const keyFd = openSync(v.deviceKeyPath, 'w', 0o600)
    try {
      writeFileSync(keyFd, deviceKey)
      fsyncSync(keyFd)
    } finally { closeSync(keyFd) }

    const vmk = crypt.randomKey()
    const db = structuredClone(EMPTY)
    const wrap = v.#wrapVmk(deviceKey, vmk, factor, passphrase)
    db.kv.vmk_wraps.push(wrap)
    db.kv.presence_factors.push({ class: factor, enrolled_at: new Date().toISOString() })
    db.kv.created_at = new Date().toISOString()

    v.db = db
    v.vmk = vmk
    v.#persist()
    v.audit = new AuditLog(v.auditPath, crypt.kAudit(vmk), v.#anchorStamp())
    v.audit.write('vault.created', { factor, schema_version: SCHEMA_VERSION })
    return v
  }

  /**
   * Whether this vault is known to keep an audit anchor, and how to record
   * that it does. Kept in the vault rather than beside the log, so removing
   * `audit.jsonl.head` does not also remove the knowledge that there was one —
   * which is what let a truncation be laundered into "chain intact" by
   * deleting the anchor as well.
   */
  #anchorStamp() {
    const vaultDb = () => this.db
    return {
      // Read live, not captured: a log opened before the stamp was set must
      // still see it when the log goes missing later in the same run.
      get anchored() { return !!vaultDb()?.kv?.audit_anchored },
      markAnchored: () => {
        if (this.db?.kv && !this.db.kv.audit_anchored) {
          this.db.kv.audit_anchored = true
          this.#persist()
        }
      },
    }
  }

  #wrapVmk(deviceKey, vmk, factor, material) {
    let factorKey = Buffer.alloc(0)
    let salt = null
    if (factor === 'passphrase') {
      if (!material) throw new Error('the passphrase factor needs a passphrase')
      salt = randomBytes(16)
      factorKey = crypt.passphraseFactor(material, salt)
    } else if (factor === 'webauthn-prf') {
      // The 32-byte secret the authenticator's PRF extension returns for our
      // salt. Only a physical Touch ID (or the enrolled security key) can
      // reproduce it, so it is real key material the agent never has.
      factorKey = Buffer.isBuffer(material) ? material : Buffer.from(material, 'base64')
      if (factorKey.length < 32) throw new Error('webauthn PRF secret must be 32 bytes')
    }
    const kek = crypt.deriveKek(deviceKey, factorKey)
    const sealed = crypt.seal(kek, vmk.toString('base64'), `av/vmk/${factor}`)
    return { class: factor, salt: salt ? salt.toString('base64') : null, ...sealed }
  }

  /** The factor key for a wrap given whatever unlock material was supplied. */
  #factorKeyFor(wrap, material) {
    if (wrap.class === 'passphrase') {
      if (material.passphrase == null) return null
      return crypt.passphraseFactor(material.passphrase, Buffer.from(wrap.salt, 'base64'))
    }
    if (wrap.class === 'webauthn-prf') {
      if (!material.prfSecret) return null
      const k = Buffer.isBuffer(material.prfSecret) ? material.prfSecret : Buffer.from(material.prfSecret, 'base64')
      return k.length >= 32 ? k : null
    }
    return Buffer.alloc(0) // none
  }

  /** Open an existing vault. It starts locked unless the factor needs no secret. */
  static open(dir) {
    const v = new Vault(dir)
    if (!existsSync(v.dbPath)) throw deny('AV_NOT_FOUND', `no vault at ${dir}; run: agent-vault setup`)
    v.db = JSON.parse(readFileSync(v.dbPath, 'utf8'))
    if (v.db.schema_version > SCHEMA_VERSION) {
      throw new Error(`vault schema ${v.db.schema_version} is newer than this build (${SCHEMA_VERSION}); upgrade agent-vault`)
    }
    return v
  }

  /** Unlock with whatever material a caller has: {passphrase} or {prfSecret}. */
  unlockWith(material = {}) { return this.#openWith(material, { unlock: true }) }

  /**
   * Open the master key with whatever material was supplied. With `unlock`,
   * the vault is left unlocked and that is recorded; without it, the key is
   * held only long enough for the caller to write to the audit log, and
   * nothing about the lock changes — on disk or in the log.
   */
  #openWith(material, { unlock }) {
    const deviceKey = readFileSync(this.deviceKeyPath)
    for (const wrap of this.db.kv.vmk_wraps) {
      try {
        const factorKey = this.#factorKeyFor(wrap, material)
        if (factorKey === null) continue
        const kek = crypt.deriveKek(deviceKey, factorKey)
        const vmk = Buffer.from(crypt.open(kek, wrap, `av/vmk/${wrap.class}`), 'base64')
        // Nothing is assigned to `this` until the whole unlock has worked.
        // It used to set this.vmk first and open the audit log after, so a
        // failure in between — a torn last line in audit.jsonl is enough —
        // left the key installed while the caller was told AV_LOCKED. The
        // vault then reported `locked === false`, revealField worked, and
        // this.audit was null, so it was open for reading and recording
        // nothing.
        const audit = new AuditLog(this.auditPath, crypt.kAudit(vmk), this.#anchorStamp())
        this.vmk = vmk
        this.audit = audit
        if (unlock) {
          if (this.db.kv.locked) { this.db.kv.locked = false; this.#persist() }
          this.audit.write('vault.unlock', { factor: wrap.class })
        }
        crypt.wipe(deviceKey)
        return wrap.class
      } catch {
        // Whatever went wrong, leave nothing half-open behind.
        if (this.vmk) { crypt.wipe(this.vmk); this.vmk = null }
        this.audit = null
      }
    }
    crypt.wipe(deviceKey)
    const wants = this.factors.filter((f) => f !== 'none')
    throw deny('AV_LOCKED', wants.length ? `unlock needs one of: ${wants.join(', ')}` : 'vault is locked', {
      hint: 'No enrolled factor could be satisfied.',
    })
  }

  /** Backwards-compatible: unlock with a passphrase (or nothing). Returns true. */
  unlock(passphrase = null) { return !!this.unlockWith({ passphrase }) }

  /**
   * Add or replace the passphrase factor. Requires the vault unlocked, because
   * re-wrapping needs the VMK. Changing an existing passphrase requires the
   * current one, so an agent that reaches the socket cannot silently swap it.
   */
  setPassphrase(newPassphrase, currentPassphrase = null) {
    this.#requireUnlocked()
    if (!newPassphrase || newPassphrase.length < 8) {
      throw deny('AV_POLICY_DENIED', 'a passphrase must be at least 8 characters')
    }
    const hasPassphrase = this.db.kv.vmk_wraps.some((w) => w.class === 'passphrase')
    if (hasPassphrase) {
      // Prove possession of the current passphrase before replacing it.
      const wrap = this.db.kv.vmk_wraps.find((w) => w.class === 'passphrase')
      try {
        const deviceKey = readFileSync(this.deviceKeyPath)
        const factorKey = crypt.passphraseFactor(currentPassphrase || '', Buffer.from(wrap.salt, 'base64'))
        crypt.open(crypt.deriveKek(deviceKey, factorKey), wrap, 'av/vmk/passphrase')
      } catch {
        throw deny('AV_LOCKED', 'the current passphrase is required to change it')
      }
    }
    const deviceKey = readFileSync(this.deviceKeyPath)
    const wrap = this.#wrapVmk(deviceKey, this.vmk, 'passphrase', newPassphrase)
    // Additive: keep any Touch-ID (webauthn-prf) wrap so both factors work.
    // Drop the 'none' fallback so the lock has teeth.
    this.#commitFactors({
      vmk_wraps: [...this.db.kv.vmk_wraps.filter((w) => w.class !== 'passphrase' && w.class !== 'none'), wrap],
    })
    this.audit.write('presence.factor_added', { class: 'passphrase', replaced: hasPassphrase })
    crypt.wipe(deviceKey)
  }

  /** Keep presence_factors in step with the wraps that actually exist. */
  #syncFactors() {
    const classes = [...new Set(this.db.kv.vmk_wraps.map((w) => w.class))]
    const now = new Date().toISOString()
    const prev = this.db.kv.presence_factors || []
    this.db.kv.presence_factors = classes.map((c) => prev.find((f) => f.class === c) || { class: c, enrolled_at: now })
  }

  /**
   * Commit a change to the factors: the wraps, the presence authenticator, or
   * both. The factor invariant is checked on the whole new state first, and
   * the change lands in memory only as part of a write that succeeded, so a
   * refusal or a failed write leaves the old factors in place.
   */
  #commitFactors({ vmk_wraps = this.db.kv.vmk_wraps, webauthn = this.db.kv.webauthn ?? null }) {
    const kv = this.db.kv
    assertFactorInvariant({ vmk_wraps: kv.vmk_wraps, webauthn: kv.webauthn ?? null }, { vmk_wraps, webauthn })
    const before = { vmk_wraps: kv.vmk_wraps, presence_factors: kv.presence_factors, webauthn: kv.webauthn }
    kv.vmk_wraps = vmk_wraps
    if (webauthn !== (kv.webauthn ?? null)) kv.webauthn = webauthn
    this.#syncFactors()
    try {
      this.#persist()
    } catch (e) {
      Object.assign(kv, before)
      if (before.webauthn === undefined) delete kv.webauthn
      throw e
    }
  }

  /**
   * Refuse, unless a passphrase is set, anything that would make Touch ID an
   * unlock factor. The passphrase is the recovery factor: without it, losing
   * the authenticator would lose every credential in the vault. The daemon
   * calls this before asking for a tap, so the owner is told what to do
   * instead of tapping for a refusal. The store's own enforcement is the factor
   * invariant, which gives the same answer from addWebauthnUnlock.
   */
  requireRecoveryFactor() {
    if (this.hasPassphrase) return
    throw recoveryRefusal()
  }

  /**
   * Add Touch ID (or any WebAuthn PRF authenticator) as an unlock factor. A
   * passphrase must already be set, so losing the authenticator can never lock
   * you out: the passphrase is always the recovery path.
   */
  addWebauthnUnlock(credentialId, prfSecret) {
    this.#requireUnlocked()
    const deviceKey = readFileSync(this.deviceKeyPath)
    let wrap
    try { wrap = this.#wrapVmk(deviceKey, this.vmk, 'webauthn-prf', prfSecret) } finally { crypt.wipe(deviceKey) }
    wrap.credential_id = credentialId
    this.#commitFactors({
      vmk_wraps: [...this.db.kv.vmk_wraps.filter((w) => w.class !== 'webauthn-prf' && w.class !== 'none'), wrap],
    })
    this.audit.write('presence.factor_added', { class: 'webauthn-prf', credential_id: credentialId })
  }

  removeWebauthnUnlock() {
    this.#requireUnlocked()
    const had = this.hasWebauthnUnlock
    let wraps = this.db.kv.vmk_wraps.filter((w) => w.class !== 'webauthn-prf')
    // Every wrap is a way back to the master key. Remove the last one and the
    // vault is not locked, it is destroyed: no factor opens it, and no factor
    // can be added, because adding one needs the key that is now unreachable.
    // Enrolling requires a passphrase, so this should be impossible — but
    // "should be" is how a one-way door gets left unguarded, and the cost of
    // being wrong here is every credential in the vault, permanently.
    // removePassphrase has had this guard since the beginning; this is the
    // same guard, for the same reason.
    const downgraded = !wraps.length
    if (downgraded) {
      const deviceKey = readFileSync(this.deviceKeyPath)
      wraps = [this.#wrapVmk(deviceKey, this.vmk, 'none', null)]
      crypt.wipe(deviceKey)
    }
    this.#commitFactors({ vmk_wraps: wraps })
    if (downgraded) {
      this.audit.write('presence.factor_downgraded', {
        class: 'none', reason: 'removing the last wrap would have made the vault unopenable',
      })
    }
    if (had) this.audit.write('presence.factor_removed', { class: 'webauthn-prf' })
    return had
  }

  get hasWebauthnUnlock() { return (this.db?.kv?.vmk_wraps || []).some((w) => w.class === 'webauthn-prf') }
  get webauthnUnlockCredentialId() {
    return (this.db?.kv?.vmk_wraps || []).find((w) => w.class === 'webauthn-prf')?.credential_id || null
  }

  /**
   * Enrol or replace the presence authenticator: the key every presence gate
   * verifies signatures from. Who may do this is the daemon's to decide (a
   * first enrolment needs a passphrase, a replacement a fresh proof); what may
   * be stored is decided here. The candidate is validated completely before
   * the old key is touched, and on any refusal the old key stays.
   */
  setPresenceKey(input) {
    this.#requireUnlocked()
    const record = presenceKeyRecord(input)
    const replaced = !!this.db.kv.webauthn
    this.#commitFactors({ webauthn: record })
    this.audit.write('presence.factor_added', {
      class: 'webauthn-platform', credential_id: record.credentialId, replaced_existing: replaced,
    })
    return { replaced }
  }

  /** The stable salt the PRF is evaluated against; created on first enroll. */
  prfSalt() {
    if (!this.db.kv.prf_salt) { this.db.kv.prf_salt = randomBytes(32).toString('base64'); this.#persist() }
    return this.db.kv.prf_salt
  }

  /** Drop the passphrase, back to the UID-boundary-only 'none' factor. */
  removePassphrase(currentPassphrase) {
    this.#requireUnlocked()
    const wrap = this.db.kv.vmk_wraps.find((w) => w.class === 'passphrase')
    if (!wrap) return false
    try {
      const deviceKey = readFileSync(this.deviceKeyPath)
      const factorKey = crypt.passphraseFactor(currentPassphrase || '', Buffer.from(wrap.salt, 'base64'))
      crypt.open(crypt.deriveKek(deviceKey, factorKey), wrap, 'av/vmk/passphrase')
      crypt.wipe(deviceKey)
    } catch {
      throw deny('AV_LOCKED', 'the current passphrase is required to remove it')
    }
    // The invariant refuses this while Touch ID unlock depends on the
    // passphrase for recovery, and when the passphrase is the last human
    // factor: with no authenticator to take over, removing it would reopen
    // the control socket to whoever reaches it.
    let wraps = this.db.kv.vmk_wraps.filter((w) => w.class !== 'passphrase')
    if (!wraps.length) {
      const deviceKey = readFileSync(this.deviceKeyPath)
      wraps = [this.#wrapVmk(deviceKey, this.vmk, 'none', null)]
      crypt.wipe(deviceKey)
    }
    this.#commitFactors({ vmk_wraps: wraps })
    this.audit.write('presence.factor_removed', { class: 'passphrase' })
    return true
  }

  get hasPassphrase() { return (this.db?.kv?.vmk_wraps || []).some((w) => w.class === 'passphrase') }

  /** Confirm a passphrase without changing anything. False if none is set. */
  verifyPassphrase(passphrase) {
    const wrap = this.db.kv.vmk_wraps.find((w) => w.class === 'passphrase')
    if (!wrap) return false
    try {
      const deviceKey = readFileSync(this.deviceKeyPath)
      const factorKey = crypt.passphraseFactor(passphrase || '', Buffer.from(wrap.salt, 'base64'))
      crypt.open(crypt.deriveKek(deviceKey, factorKey), wrap, 'av/vmk/passphrase')
      crypt.wipe(deviceKey)
      return true
    } catch { return false }
  }

  lock() {
    if (this.audit) this.audit.write('vault.lock', {})
    if (this.vmk) crypt.wipe(this.vmk)
    this.vmk = null
    // The audit key is derived from the master key, so leaving the handle alive
    // would keep key material from a locked vault in this process's memory for
    // as long as it runs. Drop it with the same breath as the master key.
    if (this.audit) {
      crypt.wipe(this.audit.key)
      this.audit = null
    }
    // Persist it. A lock that a restart forgets is not a lock, it is a pause,
    // and the difference matters at exactly the moment someone reaches for it.
    if (this.db) { this.db.kv.locked = true; this.#persist() }
  }

  /** True when this vault was locked and has not been unlocked since. */
  get lockedOnDisk() { return !!this.db?.kv?.locked }

  /**
   * Bring the daemon up in the state the vault was left in. The audit log needs
   * a key, so the vault is opened and then re-locked rather than left unopened.
   */
  startInRecordedState(passphrase = null) {
    // Read the flag first: unlocking is what clears it, so checking afterwards
    // would always find the vault unlocked and defeat the whole point.
    const wasLocked = this.lockedOnDisk
    // A vault whose only factors need a secret (passphrase, Touch ID) cannot
    // be auto-unlocked at boot: the secret is not on disk. Come up locked in
    // that case rather than crashing, and let the human unlock.
    //
    // A vault recorded as locked is opened WITHOUT unlocking it. It used to go
    // through the full unlock, which cleared the flag on disk (a crash right
    // there brought it up unlocked: a lock the restart forgot) and wrote a
    // `vault.unlock` that nobody performed into the log on every boot.
    let opened = false
    try {
      this.#openWith({ passphrase }, { unlock: !wasLocked })
      opened = true
    } catch { opened = false }

    if (!opened || wasLocked) {
      if (this.vmk) crypt.wipe(this.vmk)
      this.vmk = null
      // The audit log needs a key. Without one (a passphrase/Touch-ID vault we
      // could not open) it stays silent until the human unlocks; that is the
      // honest consequence of a cryptographic lock.
      if (this.db.kv.locked !== true) { this.db.kv.locked = true; this.#persist() }
      if (this.audit) {
        this.audit.write('vault.started_locked', {})
        // And then let go of the key, as lock() does. Keeping it meant a vault
        // locked before a reboot answered audit reads that one locked
        // explicitly refuses.
        crypt.wipe(this.audit.key)
        this.audit = null
      }
      return false
    }
    return true
  }

  #requireUnlocked() {
    if (this.locked) throw deny('AV_LOCKED', 'the vault is locked')
  }

  /**
   * Write the vault out. Temp file, then rename, which is the atomic part —
   * a reader sees the old file or the new one, never half of either.
   *
   * The rename being atomic is not the same as it being durable. Without an
   * fsync the bytes can still be in the page cache when the rename is
   * recorded, so a power loss can leave vault.json present, renamed, and
   * empty — which is every credential in it, gone, with nothing to recover
   * from. So: fsync the data before the rename, and fsync the directory
   * after, because the directory entry needs flushing too.
   */
  #persist({ durable = true } = {}) {
    const tmp = `${this.dbPath}.tmp`
    const text = JSON.stringify(this.db, null, 1)
    // The mode argument to writeFileSync applies at CREATION only. A temp file
    // left behind by a crash is written into with whatever mode it already
    // has, so reassert it rather than inherit it.
    const fd = openSync(tmp, 'w', 0o600)
    try {
      writeFileSync(fd, text)
      fchmodSync(fd, 0o600)
      // The fsync is what makes a write survive a power cut, and it costs
      // several milliseconds against a growing file. Key material and
      // credentials get it: losing one of those is unrecoverable. The
      // placeholder ledger does not, because the rename is atomic either way —
      // the file is never torn, only possibly one write behind — and one lost
      // placeholder issuance is something the agent simply asks for again.
      //
      // Without this split, minting placeholders cost 13.5ms each, all of it
      // on the event loop, and an agent chooses how often to mint.
      if (durable) fsyncSync(fd)
    } finally {
      closeSync(fd)
    }
    renameSync(tmp, this.dbPath)
    // Best effort: a filesystem that will not let us open the directory is not
    // a reason to fail the write that already succeeded.
    if (durable) {
      try {
        const dirFd = openSync(this.dir, 'r')
        try { fsyncSync(dirFd) } finally { closeSync(dirFd) }
      } catch { /* not every platform allows this */ }
    }
  }

  get kPh() { this.#requireUnlocked(); return crypt.kPh(this.vmk) }
  /** Keyed apart from kPh, because a fingerprint is taken over caller-chosen text. */
  get kFingerprint() { this.#requireUnlocked(); return crypt.kFingerprint(this.vmk) }

  // ------------------------------------------------------------ credentials

  /**
   * Store a credential. `fields` maps field name -> plaintext value; the
   * plaintext is sealed immediately and never kept.
   */
  addCredential({ slug, kind, connector = {}, fields = {}, sites = {} }) {
    this.#requireUnlocked()
    if (!ph.isValidSlug(slug)) throw deny('AV_NOT_FOUND', `invalid slug "${slug}": use [a-z0-9-], 1-24 characters`)
    if (this.findCredential(slug)) throw deny('AV_NOT_FOUND', `credential ${slug} already exists`)

    const credId = id.credential()
    const key = crypt.dek(this.vmk, credId)
    const stored = []
    for (const [name, value] of Object.entries(fields)) {
      if (!ph.isValidField(name)) throw deny('AV_NOT_FOUND', `invalid field name "${name}"`)
      const sealed = crypt.seal(key, value, `${credId}|${name}|1`)
      stored.push({
        name, ...sealed, key_version: 1,
        sites: sites[name] || [],
        fp8: crypt.fingerprint8(this.kFingerprint, value),
        length: value.length,
      })
    }
    const cred = {
      id: credId, slug, connector_kind: kind, connector, fields: stored,
      created_at: new Date().toISOString(),
    }
    this.db.credentials[credId] = cred
    this.#persist()
    this.audit.write('cred.added', { credential_slug: slug, connector: kind, fields: stored.map((f) => f.name) })
    return this.publicCredential(cred)
  }

  findCredential(slug) {
    return Object.values(this.db.credentials).find((c) => c.slug === slug) || null
  }

  /** The credential as anything outside the daemon may see it: never a value. */
  publicCredential(cred) {
    const soonThreshold = Date.now() + 7 * 86400000;
    let expiry_warning = null;
    let actualExpiry = cred.health?.observed_expires_at || cred.expires_at;
    if (actualExpiry) {
      if (!(expiryMs(actualExpiry) > Date.now())) expiry_warning = 'expired';
      else if (expiryMs(actualExpiry) < soonThreshold) expiry_warning = 'soon';
    }
    return {
      id: cred.id, slug: cred.slug, kind: cred.connector_kind, connector: cred.connector,
      expires_at: cred.expires_at || null,
      health: cred.health || null,
      expiry_warning,
      quarantine: cred.quarantine || null,
      // No exact length: it narrows an offline guess and, with the fingerprint,
      // is metadata a credential value should not leak. A coarse bucket is
      // enough for the UI to say something useful.
      fields: cred.fields.map((f) => ({ name: f.name, sites: f.sites, fp8: f.fp8, size: sizeBucket(f.length) })),
      // The profile's own read-only probe. Not sensitive — it is a constant of
      // the connector kind — and it lets a caller show an example request that
      // actually works instead of a made-up path.
      probe_path: PROFILES[cred.connector_kind]?.probe?.path || null,
      created_at: cred.created_at,
    }
  }

  listCredentials() { return Object.values(this.db.credentials).map((c) => this.publicCredential(c)) }

  /** Decrypt one field. The only path to a plaintext value, used by the pipeline. */
  revealField(credId, fieldName) {
    this.#requireUnlocked()
    const cred = this.db.credentials[credId]
    if (!cred) throw deny('AV_NOT_FOUND', `no credential ${credId}`)
    const field = cred.fields.find((f) => f.name === fieldName)
    if (!field) throw deny('AV_NOT_FOUND', `credential ${cred.slug} has no field ${fieldName}`)
    const key = crypt.dek(this.vmk, credId)
    return crypt.open(key, field, `${credId}|${fieldName}|${field.key_version}`)
  }

  /** Every unsealed credential value, for the scrubber's match set. */
  allSecrets() {
    this.#requireUnlocked()
    const out = []
    for (const cred of Object.values(this.db.credentials)) {
      for (const f of cred.fields) {
        try { out.push({ secret: this.revealField(cred.id, f.name), label: cred.slug, field: f.name }) } catch { /* skip */ }
      }
    }
    return out
  }

  setCredentialExpiry(slug, isoOrNull) {
    this.#requireUnlocked()
    const cred = this.findCredential(slug)
    if (!cred) throw deny('AV_NOT_FOUND', `no credential ${slug}`)
    if (isoOrNull !== null) {
      if (Number.isNaN(Date.parse(isoOrNull))) throw deny('AV_POLICY_DENIED', 'expires_at must be a valid ISO date or null', { rule: 'expires_at' })
    }
    cred.expires_at = isoOrNull
    this.#persist()
    this.audit.write('cred.expiry_set', { credential_slug: slug, expires_at: isoOrNull })
  }

  recordHealth(credIdOrSlug, patch) {
    const cred = this.db.credentials[credIdOrSlug] || this.findCredential(credIdOrSlug)
    if (!cred) return null
    const oldStatus = cred.health?.status
    const oldObserved = cred.health?.observed_expires_at
    cred.health = { ...(cred.health || {}), ...patch }
    this.#persist({ durable: false })
    if (cred.health.status !== oldStatus || cred.health.observed_expires_at !== oldObserved) {
      this.audit?.write('cred.health_recorded', { credential_slug: cred.slug, status: cred.health.status, observed_expires_at: cred.health.observed_expires_at })
    }
    return cred.health
  }

  setQuarantine(slug, { by, rule_id, reason_untrusted }) {
    this.#requireUnlocked()
    const cred = this.findCredential(slug)
    if (!cred) throw deny('AV_NOT_FOUND', `no credential ${slug}`)
    cred.quarantine = { since: new Date().toISOString(), by, rule_id, reason_untrusted }
    this.#persist()
    this.audit.write('cred.quarantined', { credential_slug: slug, by, rule_id })
  }

  clearQuarantine(slug) {
    this.#requireUnlocked()
    const cred = this.findCredential(slug)
    if (!cred) throw deny('AV_NOT_FOUND', `no credential ${slug}`)
    if (!cred.quarantine) return false
    cred.quarantine = null
    this.#persist()
    this.audit.write('cred.released', { credential_slug: slug })
    return true
  }

  getSettings() {
    this.#requireUnlocked()
    return JSON.parse(JSON.stringify(this.db.kv.settings || {}))
  }

  updateSettings(patch) {
    this.#requireUnlocked()
    if (!this.db.kv.settings) this.db.kv.settings = {}
    if (patch.tripwires) {
      if (typeof patch.tripwires !== 'object' || !Array.isArray(patch.tripwires.rules)) {
        throw deny('AV_POLICY_DENIED', 'invalid tripwires shape', { rule: 'tripwire_rule' })
      }
    }
    for (const [k, v] of Object.entries(patch)) {
      this.db.kv.settings[k] = v
    }
    this.#persist()
    this.audit.write('settings.changed', { keys: Object.keys(patch) })
    return this.getSettings()
  }

  deleteCredential(slug) {
    // A change that cannot be written to the audit log must not happen.
    // Locking drops the audit key with the master key, so these mutate
    // nothing while locked rather than persisting unrecorded.
    this.#requireUnlocked()
    const cred = this.findCredential(slug)
    if (!cred) throw deny('AV_NOT_FOUND', `no credential ${slug}`)
    for (const g of Object.values(this.db.grants)) {
      if (g.credential_id === cred.id) this.revokeGrant(g.id, 'credential_deleted')
    }
    delete this.db.credentials[cred.id]
    this.#persist()
    this.audit.write('cred.deleted', { credential_slug: slug })
  }

  // ------------------------------------------------------------- workspaces

  addWorkspace({ name, policy = {} }) {
    // A change that cannot be written to the audit log must not happen.
    // Locking drops the audit key with the master key, so these mutate
    // nothing while locked rather than persisting unrecorded.
    this.#requireUnlocked()
    const wsId = id.workspace()
    const ws = {
      id: wsId, name, default_policy: policy,
      policy_sha256: createHash('sha256').update(JSON.stringify(policy)).digest('hex'),
      state: 'active', created_at: new Date().toISOString(),
    }
    this.db.workspaces[wsId] = ws
    this.#persist()
    this.audit.write('policy.approved', { workspace_id: wsId, name, policy_sha256: ws.policy_sha256 })
    return ws
  }

  findWorkspace(nameOrId) {
    return this.db.workspaces[nameOrId] || Object.values(this.db.workspaces).find((w) => w.name === nameOrId) || null
  }

  // --------------------------------------------------------------- sessions

  /**
   * @param {{ttlMs?: number|null}} opts ttlMs is a LIFETIME the caller asked
   *   for, not an opening bid. Omit it to take the default and its idle
   *   extension; give it to say how long this session may live.
   *
   * `max_expires_at` used to be creation + 24h no matter what was asked for,
   * and `touchSession` raises `expires_at` towards it on every request. A
   * session a human approved for THIRTY MINUTES jumped to two hours on its
   * first call and could be held open for a day by an agent that kept working
   * — a lifetime is the one dimension a session request spells out, and it was
   * the one dimension the approval did not bind.
   *
   * The same field was never a ceiling either: `assertSessionLive` reads only
   * `expires_at`, so asking for 48 hours produced a session that outlived the
   * 24-hour cap by a day. It is now both: what is asked for is clamped down to
   * the cap, and what was asked for caps the idle extension.
   */
  createSession({ workspaceId, label, ttlMs = null, infinite = false, policy = {}, peerUid = process.getuid?.(), remote = false, clientName = null }) {
    this.#requireUnlocked()
    if (ttlMs !== null && (!Number.isFinite(ttlMs) || ttlMs <= 0)) throw deny('AV_POLICY_DENIED', 'ttl must be a positive number', { rule: 'ttl' })
    if (infinite && ttlMs != null) throw deny('AV_POLICY_DENIED', 'an infinite session has no lifetime to set', { rule: 'ttl' })
    if (infinite && remote) throw deny('AV_REMOTE_FORBIDDEN', 'infinite session cannot be remote', { rule: 'infinite_remote' })
    const sid = ph.newSid()
    const secret = randomBytes(33).toString('base64url')
    const token = `avs1.${sid}.${secret}`
    const now = Date.now()
    const hardCapMs = (remote ? 8 : 24) * 3600_000
    // What this session actually gets, never more than the cap.
    const life = Math.min(ttlMs ?? 8 * 3600_000, hardCapMs)
    // How far idle activity may push that out. A requested lifetime is its own
    // ceiling; only a session that never named one gets the generous default.
    const ceiling = ttlMs == null ? hardCapMs : life
    const session = {
      id: sid, workspace_id: workspaceId || null, label: label || 'session',
      token_hash: createHash('sha256').update(token).digest('hex'),
      policy, owner_uid: peerUid ?? null, remote, client_name: clientName,
      state: 'active',
      created_at: new Date(now).toISOString(),
      expires_at: infinite ? null : new Date(now + life).toISOString(),
      max_expires_at: infinite ? null : new Date(now + ceiling).toISOString(),
      idle_timeout_ms: infinite ? null : ((remote ? 1 : 2) * 3600_000),
      infinite,
      last_seen_at: new Date(now).toISOString(),
    }
    this.db.sessions[sid] = session
    this.#persist()
    this.audit.write('session.created', { session_id: sid, workspace_id: workspaceId, label, remote, infinite, expires_at: session.expires_at })
    return { session, token }
  }

  /** Resolve a bearer token to a live session, enforcing expiry and state. */
  sessionByToken(token) {
    if (!token) return null
    const hash = createHash('sha256').update(token).digest('hex')
    const s = Object.values(this.db.sessions).find((x) => crypt.constantTimeEqual(x.token_hash, hash))
    return s || null
  }

  assertSessionLive(session) {
    if (!session) throw deny('AV_SESSION_REQUIRED', 'no session', {
      next: { cli: ['agent-vault session create --cred <slug>'], mcp: { tool: 'vault_request_session' } },
    })
    if (session.state === 'revoked') throw deny('AV_SESSION_REVOKED', `session ${session.id} was revoked`)
    if (!(sessionExpiryMs(session) > Date.now())) {
      if (session.state !== 'expired') {
        session.state = 'expired'
        // Its placeholders die with it, as they do on revocation. Left
        // active, they were exempt from the ledger bound forever and counted
        // as live in every status report.
        for (const p of Object.values(this.db.placeholders)) {
          if (p.sid === session.id && p.state === 'active') { p.state = 'dead'; p.dead_reason = 'session_ended' }
        }
        this.#persist()
      }
      throw deny('AV_SESSION_EXPIRED', `session ${session.id} expired at ${session.expires_at}`)
    }
    return session
  }

  /** Idle extension. Never widens capability, so it needs no presence. */
  touchSession(session) {
    const now = Date.now()
    if (!session.infinite) {
      const extended = Math.min(now + session.idle_timeout_ms, Date.parse(session.max_expires_at))
      if (extended > Date.parse(session.expires_at)) session.expires_at = new Date(extended).toISOString()
    }
    session.last_seen_at = new Date(now).toISOString()
  }

  shortenSession(sid, ttlMs) {
    this.#requireUnlocked()
    const s = this.db.sessions[sid]
    if (!s) throw deny('AV_NOT_FOUND', `no session ${sid}`)
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) throw deny('AV_POLICY_DENIED', 'ttlMs must be finite and positive', { rule: 'ttl' })
    const now = Date.now()
    const currentExpiry = s.infinite ? Infinity : Date.parse(s.expires_at)
    const newExpiry = Math.min(currentExpiry, now + ttlMs)
    s.expires_at = new Date(newExpiry).toISOString()
    const currentMax = s.infinite ? Infinity : Date.parse(s.max_expires_at)
    const newMax = Math.min(currentMax, now + ttlMs)
    s.max_expires_at = new Date(newMax).toISOString()
    const was_infinite = s.infinite
    s.infinite = false
    s.idle_timeout_ms = (s.remote ? 1 : 2) * 3600_000
    this.#persist()
    this.audit.write('session.shortened', { session_id: sid, expires_at: s.expires_at, was_infinite })
    return s
  }

  revokeSession(sid, reason = 'revoked') {
    // A change that cannot be written to the audit log must not happen.
    // Locking drops the audit key with the master key, so these mutate
    // nothing while locked rather than persisting unrecorded.
    this.#requireUnlocked()
    const s = this.db.sessions[sid]
    if (!s) throw deny('AV_NOT_FOUND', `no session ${sid}`)
    s.state = 'revoked'
    for (const g of Object.values(this.db.grants)) if (g.session_id === sid) g.state = 'revoked'
    for (const p of Object.values(this.db.placeholders)) {
      if (p.sid === sid && p.state === 'active') { p.state = 'dead'; p.dead_reason = 'session_ended' }
    }
    this.#persist()
    this.audit.write('session.revoked', { session_id: sid, reason })
  }

  /** Fork: policy is the intersection, so a child can only narrow. */
  forkSession(parentSid, { label, narrow = {}, ttlMs } = {}) {
    // A change that cannot be written to the audit log must not happen.
    // Locking drops the audit key with the master key, so these mutate
    // nothing while locked rather than persisting unrecorded.
    this.#requireUnlocked()
    const parent = this.assertSessionLive(this.db.sessions[parentSid])
    const parentTtl = Date.parse(parent.expires_at) - Date.now()
    const { session, token } = this.createSession({
      workspaceId: parent.workspace_id,
      label: label || `${parent.label} (fork)`,
      ttlMs: Math.min(ttlMs ?? parentTtl, parentTtl),
      policy: parent.policy,
      peerUid: parent.owner_uid,
      remote: parent.remote,
      clientName: parent.client_name,
    })
    session.parent_sid = parentSid
    for (const g of Object.values(this.db.grants)) {
      if (g.session_id !== parentSid || g.state !== 'active') continue
      this.createGrant({ sessionId: session.id, credentialId: g.credential_id, fields: g.fields, policy: g.policy, narrow })
    }
    this.#persist()
    this.audit.write('session.forked', { session_id: session.id, parent_session_id: parentSid })
    return { session, token }
  }

  // ----------------------------------------------------------------- grants

  createGrant({ sessionId, credentialId, fields, policy, narrow = null, ttlMs = null }) {
    // A change that cannot be written to the audit log must not happen.
    // Locking drops the audit key with the master key, so these mutate
    // nothing while locked rather than persisting unrecorded.
    this.#requireUnlocked()
    const session = this.db.sessions[sessionId]
    if (!session) throw deny('AV_NOT_FOUND', `no session ${sessionId}`)
    const cred = this.db.credentials[credentialId]
    if (!cred) throw deny('AV_NOT_FOUND', `no credential ${credentialId}`)
    if (ttlMs !== null && (!Number.isFinite(ttlMs) || ttlMs <= 0)) throw deny('AV_POLICY_DENIED', 'grant ttl must be positive', { rule: 'grant_ttl' })
    const expires_at = ttlMs !== null ? new Date(Math.min(Date.now() + ttlMs, sessionExpiryMs(session))).toISOString() : null
    const grantId = id.grant()
    const grant = {
      id: grantId, session_id: sessionId, credential_id: credentialId,
      fields: fields || cred.fields.map((f) => f.name),
      // Intersected, never spread. `{ ...policy, ...narrow }` let a
      // "narrowing" replace any dimension outright — methods: ['DELETE'],
      // approval: 'auto' — so a fork could widen the grant it came from.
      policy: narrow && Object.keys(narrow).length ? policyMod.intersect([policy, narrow]) : policy,
      budget_used: 0, counters: { requests: 0, denials: 0 }, state: 'active',
      created_at: new Date().toISOString(),
      expires_at,
    }
    this.db.grants[grantId] = grant
    this.#persist()
    this.audit.write('grant.created', { grant_id: grantId, session_id: sessionId, credential_slug: cred.slug, expires_at })
    return grant
  }

  findGrant(sid, credId) {
    let newest = null;
    for (const g of Object.values(this.db.grants)) {
      if (g.session_id === sid && g.credential_id === credId) {
        if (!newest || String(g.created_at).localeCompare(String(newest.created_at)) > 0) {
          newest = g;
        }
      }
    }
    return newest;
  }

  assertGrantLive(grant) {
    if (!grant || grant.state !== 'active') throw deny('AV_NO_GRANT', `no active grant ${grant?.id}`);
    if (!(expiryMs(grant.expires_at) > Date.now())) {
      grant.state = 'expired';
      for (const p of Object.values(this.db.placeholders)) {
        if (p.grant_id === grant.id && p.state === 'active') { p.state = 'dead'; p.dead_reason = 'expired'; }
      }
      this.#persist();
      this.audit.write('grant.expired', { grant_id: grant.id, session_id: grant.session_id });
      throw deny('AV_GRANT_EXPIRED', `grant ${grant.id} has expired`, { next: { mcp: { tool: 'vault_request_session' } } });
    }
    return grant;
  }

  grantsForSession(sid) {
    return Object.values(this.db.grants).filter((g) => g.session_id === sid && g.state === 'active')
  }

  chargeGrant(grantId, n = 1) {
    const grant = this.db.grants[grantId];
    if (!grant) return false;
    const limit = grant.policy?.budget?.limit;
    if (limit !== undefined && Number.isFinite(limit) && grant.budget_used + n > limit) return false;
    grant.budget_used += n;
    grant.counters.requests += n;
    this.#persist({ durable: false });
    return true;
  }

  revokeGrant(grantId, reason = 'revoked') {
    // A change that cannot be written to the audit log must not happen.
    // Locking drops the audit key with the master key, so these mutate
    // nothing while locked rather than persisting unrecorded.
    this.#requireUnlocked()
    const g = this.db.grants[grantId]
    if (!g) return
    g.state = 'revoked'
    for (const p of Object.values(this.db.placeholders)) {
      if (p.grant_id === grantId && p.state === 'active') { p.state = 'dead'; p.dead_reason = 'revoked' }
    }
    this.#persist()
    this.audit.write('grant.revoked', { grant_id: grantId, reason })
  }

  /** Narrow an existing grant. Reducing capability never needs presence. */
  shortenGrant(grantId, ttlMs) {
    this.#requireUnlocked()
    const g = this.db.grants[grantId]
    if (!g) throw deny('AV_NOT_FOUND', `no grant ${grantId}`)
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) throw deny('AV_POLICY_DENIED', 'ttlMs must be finite and positive', { rule: 'grant_ttl' })
    const now = Date.now()
    const currentExpiry = g.expires_at ? Date.parse(g.expires_at) : Infinity
    g.expires_at = new Date(Math.min(currentExpiry, now + ttlMs)).toISOString()
    for (const p of Object.values(this.db.placeholders)) {
      if (p.grant_id === grantId && p.state === 'active') {
        const theirExpiry = p.expires_at ? Date.parse(p.expires_at) : Infinity
        p.expires_at = new Date(Math.min(theirExpiry, Date.parse(g.expires_at))).toISOString()
      }
    }
    this.#persist()
    this.audit.write('grant.shortened', { grant_id: grantId, expires_at: g.expires_at })
    return g
  }

  narrowGrant(grantId, narrow) {
    // A change that cannot be written to the audit log must not happen.
    // Locking drops the audit key with the master key, so these mutate
    // nothing while locked rather than persisting unrecorded.
    this.#requireUnlocked()
    const g = this.db.grants[grantId]
    if (!g) throw deny('AV_NOT_FOUND', `no grant ${grantId}`)
    // The same intersection every request is checked against, so this can
    // only ever remove capability. It was an object spread, which replaced
    // whatever `narrow` named: a "narrowing" to DELETE on /admin/** with
    // approval: 'auto' widened every one of them.
    g.policy = policyMod.intersect([g.policy, narrow])
    this.#persist()
    this.audit.write('grant.narrowed', { grant_id: grantId, narrow })
    return g
  }

  // ---------------------------------------------------------- placeholders

  /**
   * Issue a placeholder against a grant. Session-lifetime by default: max_uses
   * comes from the grant budget, so SDK pagination and connection pools do not
   * exhaust it. One-time and n-use are opt-in, which is what the product
   * requirement asked for without making it the default that breaks clients.
   */
  issuePlaceholder({ grantId, field, uses = null, ttlMs = null }) {
    this.#requireUnlocked()
    const grant = this.db.grants[grantId]
    this.assertGrantLive(grant)
    const session = this.assertSessionLive(this.db.sessions[grant.session_id])
    const cred = this.db.credentials[grant.credential_id]
    const fieldName = field || grant.fields[0]
    if (!grant.fields.includes(fieldName)) throw deny('AV_NO_GRANT', `grant does not cover field ${fieldName}`)
    if (cred.quarantine) throw deny('AV_QUARANTINED', `credential ${cred.slug} is quarantined`, { rule: 'quarantined' })

    // `?? 1000` does not catch NaN, only null and undefined, so a malformed
    // budget propagated straight into the placeholder's use ceiling — and
    // `Math.min(asked, NaN)` is NaN, which no `uses >= max_uses` ever stops.
    const stated = Number(grant.policy?.budget?.limit)
    const budgetLimit = Number.isFinite(stated) && stated > 0 ? stated : 1000
    const phPolicy = grant.policy?.placeholder_policy || {}
    // Validated, not `?? 8`: a string or NaN made `length >= max_active`
    // false for good, which is no bound at all.
    const maxActive = Number.isSafeInteger(phPolicy.max_active) && phPolicy.max_active >= 1 ? phPolicy.max_active : 8
    const active = Object.values(this.db.placeholders)
      .filter((p) => p.grant_id === grantId && p.field === fieldName && p.state === 'active')
    // Rotate rather than refuse: an agent that asks twice should get a working
    // placeholder, not an error it cannot act on. Unused ones go first, oldest
    // first; then the least recently used. Only unused ones used to be
    // eligible, so once every live row had been used once the bound stopped
    // applying — ask, use, ask again, and the live rows grew without limit.
    // A rotated placeholder answers AV_PH_STALE, which says to ask again.
    const order = (p) => [p.uses === 0 ? 0 : 1, p.last_used_at || p.created_at]
    active.sort((a, b) => {
      const [ua, ta] = order(a)
      const [ub, tb] = order(b)
      return ua - ub || String(ta).localeCompare(String(tb))
    })
    for (const p of active.slice(0, Math.max(0, active.length - maxActive + 1))) {
      p.state = 'dead'
      p.dead_reason = 'rotated'
    }

    // The grant's placeholder_policy is a ceiling, not a default. It used to
    // sit on the right of a `??`, so a caller asking for a million uses got a
    // million even where the human had configured one-time placeholders.
    // Enforced here so no call site can forget it.
    const ceiling = Number.isFinite(phPolicy.max_uses) ? phPolicy.max_uses : budgetLimit
    // Floored to an integer. A fractional `uses` reached the audit record as a
    // float, and canonicalize refuses floats — so write() threw AFTER the
    // ledger had already been persisted, leaving a placeholder that existed
    // and a change nobody recorded. An agent could ask for 1.5 uses.
    const asked = Math.floor(Number(uses))
    const maxUses = uses == null || !Number.isFinite(asked) || asked < 1
      ? ceiling
      : Math.min(asked, ceiling)
    // The grant's ttl is a ceiling too. An explicit ttlMs replaced it, so a
    // caller asking for an hour got an hour on a grant that said one second.
    // Either one that is not a positive number is no limit, not a zero.
    const positive = (n) => (Number.isFinite(n) && n > 0 ? n : Infinity)
    const ttl = Math.min(positive(Number(ttlMs ?? NaN)), positive(Number(phPolicy.ttl) * 1000))
    // Bounded by how long the session can possibly last, not by when it would
    // expire today. Idle activity moves `expires_at` out towards
    // `max_expires_at`, and a placeholder pinned to the first value died hours
    // before the session it belongs to — the one `session create` hands out
    // included. The session's own liveness is checked on every use anyway
    // (#authenticate asserts it for token and carrier alike).
    const expires = Math.min(
      ttl ? Date.now() + ttl : Infinity,
      session.infinite ? Infinity : Date.parse(session.max_expires_at ?? session.expires_at),
      expiryMs(grant.expires_at)
    )
    this.#collectDeadPlaceholders()
    const minted = ph.mint({ kPh: this.kPh, sid: session.id, slug: cred.slug, field: fieldName })
    const row = {
      id: id.placeholder(), grant_id: grantId, credential_id: cred.id, field: fieldName,
      sid: session.id, nonce_hash: minted.nonceHash,
      uses: 0, max_uses: maxUses, state: 'active', dead_reason: null, replaces_id: null,
      created_at: new Date().toISOString(),
      expires_at: Number.isFinite(expires) ? new Date(expires).toISOString() : null,
      last_used_at: null,
    }
    this.db.placeholders[row.id] = row
    // Ledger churn, not key material: the rename is atomic either way, so the
    // worst a power cut costs is one placeholder the agent asks for again.
    this.#persist({ durable: false })
    this.audit.write('placeholder.issued', {
      placeholder_id: row.id, grant_id: grantId, session_id: session.id,
      credential_slug: cred.slug, field: fieldName, max_uses: maxUses,
    })
    return { placeholder: minted.text, row }
  }

  /** Look a placeholder up by its nonce. Constant-time on the stored hash. */
  resolvePlaceholder(parsed) {
    const hash = ph.hashNonce(parsed.nonce)
    for (const row of Object.values(this.db.placeholders)) {
      if (crypt.constantTimeEqual(row.nonce_hash, hash)) return row
    }
    return null
  }

  /**
   * Spend one use, atomically, before any upstream byte. Returns the updated
   * row. Throws with the precise reason so the agent knows whether this is a
   * benign rotation or a replay.
   */
  consumePlaceholder(rowId) {
    const row = this.db.placeholders[rowId]
    if (!row) throw deny('AV_PH_REPLAY', 'unknown placeholder')
    if (row.state !== 'active') {
      // Three distinct outcomes, because the agent should react differently to
      // each: exhausted means "take the successor", stale means "re-fetch,
      // nothing is wrong", replay means a dead placeholder came back and that
      // is treated as hostile.
      const STALE = ['expired', 'session_ended', 'rotated']
      const code = row.dead_reason === 'exhausted' ? 'AV_PH_EXHAUSTED'
        : STALE.includes(row.dead_reason) ? 'AV_PH_STALE'
        : 'AV_PH_REPLAY'
      throw deny(code, `placeholder is ${row.dead_reason || row.state}`, {
        next: { cli: ['agent-vault ph next <cred>'], mcp: { tool: 'vault_get_placeholder' } },
      })
    }
    this.assertGrantLive(this.db.grants[row.grant_id])
    if (row.expires_at !== null && !(expiryMs(row.expires_at) > Date.now())) {
      row.state = 'dead'; row.dead_reason = 'expired'; this.#persist({ durable: false })
      throw deny('AV_PH_STALE', 'placeholder expired', {
        next: { cli: ['agent-vault ph next <cred>'], mcp: { tool: 'vault_get_placeholder' } },
      })
    }
    if (row.uses >= row.max_uses) {
      row.state = 'dead'; row.dead_reason = 'exhausted'; this.#persist({ durable: false })
      throw deny('AV_PH_EXHAUSTED', `placeholder used ${row.uses}/${row.max_uses} times`, {
        next: { cli: ['agent-vault ph next <cred>'], mcp: { tool: 'vault_get_placeholder' } },
      })
    }
    row.uses += 1
    row.last_used_at = new Date().toISOString()
    if (row.uses >= row.max_uses) { row.state = 'dead'; row.dead_reason = 'exhausted' }
    const grant = this.db.grants[row.grant_id]
    if (grant) { grant.budget_used += 1; grant.counters.requests += 1 }
    this.#persist()
    return row
  }

  /** Give back a use when the daemon failed before the first upstream byte. */
  /**
   * Give back a use and a budget unit when a request never reached anyone.
   *
   * It used to revive ANY exhausted row unconditionally, without re-checking
   * the grant or the session and without recording anything — so a placeholder
   * whose grant had been revoked in the meantime came back to life, and the
   * log kept the `placeholder.resolved` record saying the use had happened.
   * Ledger and log disagreed by one on every refund.
   *
   * That used to be unreachable through the pipeline, because markUpstream()
   * fired before the upstream call and left no await between consuming and
   * marking. Moving the mark to AFTER the call — so the refund could happen at
   * all — put a real await in that gap, and made this live.
   */
  refundPlaceholder(rowId) {
    const row = this.db.placeholders[rowId]
    if (!row) return
    const grant = this.db.grants[row.grant_id]
    const session = this.db.sessions[row.sid]
    // Revoked in the meantime: the use stays spent and the row stays dead.
    // Refunding into a revoked grant would hand back capability a human took
    // away, which is the one direction a refund must never go.
    const stillLive = grant?.state === 'active' && session?.state === 'active'
    if (!stillLive) {
      this.audit?.write('placeholder.refund_refused', {
        placeholder_id: rowId,
        grant_state: grant?.state ?? 'missing',
        session_state: session?.state ?? 'missing',
      })
      return
    }
    if (row.uses > 0) row.uses -= 1
    if (row.state === 'dead' && row.dead_reason === 'exhausted') { row.state = 'active'; row.dead_reason = null }
    if (grant.budget_used > 0) grant.budget_used -= 1
    this.#persist({ durable: false })
    // Recorded, so the ledger and the log agree about how many uses happened.
    this.audit?.write('placeholder.refunded', {
      placeholder_id: rowId, grant_id: row.grant_id, uses: row.uses, max_uses: row.max_uses,
    })
  }

  burnPlaceholder(rowId, reason = 'burned') {
    // A change that cannot be written to the audit log must not happen.
    // Locking drops the audit key with the master key, so these mutate
    // nothing while locked rather than persisting unrecorded.
    this.#requireUnlocked()
    const row = this.db.placeholders[rowId]
    if (!row) throw deny('AV_NOT_FOUND', `no placeholder ${rowId}`)
    row.state = 'dead'
    row.dead_reason = reason
    this.#persist()
    this.audit.write('placeholder.burned', { placeholder_id: rowId, reason })
    return row
  }

  /** Idempotent successor: repeated calls return the same unused replacement. */
  nextPlaceholder(rowId) {
    const old = this.db.placeholders[rowId]
    if (!old) throw deny('AV_NOT_FOUND', `no placeholder ${rowId}`)
    const existing = Object.values(this.db.placeholders)
      .find((p) => p.replaces_id === rowId && p.state === 'active' && p.uses === 0)
    if (existing) return { placeholder: null, row: existing, reused: true }
    // The successor inherits the predecessor's limit. Issuing it with no
    // `uses` gave it the ceiling instead — the grant's entire budget — so a
    // placeholder the human deliberately made one-time was replaced, on the
    // success path and unprompted, by one good for hundreds of calls. The
    // narrowest thing the operator could ask for silently became the widest.
    const { placeholder, row } = this.issuePlaceholder({
      grantId: old.grant_id, field: old.field, uses: old.max_uses,
    })
    row.replaces_id = rowId
    this.#persist()
    return { placeholder, row, reused: false }
  }

  /**
   * Forget the oldest dead placeholders.
   *
   * `max_active` caps how many are ACTIVE by marking the excess dead; nothing
   * ever removed a row, so the ledger grew forever and every write rewrote all
   * of it. 1400 mints produced 1400 rows and a 744 KiB vault.json, at 13.5ms
   * per mint — and an agent decides how often to mint.
   *
   * Recent dead ones are kept so a replay gets the specific answer it deserves
   * (`exhausted`, `revoked`) rather than the generic one. Past that the
   * checksum still proves the vault minted it and the ledger still refuses it;
   * only the reason becomes less precise.
   */
  #collectDeadPlaceholders() {
    const rows = Object.entries(this.db.placeholders)
    if (rows.length <= MAX_PLACEHOLDER_ROWS) return
    // A row whose time has passed is dead whatever its state says. Rows of a
    // session nobody touched again stay 'active' — expiry is noticed lazily —
    // and they were exempt from this bound, so it bounded nothing.
    const now = Date.now()
    const dead = rows
      .filter(([, p]) => p.state !== 'active' || Date.parse(p.expires_at) <= now)
      .sort((a, b) => String(a[1].created_at).localeCompare(String(b[1].created_at)))
    const overBy = rows.length - MAX_PLACEHOLDER_ROWS
    for (const [id] of dead.slice(0, overBy)) delete this.db.placeholders[id]
  }

  listPlaceholders(sid) {
    return Object.values(this.db.placeholders).filter((p) => !sid || p.sid === sid)
  }

  // --------------------------------------------------------------- listeners

  addListener(entry) {
    // A change that cannot be written to the audit log must not happen.
    // Locking drops the audit key with the master key, so these mutate
    // nothing while locked rather than persisting unrecorded.
    this.#requireUnlocked()
    const lid = entry.id
    if (this.db.listeners[lid]) throw deny('AV_NOT_FOUND', `listener ${lid} already exists`)
    // The surfaces that may never leave the machine. Refusing the whole entry
    // rather than silently dropping the surface is the point: a misconfigured
    // listener must be loud.
    const FORBIDDEN = ['control', 'approver', 'l4']
    const bad = (entry.surfaces || []).filter((s) => FORBIDDEN.includes(s))
    if (bad.length && !isLoopbackSpec(entry.address)) {
      this.audit?.write('listen.refused', { listener_id: lid, reason: 'surface_not_networkable', surfaces: bad })
      throw deny('AV_REMOTE_FORBIDDEN', `surfaces ${bad.join(', ')} can never be bound to a network address`, {
        hint: 'The control API, the approver socket and the database listeners stay on loopback and Unix sockets.',
      })
    }
    this.db.listeners[lid] = { ...entry, created_at: new Date().toISOString(), state: 'configured' }
    this.#persist()
    this.audit.write('listen.bound', { listener_id: lid, address: entry.address, surfaces: entry.surfaces })
    return this.db.listeners[lid]
  }

  removeListener(lid) {
    // A change that cannot be written to the audit log must not happen.
    // Locking drops the audit key with the master key, so these mutate
    // nothing while locked rather than persisting unrecorded.
    this.#requireUnlocked()
    if (!this.db.listeners[lid]) throw deny('AV_NOT_FOUND', `no listener ${lid}`)
    delete this.db.listeners[lid]
    this.#persist()
    this.audit.write('listen.removed', { listener_id: lid })
  }

  listListeners() { return Object.values(this.db.listeners) }

  // ------------------------------------------------------------------ misc

  /**
   * Write the document out. `durable: false` skips the fsync, for state that is
   * cheap to lose — a pending question an agent will ask again, not key
   * material. The rename is atomic either way, so the file is never torn.
   */
  save(opts) { this.#persist(opts) }

  /** What unlocking this vault actually requires. */
  get factors() { return (this.db?.kv?.presence_factors || []).map((f) => f.class) }

  stats() {
    const live = (o, f) => Object.values(o).filter(f).length
    return {
      credentials: Object.keys(this.db.credentials).length,
      workspaces: Object.keys(this.db.workspaces).length,
      credentials_expiring: Object.values(this.db.credentials).filter(c => {
        const actualExpiry = c.health?.observed_expires_at || c.expires_at;
        return actualExpiry && expiryMs(actualExpiry) < Date.now() + 7 * 86400000;
      }).length,
      sessions_active: live(this.db.sessions, (s) => s.state === 'active' && sessionExpiryMs(s) > Date.now()),
      grants_active: live(this.db.grants, (g) => g.state === 'active'),
      placeholders_live: live(this.db.placeholders, (p) => p.state === 'active'),
      listeners: Object.keys(this.db.listeners).length,
      // null, not 0. The log is keyed from the master key, so a locked vault
      // cannot count its own records — and reporting zero reads as "your audit
      // trail was wiped", which is the last thing to say to someone who has
      // just found their vault locked.
      audit_records: this.audit ? this.audit.seq : null,
      locked: this.locked,
    }
  }
}

/** A coarse size label, so exact length never leaves the daemon. */
export function sizeBucket(n) {
  if (n == null) return 'unknown'
  if (n < 16) return 'short'
  if (n < 60) return 'typical'
  return 'long'
}

export function isLoopbackSpec(address = '') {
  return address.startsWith('unix:') || address.startsWith('127.0.0.1:') ||
    address.startsWith('[::1]:') || address.startsWith('localhost:')
}
