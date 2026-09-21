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
import { createHash, randomBytes } from 'node:crypto'
import * as crypt from './crypto.js'
import { id } from './ids.js'
import { AuditLog } from './audit.js'
import * as ph from '../core/placeholder.js'
import { deny } from '../core/errors.js'
import { PROFILES } from '../connectors/profiles.js'

export const SCHEMA_VERSION = 1

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
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    chmodSync(dir, 0o700)
    const v = new Vault(dir)
    if (existsSync(v.dbPath)) throw new Error(`a vault already exists at ${dir}`)

    const deviceKey = crypt.randomKey()
    writeFileSync(v.deviceKeyPath, deviceKey, { mode: 0o600 })

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
    return {
      anchored: !!this.db?.kv?.audit_anchored,
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
  unlockWith(material = {}) {
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
        if (this.db.kv.locked) { this.db.kv.locked = false; this.#persist() }
        this.audit.write('vault.unlock', { factor: wrap.class })
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
    this.db.kv.vmk_wraps = this.db.kv.vmk_wraps.filter((w) => w.class !== 'passphrase' && w.class !== 'none')
    this.db.kv.vmk_wraps.push(wrap)
    this.#syncFactors()
    this.#persist()
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
   * Add Touch ID (or any WebAuthn PRF authenticator) as an unlock factor. A
   * passphrase must already be set, so losing the authenticator can never lock
   * you out: the passphrase is always the recovery path.
   */
  addWebauthnUnlock(credentialId, prfSecret) {
    this.#requireUnlocked()
    if (!this.hasPassphrase) {
      throw deny('AV_POLICY_DENIED', 'set a passphrase first; it is the recovery factor if the authenticator is lost')
    }
    const deviceKey = readFileSync(this.deviceKeyPath)
    this.db.kv.vmk_wraps = this.db.kv.vmk_wraps.filter((w) => w.class !== 'webauthn-prf' && w.class !== 'none')
    const wrap = this.#wrapVmk(deviceKey, this.vmk, 'webauthn-prf', prfSecret)
    wrap.credential_id = credentialId
    this.db.kv.vmk_wraps.push(wrap)
    this.#syncFactors()
    this.#persist()
    this.audit.write('presence.factor_added', { class: 'webauthn-prf', credential_id: credentialId })
    crypt.wipe(deviceKey)
  }

  removeWebauthnUnlock() {
    this.#requireUnlocked()
    const had = this.hasWebauthnUnlock
    this.db.kv.vmk_wraps = this.db.kv.vmk_wraps.filter((w) => w.class !== 'webauthn-prf')
    // Every wrap is a way back to the master key. Remove the last one and the
    // vault is not locked, it is destroyed: no factor opens it, and no factor
    // can be added, because adding one needs the key that is now unreachable.
    // Enrolling requires a passphrase, so this should be impossible — but
    // "should be" is how a one-way door gets left unguarded, and the cost of
    // being wrong here is every credential in the vault, permanently.
    // removePassphrase has had this guard since the beginning; this is the
    // same guard, for the same reason.
    if (!this.db.kv.vmk_wraps.length) {
      const deviceKey = readFileSync(this.deviceKeyPath)
      this.db.kv.vmk_wraps = [this.#wrapVmk(deviceKey, this.vmk, 'none', null)]
      crypt.wipe(deviceKey)
      this.audit.write('presence.factor_downgraded', {
        class: 'none', reason: 'removing the last wrap would have made the vault unopenable',
      })
    }
    this.#syncFactors()
    this.#persist()
    if (had) this.audit.write('presence.factor_removed', { class: 'webauthn-prf' })
    return had
  }

  get hasWebauthnUnlock() { return (this.db?.kv?.vmk_wraps || []).some((w) => w.class === 'webauthn-prf') }
  get webauthnUnlockCredentialId() {
    return (this.db?.kv?.vmk_wraps || []).find((w) => w.class === 'webauthn-prf')?.credential_id || null
  }

  /** The stable salt the PRF is evaluated against; created on first enroll. */
  prfSalt() {
    if (!this.db.kv.prf_salt) { this.db.kv.prf_salt = randomBytes(32).toString('base64'); this.#persist() }
    return this.db.kv.prf_salt
  }

  /** Drop the passphrase, back to the UID-boundary-only 'none' factor. */
  removePassphrase(currentPassphrase) {
    this.#requireUnlocked()
    if (this.hasWebauthnUnlock) {
      throw deny('AV_POLICY_DENIED', 'remove Touch ID unlock first; the passphrase is its recovery factor')
    }
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
    const deviceKey = readFileSync(this.deviceKeyPath)
    this.db.kv.vmk_wraps = this.db.kv.vmk_wraps.filter((w) => w.class !== 'passphrase')
    if (!this.db.kv.vmk_wraps.length) this.db.kv.vmk_wraps = [this.#wrapVmk(deviceKey, this.vmk, 'none', null)]
    this.#syncFactors()
    this.#persist()
    this.audit.write('presence.factor_removed', { class: 'passphrase' })
    crypt.wipe(deviceKey)
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
    let unlocked = false
    try {
      this.unlockWith({ passphrase })
      unlocked = true
    } catch { unlocked = false }

    if (!unlocked || wasLocked) {
      if (this.vmk) crypt.wipe(this.vmk)
      this.vmk = null
      // The audit log needs a key. Without one (a passphrase/Touch-ID vault we
      // could not open) it stays silent until the human unlocks; that is the
      // honest consequence of a cryptographic lock.
      if (this.db.kv.locked !== true) { this.db.kv.locked = true; this.#persist() }
      if (this.audit) this.audit.write('vault.started_locked', {})
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
  #persist() {
    const tmp = `${this.dbPath}.tmp`
    const text = JSON.stringify(this.db, null, 1)
    // The mode argument to writeFileSync applies at CREATION only. A temp file
    // left behind by a crash is written into with whatever mode it already
    // has, so reassert it rather than inherit it.
    const fd = openSync(tmp, 'w', 0o600)
    try {
      writeFileSync(fd, text)
      fchmodSync(fd, 0o600)
      fsyncSync(fd)
    } finally {
      closeSync(fd)
    }
    renameSync(tmp, this.dbPath)
    // Best effort: a filesystem that will not let us open the directory is not
    // a reason to fail the write that already succeeded.
    try {
      const dirFd = openSync(this.dir, 'r')
      try { fsyncSync(dirFd) } finally { closeSync(dirFd) }
    } catch { /* not every platform allows this */ }
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
    return {
      id: cred.id, slug: cred.slug, kind: cred.connector_kind, connector: cred.connector,
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

  createSession({ workspaceId, label, ttlMs = 8 * 3600_000, policy = {}, peerUid = process.getuid?.(), remote = false, clientName = null }) {
    this.#requireUnlocked()
    const sid = ph.newSid()
    const secret = randomBytes(33).toString('base64url')
    const token = `avs1.${sid}.${secret}`
    const now = Date.now()
    const session = {
      id: sid, workspace_id: workspaceId || null, label: label || 'session',
      token_hash: createHash('sha256').update(token).digest('hex'),
      policy, owner_uid: peerUid ?? null, remote, client_name: clientName,
      state: 'active',
      created_at: new Date(now).toISOString(),
      expires_at: new Date(now + ttlMs).toISOString(),
      max_expires_at: new Date(now + (remote ? 8 : 24) * 3600_000).toISOString(),
      idle_timeout_ms: (remote ? 1 : 2) * 3600_000,
      last_seen_at: new Date(now).toISOString(),
    }
    this.db.sessions[sid] = session
    this.#persist()
    this.audit.write('session.created', { session_id: sid, workspace_id: workspaceId, label, remote })
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
    if (Date.parse(session.expires_at) <= Date.now()) {
      if (session.state !== 'expired') { session.state = 'expired'; this.#persist() }
      throw deny('AV_SESSION_EXPIRED', `session ${session.id} expired at ${session.expires_at}`)
    }
    return session
  }

  /** Idle extension. Never widens capability, so it needs no presence. */
  touchSession(session) {
    const now = Date.now()
    const extended = Math.min(now + session.idle_timeout_ms, Date.parse(session.max_expires_at))
    if (extended > Date.parse(session.expires_at)) session.expires_at = new Date(extended).toISOString()
    session.last_seen_at = new Date(now).toISOString()
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

  createGrant({ sessionId, credentialId, fields, policy, narrow = null }) {
    // A change that cannot be written to the audit log must not happen.
    // Locking drops the audit key with the master key, so these mutate
    // nothing while locked rather than persisting unrecorded.
    this.#requireUnlocked()
    const session = this.db.sessions[sessionId]
    if (!session) throw deny('AV_NOT_FOUND', `no session ${sessionId}`)
    const cred = this.db.credentials[credentialId]
    if (!cred) throw deny('AV_NOT_FOUND', `no credential ${credentialId}`)
    const grantId = id.grant()
    const grant = {
      id: grantId, session_id: sessionId, credential_id: credentialId,
      fields: fields || cred.fields.map((f) => f.name),
      policy: narrow && Object.keys(narrow).length ? { ...policy, ...narrow } : policy,
      budget_used: 0, counters: { requests: 0, denials: 0 }, state: 'active',
      created_at: new Date().toISOString(),
    }
    this.db.grants[grantId] = grant
    this.#persist()
    this.audit.write('grant.created', { grant_id: grantId, session_id: sessionId, credential_slug: cred.slug })
    return grant
  }

  grantsForSession(sid) {
    return Object.values(this.db.grants).filter((g) => g.session_id === sid && g.state === 'active')
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
  narrowGrant(grantId, narrow) {
    // A change that cannot be written to the audit log must not happen.
    // Locking drops the audit key with the master key, so these mutate
    // nothing while locked rather than persisting unrecorded.
    this.#requireUnlocked()
    const g = this.db.grants[grantId]
    if (!g) throw deny('AV_NOT_FOUND', `no grant ${grantId}`)
    g.policy = { ...g.policy, ...narrow }
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
    if (!grant || grant.state !== 'active') throw deny('AV_NO_GRANT', `no active grant ${grantId}`)
    const session = this.assertSessionLive(this.db.sessions[grant.session_id])
    const cred = this.db.credentials[grant.credential_id]
    const fieldName = field || grant.fields[0]
    if (!grant.fields.includes(fieldName)) throw deny('AV_NO_GRANT', `grant does not cover field ${fieldName}`)

    // `?? 1000` does not catch NaN, only null and undefined, so a malformed
    // budget propagated straight into the placeholder's use ceiling — and
    // `Math.min(asked, NaN)` is NaN, which no `uses >= max_uses` ever stops.
    const stated = Number(grant.policy?.budget?.limit)
    const budgetLimit = Number.isFinite(stated) && stated > 0 ? stated : 1000
    const phPolicy = grant.policy?.placeholder_policy || {}
    const maxActive = phPolicy.max_active ?? 8
    const active = Object.values(this.db.placeholders)
      .filter((p) => p.grant_id === grantId && p.field === fieldName && p.state === 'active')
    if (active.length >= maxActive) {
      // Evict the oldest unused rather than refusing: an agent that asks twice
      // should get a working placeholder, not an error it cannot act on.
      const oldest = active.filter((p) => p.uses === 0).sort((a, b) => a.created_at.localeCompare(b.created_at))[0]
      if (oldest) { oldest.state = 'dead'; oldest.dead_reason = 'rotated' }
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
    const ttl = ttlMs ?? (phPolicy.ttl ? phPolicy.ttl * 1000 : null)
    const expires = Math.min(
      ttl ? Date.now() + ttl : Infinity,
      Date.parse(session.expires_at),
    )
    const minted = ph.mint({ kPh: this.kPh, sid: session.id, slug: cred.slug, field: fieldName })
    const row = {
      id: id.placeholder(), grant_id: grantId, credential_id: cred.id, field: fieldName,
      sid: session.id, nonce_hash: minted.nonceHash,
      uses: 0, max_uses: maxUses, state: 'active', dead_reason: null, replaces_id: null,
      created_at: new Date().toISOString(),
      expires_at: new Date(expires).toISOString(),
      last_used_at: null,
    }
    this.db.placeholders[row.id] = row
    this.#persist()
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
    if (Date.parse(row.expires_at) <= Date.now()) {
      row.state = 'dead'; row.dead_reason = 'expired'; this.#persist()
      throw deny('AV_PH_STALE', 'placeholder expired', {
        next: { cli: ['agent-vault ph next <cred>'], mcp: { tool: 'vault_get_placeholder' } },
      })
    }
    if (row.uses >= row.max_uses) {
      row.state = 'dead'; row.dead_reason = 'exhausted'; this.#persist()
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
  refundPlaceholder(rowId) {
    const row = this.db.placeholders[rowId]
    if (!row) return
    if (row.uses > 0) row.uses -= 1
    if (row.state === 'dead' && row.dead_reason === 'exhausted') { row.state = 'active'; row.dead_reason = null }
    const grant = this.db.grants[row.grant_id]
    if (grant && grant.budget_used > 0) grant.budget_used -= 1
    this.#persist()
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

  save() { this.#persist() }

  /** What unlocking this vault actually requires. */
  get factors() { return (this.db?.kv?.presence_factors || []).map((f) => f.class) }

  stats() {
    const live = (o, f) => Object.values(o).filter(f).length
    return {
      credentials: Object.keys(this.db.credentials).length,
      workspaces: Object.keys(this.db.workspaces).length,
      sessions_active: live(this.db.sessions, (s) => s.state === 'active' && Date.parse(s.expires_at) > Date.now()),
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
