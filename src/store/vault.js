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
import { PIN_RE, pinListState, urlHostOf } from '../connectors/pinning.js'
import { compileScrubPattern } from '../core/scrub.js'
import { canonicalOperation } from '../ui/webauthn.js'

export const SCHEMA_VERSION = 1

/**
 * When something stamped with `iso` stops being valid, as epoch ms. Absent is
 * "no limit" (Infinity); anything that does not parse counts as already past
 * (-Infinity), so a corrupted date can only end access early, never extend it.
 * `Date.parse` alone is NaN for garbage, and `NaN <= now` is false: that is how
 * an unparseable `expires_at` used to be live forever.
 */
export function expiryMs(iso) {
  if (iso === null || iso === undefined) return Infinity
  if (typeof iso !== 'string') return -Infinity
  const ms = Date.parse(iso)
  return Number.isNaN(ms) ? -Infinity : ms
}

/**
 * When a session ends. Only a session that says it is infinite with exactly
 * `infinite === true` and `expires_at === null` never ends. A missing date on
 * any other session — a legacy row, a truthy-but-not-true flag, a flag with the
 * date dropped — is expired, never eternal.
 */
export function sessionExpiryMs(s) {
  if (s.expires_at === null || s.expires_at === undefined) {
    return s.infinite === true && s.expires_at === null ? Infinity : -Infinity
  }
  return expiryMs(s.expires_at)
}

/** The furthest a session could live, idle extension included. */
function sessionCeilingMs(s) {
  const ends = sessionExpiryMs(s)
  if (ends === Infinity || !(ends > -Infinity)) return ends
  return s.max_expires_at == null ? ends : Math.max(ends, expiryMs(s.max_expires_at))
}

/** A ledger row's end. Exactly null never expires; anything else unreadable already has. */
function rowExpiryMs(row) {
  return row.expires_at === null ? Infinity : (typeof row.expires_at === 'string' ? expiryMs(row.expires_at) : -Infinity)
}

/** `min(a, b)` as an ISO date, or `now` when it is already behind us. */
function shortenedIso(current, now, ttlMs) {
  const at = Math.min(current, now + ttlMs)
  return new Date(at > now ? at : now).toISOString()
}

// How close an expiry has to be before a credential is flagged (F10).
export const EXPIRY_WARN_DAYS = 7

/** 'expired', 'soon' or null. The sooner of the human's date and the observed one wins. */
export function expiryWarning(cred, now = Date.now()) {
  const dates = [cred.expires_at, cred.health?.observed_expires_at].filter((d) => d != null)
  if (!dates.length) return null
  const ends = Math.min(...dates.map(expiryMs))
  if (!(ends > now)) return 'expired'
  return ends < now + EXPIRY_WARN_DAYS * 86_400_000 ? 'soon' : null
}

/** An ISO date, normalised, or undefined when `v` is not one. */
function isoOrUndefined(v) {
  if (typeof v !== 'string') return undefined
  const ms = Date.parse(v)
  return Number.isNaN(ms) ? undefined : new Date(ms).toISOString()
}

/**
 * A bundle's quarantine record, checked by the rules setQuarantine keeps, or
 * the whole restore refused: one that cannot be read is never dropped, since
 * dropping it would release the credential.
 */
function restoredQuarantine(q, format) {
  const ok = q && typeof q === 'object' && !Array.isArray(q) &&
    Object.keys(q).every((k) => ['since', 'by', 'rule_id', 'reason_untrusted'].includes(k)) &&
    isoOrUndefined(q.since) !== undefined && (q.by === 'control' || q.by === 'tripwire') &&
    (q.rule_id == null || (typeof q.rule_id === 'string' && /^[a-z0-9_-]{1,32}$/.test(q.rule_id))) &&
    (q.reason_untrusted == null || (typeof q.reason_untrusted === 'string' && q.reason_untrusted.length <= 200))
  if (!ok) throw format('a quarantine record is malformed')
  return { since: q.since, by: q.by, rule_id: q.rule_id ?? null, reason_untrusted: q.reason_untrusted ?? null }
}

/** `a` is `b`, or a restored copy of it (`-restored`, `-restored-2`, … as F8 renames), or `b` is one of `a`. */
function sameCredential(a, b) {
  const copyOf = (slug, base) => {
    const m = /-restored(?:-\d+)?$/.exec(slug)
    return !!m && slug.slice(0, m.index) === base.slice(0, 24 - m[0].length)
  }
  return a === b || copyOf(a, b) || copyOf(b, a)
}

const DAY_MS = 86_400_000

// Binds the sealed webhook URL to what it is, so no other blob opens as one.
const NOTIFY_AAD = 'av/notify/webhook'

// F4's bounds on scrub patterns. The grammar is the gateway's (C5).
const MAX_SCRUB_SOURCE = 256
const MAX_SCRUB_PER_CRED = 16
const MAX_SCRUB_TOTAL = 64

// F17's bounds on templates.
const TEMPLATE_NAME = /^[a-z0-9][a-z0-9-]{0,31}$/
const MAX_TEMPLATE_BYTES = 16 * 1024
const MAX_TEMPLATES = 64

// What elevated a session (C3). Recorded, not decided, here: the daemon decides
// with elevationOf(), and the store refuses anything it does not recognise.
const ELEVATIONS = new Set(['approval_auto_writes', 'infinite'])

// F10's health record. Only these keys, each only with a value of its type.
const HEALTH_STATUS = new Set(['ok', 'unauthorized', 'forbidden', 'unreachable', 'error', 'unknown'])
const HEALTH_SOURCE = new Set(['probe', 'response'])

// F16's tripwire rules. The shape is checked here, where it is stored, so no
// reader of `settings.tripwires` has to wonder what it might hold.
const RULE_KEYS = new Set(['id', 'codes', 'rule_prefix', 'threshold', 'window_s', 'action'])
const RULE_ACTIONS = new Set(['revoke_session', 'quarantine_credential', 'panic'])
const MAX_TRIPWIRE_RULES = 32

function tripwireProblem(tw) {
  if (!tw || typeof tw !== 'object' || Array.isArray(tw)) return 'tripwires must be an object'
  for (const k of Object.keys(tw)) if (k !== 'enabled' && k !== 'rules') return `tripwires has an unknown key ${JSON.stringify(k)}`
  if (typeof tw.enabled !== 'boolean') return 'tripwires.enabled must be true or false'
  if (!Array.isArray(tw.rules)) return 'tripwires.rules must be a list'
  if (tw.rules.length > MAX_TRIPWIRE_RULES) return `at most ${MAX_TRIPWIRE_RULES} tripwire rules`
  const ids = new Set()
  for (const r of tw.rules) {
    if (!r || typeof r !== 'object' || Array.isArray(r)) return 'a tripwire rule must be an object'
    for (const k of Object.keys(r)) if (!RULE_KEYS.has(k)) return `a tripwire rule has an unknown key ${JSON.stringify(k)}`
    if (typeof r.id !== 'string' || !/^[a-z0-9_-]{1,32}$/.test(r.id)) return 'a tripwire rule id must match [a-z0-9_-]{1,32}'
    if (ids.has(r.id)) return `tripwire rule ${r.id} appears twice`
    ids.add(r.id)
    if (r.codes !== undefined && (!Array.isArray(r.codes) || !r.codes.length || r.codes.length > 16 ||
      !r.codes.every((c) => typeof c === 'string' && /^AV_[A-Z0-9_]{1,40}$/.test(c)))) {
      return `tripwire rule ${r.id}: codes must be a non-empty list of AV_* codes`
    }
    // An empty prefix matches every rule name there is.
    if (r.rule_prefix !== undefined && (typeof r.rule_prefix !== 'string' || !/^[a-z0-9_:.-]{1,64}$/.test(r.rule_prefix))) {
      return `tripwire rule ${r.id}: rule_prefix must be 1-64 characters of [a-z0-9_:.-]`
    }
    if (r.codes === undefined && r.rule_prefix === undefined) return `tripwire rule ${r.id} matches nothing: give codes or rule_prefix`
    if (!Number.isInteger(r.threshold) || r.threshold < 1 || r.threshold > 1000) return `tripwire rule ${r.id}: threshold must be an integer 1-1000`
    if (!Number.isInteger(r.window_s) || r.window_s < 10 || r.window_s > 86_400) return `tripwire rule ${r.id}: window_s must be an integer 10-86400`
    if (!RULE_ACTIONS.has(r.action)) return `tripwire rule ${r.id}: action must be revoke_session, quarantine_credential or panic`
  }
  return null
}

/** The refusal for a quarantined credential (F16), the same wherever it is met. */
function quarantined(cred) {
  return deny('AV_QUARANTINED', `${cred.slug} is quarantined`, {
    rule: 'quarantine', hint: `A human can release it: agent-vault cred release ${cred.slug}`,
  })
}


/** The refusal for a grant whose budget is spent, or cannot be read: the gateway's rule. */
function budgetSpent(limit) {
  return deny('AV_POLICY_DENIED', limit === null
    ? 'this grant has a budget that cannot be read, so no request can be counted against it'
    : `grant budget of ${limit} requests is spent`, { rule: 'budget', hint: 'A human must widen the grant or start a new session.' })
}

const MAX_PIN_HOSTS = 4

/** F11: 1 to 4 pins of the one format, each kept once, or refused. */
function pinList(pins) {
  if (pinListState(pins) !== 'pinned') {
    throw deny('AV_POLICY_DENIED', 'pins are 1 to 4 values of the form sha256/<base64 of 32 bytes>', { rule: 'pin_format' })
  }
  return [...new Set(pins)]
}

/** A stored pin table as an object, or {} when it is not one. */
function plainTable(pins) {
  return pins && typeof pins === 'object' && !Array.isArray(pins) ? pins : {}
}

/** A copy of a pin table without any key that names `key`'s host. */
function pinTableOf(pins, key) {
  return Object.fromEntries(Object.entries(plainTable(pins)).filter(([k]) => urlHostOf(k) !== key))
}

/** Pin counts per host for a public view (F11): never the pins. */
function pinCounts(pins) {
  return Object.fromEntries(Object.entries(plainTable(pins)).map(([k, v]) => [k, Array.isArray(v) ? v.length : 0]))
}

function scrubRefusal(why) {
  return deny('AV_POLICY_DENIED', `scrub pattern refused: ${why}`, { rule: 'scrub_pattern' })
}

/**
 * A grant's own request budget, for a placeholder's issue and use and a
 * redirect hop's charge: the gateway's reader (C4, policy.budgetLimit), so the
 * two cannot disagree. Infinity when the layer states no limit (the gateway
 * then takes it from the session's layer), the number, or null when it cannot
 * be read, which refuses. A policy with no budget key states none.
 */
function budgetLimit(policy) {
  return policyMod.budgetLimit(policy?.budget)
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
      // What a witness checkpoint names (F9): stable for the vault's life,
      // created on first use and written durably, since a witness file
      // outlives any one run.
      vaultId: () => {
        if (!this.db?.kv) return null
        if (!this.db.kv.vault_id) {
          this.db.kv.vault_id = id.vault()
          this.#persist()
        }
        return this.db.kv.vault_id
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
    if (this.findCredential(slug)) throw deny('AV_NOT_FOUND', `credential ${slug} already exists`)
    const cred = this.#sealCredential({ slug, kind, connector, fields, sites })
    this.db.credentials[cred.id] = cred
    this.#persist()
    this.audit.write('cred.added', { credential_slug: slug, connector: kind, fields: cred.fields.map((f) => f.name) })
    return this.publicCredential(cred)
  }

  /** A new credential record, every value sealed, checked and not yet stored. Writes nothing. */
  #sealCredential({ slug, kind, connector = {}, fields = {}, sites = {} }) {
    if (!ph.isValidSlug(slug)) throw deny('AV_NOT_FOUND', `invalid slug "${slug}": use [a-z0-9-], 1-24 characters`)
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
    return {
      id: credId, slug, connector_kind: kind, connector, fields: stored,
      created_at: new Date().toISOString(),
    }
  }

  findCredential(slug) {
    return Object.values(this.db.credentials).find((c) => c.slug === slug) || null
  }

  /** The credential as anything outside the daemon may see it: never a value. */
  publicCredential(cred) {
    return {
      id: cred.id, slug: cred.slug, kind: cred.connector_kind, connector: cred.connector,
      expires_at: cred.expires_at ?? null,
      health: cred.health ? structuredClone(cred.health) : null,
      expiry_warning: expiryWarning(cred),
      quarantine: cred.quarantine ? structuredClone(cred.quarantine) : null,
      scrub_patterns: (cred.scrub_patterns || []).map(({ id: pid, source, added_at }) => ({ id: pid, source, added_at })),
      // F11: how many pins each host has, never the pins themselves.
      pins: pinCounts(cred.pins),
      // No exact length: it narrows an offline guess and, with the fingerprint,
      // is metadata a credential value should not leak. A coarse bucket is
      // enough for the UI to say something useful.
      fields: cred.fields.map((f) => ({
        name: f.name, sites: f.sites, fp8: f.fp8, size: sizeBucket(f.length),
        version: f.key_version ?? 1, rotated_at: f.rotated_at ?? null,
      })),
      // The profile's own read-only probe. Not sensitive — it is a constant of
      // the connector kind — and it lets a caller show an example request that
      // actually works instead of a made-up path.
      probe_path: PROFILES[cred.connector_kind]?.probe?.path || null,
      created_at: cred.created_at,
    }
  }

  listCredentials() { return Object.values(this.db.credentials).map((c) => this.publicCredential(c)) }

  /**
   * Decrypt one field for a request: the pipeline's only path to a plaintext
   * value. A quarantined credential is refused here (F16), not just where the
   * gateway looks, so a placeholder issued before the quarantine reaches
   * nothing either.
   */
  revealField(credId, fieldName) {
    this.#requireUnlocked()
    const cred = this.db.credentials[credId]
    if (!cred) throw deny('AV_NOT_FOUND', `no credential ${credId}`)
    if (cred.quarantine) throw quarantined(cred)
    return this.#unseal(cred, fieldName)
  }

  /**
   * A field's plaintext, quarantined or not. For the vault's own readers —
   * the scrubber's match set, rotation, a backup — and never for a request:
   * a quarantined value still has to be scrubbed, rotated and kept.
   */
  #unseal(cred, fieldName) {
    const field = cred.fields.find((f) => f.name === fieldName)
    if (!field) throw deny('AV_NOT_FOUND', `credential ${cred.slug} has no field ${fieldName}`)
    const key = crypt.dek(this.vmk, cred.id)
    return crypt.open(key, field, `${cred.id}|${fieldName}|${field.key_version}`)
  }

  /**
   * Every unsealed credential value, for the scrubber's match set. That
   * includes a rotated-out value until its retire_until (F7), so an upstream
   * that echoes the old token for a while is still scrubbed. Read-only: an
   * expired retired value is skipped here and dropped at the next rotation.
   */
  allSecrets() {
    this.#requireUnlocked()
    const out = []
    const now = Date.now()
    for (const cred of Object.values(this.db.credentials)) {
      const key = crypt.dek(this.vmk, cred.id)
      for (const f of cred.fields) {
        try { out.push({ secret: this.#unseal(cred, f.name), label: cred.slug, field: f.name }) } catch { /* skip */ }
        for (const r of f.retired || []) {
          if (!(expiryMs(r.retire_until) > now)) continue
          try {
            out.push({ secret: crypt.open(key, r, `${cred.id}|${f.name}|${r.key_version}`), label: cred.slug, field: f.name, retired: true })
          } catch { /* skip */ }
        }
      }
    }
    return out
  }

  /**
   * The human's own note of when a credential stops working (F10). Metadata,
   * not enforcement: the upstream refuses an expired credential anyway, and
   * refusing it here would hand an agent a way to deny service. Stored as one
   * normalised ISO string, so every reader parses the same thing.
   */
  setCredentialExpiry(slug, isoOrNull) {
    this.#requireUnlocked()
    const cred = this.findCredential(slug)
    if (!cred) throw deny('AV_NOT_FOUND', `no credential ${slug}`)
    const expires = isoOrNull === null ? null : isoOrUndefined(isoOrNull)
    if (expires === undefined) {
      throw deny('AV_POLICY_DENIED', 'expires_at must be an ISO date, or null to clear it', { rule: 'expires_at' })
    }
    cred.expires_at = expires
    this.#persist()
    this.audit.write('cred.expiry_set', { credential_slug: cred.slug, expires_at: expires })
    return this.publicCredential(cred)
  }

  /**
   * Merge what was observed about a credential (F10): from a probe, or from
   * the headers of a response it was used for. Called on the hot path, so the
   * write skips the fsync and the log only hears about a change of status or
   * of the observed expiry: a busy credential must not flood the log.
   *
   * Only the record's own keys are taken, each only with a value of its type.
   * A value that is not one is dropped rather than stored, because it would
   * reach the audit record (where a float throws) and every reader after it.
   * A locked vault cannot record, so it changes nothing and returns null.
   */
  recordHealth(credIdOrSlug, patch) {
    if (this.locked) return null
    const cred = (Object.hasOwn(this.db.credentials, credIdOrSlug) && this.db.credentials[credIdOrSlug]) || this.findCredential(credIdOrSlug)
    if (!cred || !patch || typeof patch !== 'object') return null
    const clean = {}
    if (HEALTH_STATUS.has(patch.status)) clean.status = patch.status
    if (patch.http_status === null || (Number.isInteger(patch.http_status) && patch.http_status >= 100 && patch.http_status <= 599)) clean.http_status = patch.http_status
    if (isoOrUndefined(patch.checked_at)) clean.checked_at = isoOrUndefined(patch.checked_at)
    if (HEALTH_SOURCE.has(patch.source)) clean.source = patch.source
    if (patch.observed_expires_at === null) clean.observed_expires_at = null
    else if (isoOrUndefined(patch.observed_expires_at)) clean.observed_expires_at = isoOrUndefined(patch.observed_expires_at)
    if (patch.scopes === null || (Array.isArray(patch.scopes) && patch.scopes.length <= 64 &&
      patch.scopes.every((s) => typeof s === 'string' && s.length <= 128))) clean.scopes = patch.scopes && [...patch.scopes]
    const before = cred.health || {}
    const health = {
      status: 'unknown', http_status: null, checked_at: new Date().toISOString(), source: 'response',
      observed_expires_at: null, scopes: null, ...before, ...clean,
    }
    cred.health = health
    this.#persist({ durable: false })
    if (health.status !== before.status || health.observed_expires_at !== (before.observed_expires_at ?? null)) {
      this.audit.write('cred.health_recorded', {
        credential_slug: cred.slug, status: health.status, http_status: health.http_status,
        source: health.source, observed_expires_at: health.observed_expires_at,
      })
    }
    return structuredClone(health)
  }

  /**
   * Stop a credential being used at all (F16), until a human releases it. Open
   * by design: it only narrows, and it has to work in an emergency. A second
   * quarantine keeps the first record, so who stopped it first, and when, is
   * not overwritten by whoever repeats it.
   */
  setQuarantine(slug, { by = 'control', rule_id = null, reason = null } = {}) {
    this.#requireUnlocked()
    const cred = this.findCredential(slug)
    if (!cred) throw deny('AV_NOT_FOUND', `no credential ${slug}`)
    if (by !== 'control' && by !== 'tripwire') throw deny('AV_POLICY_DENIED', 'a quarantine is set by control or tripwire', { rule: 'quarantine' })
    if (rule_id !== null && (typeof rule_id !== 'string' || !/^[a-z0-9_-]{1,32}$/.test(rule_id))) {
      throw deny('AV_POLICY_DENIED', 'a tripwire rule id must match [a-z0-9_-]{1,32}', { rule: 'quarantine' })
    }
    if (cred.quarantine) return structuredClone(cred.quarantine)
    // Written by whoever called the open route, an agent included.
    const reasonUntrusted = typeof reason === 'string' && reason ? reason.slice(0, 200) : null
    cred.quarantine = { since: new Date().toISOString(), by, rule_id, reason_untrusted: reasonUntrusted }
    this.#persist()
    this.audit.write('cred.quarantined', { credential_slug: cred.slug, by, rule_id, reason_untrusted: reasonUntrusted })
    return structuredClone(cred.quarantine)
  }

  /** Release a quarantine. Grants were paused, not revoked, so live ones work again. */
  clearQuarantine(slug) {
    this.#requireUnlocked()
    const cred = this.findCredential(slug)
    if (!cred) throw deny('AV_NOT_FOUND', `no credential ${slug}`)
    if (!cred.quarantine) return false
    cred.quarantine = null
    this.#persist()
    this.audit.write('cred.released', { credential_slug: cred.slug })
    return true
  }

  /** A deep copy: nothing a caller does to it reaches the vault. Not secret, so open while locked. */
  getSettings() {
    return structuredClone(this.db.kv.settings || {})
  }

  /** Shallow merge per top-level key (F16). Tripwire rules are checked whole before anything is kept. */
  updateSettings(patch) {
    this.#requireUnlocked()
    if (!patch || typeof patch !== 'object' || Array.isArray(patch)) {
      throw deny('AV_POLICY_DENIED', 'settings must be an object', { rule: 'policy_invalid' })
    }
    const keys = Object.keys(patch)
    for (const k of keys) {
      // `__proto__` as an own key of parsed JSON would replace the prototype.
      if (!/^[a-z][a-z0-9_]{0,31}$/.test(k)) throw deny('AV_POLICY_DENIED', 'a setting name must match [a-z][a-z0-9_]{0,31}', { rule: 'policy_invalid' })
    }
    if (Object.hasOwn(patch, 'tripwires')) {
      const problem = tripwireProblem(patch.tripwires)
      if (problem) throw deny('AV_POLICY_DENIED', problem, { rule: 'tripwire_rule' })
    }
    const next = { ...(this.db.kv.settings || {}) }
    for (const k of keys) next[k] = structuredClone(patch[k])
    this.db.kv.settings = next
    this.#persist()
    this.audit.write('settings.changed', { keys })
    return this.getSettings()
  }

  // ---------------------------------------------------- F4: scrub patterns

  /**
   * Add a scrub pattern to a credential (F4): a raw store write. The route
   * compiles the pattern first (the gateway's compileScrubPattern decides the
   * grammar); this checks the bounds, and that the source carries no secret.
   * A pattern is stored in clear and shown to whoever lists credentials, so a
   * source that contains a stored credential value, or a placeholder, would
   * publish it. The log keeps only its digest and length.
   */
  addScrubPattern(slug, source) {
    this.#requireUnlocked()
    const cred = this.findCredential(slug)
    if (!cred) throw deny('AV_NOT_FOUND', `no credential ${slug}`)
    const refuse = scrubRefusal
    this.#checkScrubSource(source, this.allSecrets().map((s) => s.secret))
    const mine = cred.scrub_patterns || []
    if (mine.length >= MAX_SCRUB_PER_CRED) throw refuse(`at most ${MAX_SCRUB_PER_CRED} patterns per credential`)
    const total = Object.values(this.db.credentials).reduce((n, c) => n + (c.scrub_patterns?.length || 0), 0)
    if (total >= MAX_SCRUB_TOTAL) throw refuse(`at most ${MAX_SCRUB_TOTAL} patterns in the vault`)
    const pattern = { id: id.scrubPattern(), source, added_at: new Date().toISOString() }
    cred.scrub_patterns = [...mine, pattern]
    this.#persist()
    this.#auditScrubPattern(cred, pattern)
    return { ...pattern }
  }

  /** The source rules, shared with a restore so both refuse the same patterns. Writes nothing. */
  #checkScrubSource(source, secrets) {
    const refuse = scrubRefusal
    // 3 characters (F4) up to 256 (C5, which revised F4's 200).
    if (typeof source !== 'string' || source.length < 3 || source.length > MAX_SCRUB_SOURCE) {
      throw refuse(`a pattern is 3 to ${MAX_SCRUB_SOURCE} characters`)
    }
    if (ph.findAll(source).length) throw refuse('it contains a placeholder')
    for (const secret of secrets) {
      if (secret && source.includes(secret)) throw refuse('it contains a stored credential value')
    }
    // The gateway's own grammar (C5), so a pattern stored here is one the
    // scrubber can apply. One it could not compile would withhold every
    // response from every credential (scrub_pattern_invalid).
    compileScrubPattern(source)
  }

  #auditScrubPattern(cred, pattern) {
    this.audit.write('cred.scrub_pattern_added', {
      credential_slug: cred.slug, pattern_id: pattern.id,
      pattern_sha256: createHash('sha256').update(pattern.source).digest('hex'), length: pattern.source.length,
    })
  }

  /** Remove one scrub pattern. False, and nothing recorded, when there was none. */
  removeScrubPattern(slug, patternId) {
    this.#requireUnlocked()
    const cred = this.findCredential(slug)
    if (!cred) throw deny('AV_NOT_FOUND', `no credential ${slug}`)
    const mine = cred.scrub_patterns || []
    if (!mine.some((p) => p.id === patternId)) return false
    cred.scrub_patterns = mine.filter((p) => p.id !== patternId)
    this.#persist()
    this.audit.write('cred.scrub_pattern_removed', { credential_slug: cred.slug, pattern_id: patternId })
    return true
  }

  // ------------------------------------------------------- F11: SPKI pins

  /**
   * Pin a host of a credential to these SPKI digests (F11), replacing that
   * host's list. The host is stored the way the connectors read a pin key
   * (urlHostOf), so the gateway and the probe find it under the URL host
   * they connect to, and two spellings of one host are one entry. It must be
   * a host this credential can reach. Pins are 1 to 4 values of the one
   * format (pinListState), each kept once; at most 4 hosts.
   */
  setPins(slug, host, pins) {
    this.#requireUnlocked()
    const cred = this.findCredential(slug)
    if (!cred) throw deny('AV_NOT_FOUND', `no credential ${slug}`)
    const key = this.#pinHost(cred, host)
    const list = pinList(pins)
    const table = { ...pinTableOf(cred.pins, key), [key]: list }
    if (Object.keys(table).length > MAX_PIN_HOSTS) {
      throw deny('AV_POLICY_DENIED', `at most ${MAX_PIN_HOSTS} hosts can be pinned`, { rule: 'pin_host' })
    }
    cred.pins = table
    this.#persist()
    this.audit.write('cred.pins_set', { credential_slug: cred.slug, host: key, pins: list.length })
    return { slug: cred.slug, host: key, pins: list.length }
  }

  /**
   * Remove one pin from a host, or every pin of it (`spki` null). Returns how
   * many stay for that host. Nothing is written or recorded when nothing was
   * removed.
   */
  clearPins(slug, host, spki = null) {
    this.#requireUnlocked()
    const cred = this.findCredential(slug)
    if (!cred) throw deny('AV_NOT_FOUND', `no credential ${slug}`)
    if (spki !== null && (typeof spki !== 'string' || !PIN_RE.test(spki))) {
      throw deny('AV_POLICY_DENIED', 'a pin is sha256/<base64 of 32 bytes>', { rule: 'pin_format' })
    }
    const key = typeof host === 'string' ? urlHostOf(host) : null
    if (!key) throw deny('AV_POLICY_DENIED', `${String(host)} is not a host name`, { rule: 'pin_host' })
    const current = Object.entries(plainTable(cred.pins))
      .filter(([k, v]) => urlHostOf(k) === key && Array.isArray(v))
      .flatMap(([, v]) => v)
    const remaining = spki === null ? [] : [...new Set(current.filter((p) => p !== spki))]
    const removed = new Set(current).size - remaining.length
    if (removed === 0) return remaining.length
    const table = pinTableOf(cred.pins, key)
    if (remaining.length) table[key] = remaining
    cred.pins = table
    this.#persist()
    this.audit.write('cred.pins_removed', { credential_slug: cred.slug, host: key, pins: removed })
    return remaining.length
  }

  /** The canonical pin key for `host`, refused unless this credential can reach it. Writes nothing. */
  #pinHost(cred, host) {
    const key = typeof host === 'string' ? urlHostOf(host) : null
    const ceiling = policyMod.credentialHostCeiling(cred, PROFILES[cred.connector_kind]?.hosts || [])
    if (!key || !ceiling.some((h) => urlHostOf(h) === key || policyMod.matchHost(h, key))) {
      throw deny('AV_POLICY_DENIED', `${String(host)} is not a host this credential reaches`, { rule: 'pin_host' })
    }
    return key
  }

  // ------------------------------------------------------- F7: rotation

  /**
   * Replace a field's value (F7). The current sealed value moves into
   * `retired`, where it stays only so an upstream that echoes the old token
   * is still scrubbed until `retire_until`; it is never substituted again.
   * The new value is sealed under the same per-credential key with the next
   * key_version in the AAD, as every field is.
   *
   * Everything is checked before anything changes, and `mode: 'revoke'`
   * revokes the credential's grants. The route then denies the credential's
   * held approvals (pipeline.denyApprovals): a human approved those against
   * the old key, and the new one may reach further.
   */
  rotateCredential(slug, { field = null, value, mode = 'keep', retireMs = DAY_MS, expiresAt = undefined } = {}) {
    this.#requireUnlocked()
    const cred = this.findCredential(slug)
    if (!cred) throw deny('AV_NOT_FOUND', `no credential ${slug}`)
    const f = field === null ? cred.fields[0] : cred.fields.find((x) => x.name === field)
    if (!f) throw deny('AV_NOT_FOUND', `credential ${slug} has no field ${field}`)
    if (typeof value !== 'string' || value.length === 0) {
      throw deny('AV_POLICY_DENIED', 'the new value must be a non-empty string', { rule: 'value_empty' })
    }
    if (mode !== 'keep' && mode !== 'revoke') throw deny('AV_POLICY_DENIED', 'mode must be keep or revoke', { rule: 'rotate_mode' })
    if (!Number.isSafeInteger(retireMs) || retireMs < 0 || retireMs > 7 * DAY_MS) {
      throw deny('AV_POLICY_DENIED', 'the retire window is a whole number of milliseconds, at most 7 days', { rule: 'retire_window' })
    }
    // Undefined clears it: the old expiry described the old token.
    const expires = expiresAt === undefined || expiresAt === null ? null : isoOrUndefined(expiresAt)
    if (expires === undefined) throw deny('AV_POLICY_DENIED', 'expires_at must be an ISO date, or null', { rule: 'expires_at' })
    const current = this.#unseal(cred, f.name)
    if (crypt.constantTimeEqual(current, value)) {
      throw deny('AV_POLICY_DENIED', 'that is the value already stored', { rule: 'rotate_same_value' })
    }

    const now = Date.now()
    const version = (Number.isSafeInteger(f.key_version) ? f.key_version : 1) + 1
    const sealed = crypt.seal(crypt.dek(this.vmk, cred.id), value, `${cred.id}|${f.name}|${version}`)
    const retireUntil = new Date(now + retireMs).toISOString()
    // A zero window keeps nothing: an old value nobody will scrub for is
    // only ciphertext of a secret, lying around.
    const kept = (f.retired || []).filter((r) => expiryMs(r.retire_until) > now)
    const retired = retireMs > 0
      ? [...kept, { ct: f.ct, nonce: f.nonce, key_version: f.key_version ?? 1, retired_at: new Date(now).toISOString(), retire_until: retireUntil }]
      : kept
    const previousFp8 = f.fp8
    Object.assign(f, {
      ct: sealed.ct, nonce: sealed.nonce, key_version: version, retired,
      fp8: crypt.fingerprint8(this.kFingerprint, value), length: value.length,
      rotated_at: new Date(now).toISOString(),
    })
    cred.expires_at = expires
    let revokedGrants = 0
    if (mode === 'revoke') {
      for (const g of Object.values(this.db.grants)) {
        if (g.credential_id === cred.id && g.state === 'active') { this.revokeGrant(g.id, 'credential_rotated'); revokedGrants++ }
      }
    }
    this.#persist()
    const rotated = {
      field: f.name, version, previous_fp8: previousFp8, fp8: f.fp8, mode, revoked_grants: revokedGrants, retire_until: retireUntil,
    }
    this.audit.write('cred.rotated', { credential_slug: cred.slug, ...rotated })
    return { credential: this.publicCredential(cred), rotated }
  }

  // ------------------------------------------------- F14: notify webhook

  /**
   * The owner's approval-notification webhook (F14). Its URL is a bearer
   * credential (a Slack webhook URL is one), so it is sealed at rest under its
   * own key and only its host is ever shown or audited. HTTPS only, or plain
   * HTTP to this machine; never userinfo.
   */
  setNotifyWebhook({ url, detail = 'minimal' } = {}) {
    this.#requireUnlocked()
    const refuse = (why) => deny('AV_POLICY_DENIED', `webhook refused: ${why}`, { rule: 'webhook_url' })
    if (typeof url !== 'string' || !url || url.length > 2048) throw refuse('give an https URL of at most 2048 characters')
    let parsed
    try { parsed = new URL(url) } catch { throw refuse('not a URL') }
    const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname)
    if (!(parsed.protocol === 'https:' || (parsed.protocol === 'http:' && loopback))) throw refuse('it must be https (or http to this machine)')
    if (parsed.username || parsed.password) throw refuse('it must not carry a user name or password')
    if (detail !== 'minimal' && detail !== 'headline') {
      throw deny('AV_POLICY_DENIED', 'detail must be minimal or headline', { rule: 'policy_invalid' })
    }
    const sealed = crypt.seal(crypt.dek(this.vmk, 'notify'), url, NOTIFY_AAD)
    this.db.kv.notify = { sealed, host: parsed.host, detail, configured_at: new Date().toISOString() }
    this.#persist()
    this.audit.write('notify.configured', { host: parsed.host, detail })
    return this.notifyConfig()
  }

  /** The URL itself. Daemon-internal: nothing it returns may reach a response. */
  getNotifyWebhook() {
    this.#requireUnlocked()
    const n = this.db.kv.notify
    if (!n) return null
    return { url: crypt.open(crypt.dek(this.vmk, 'notify'), n.sealed, NOTIFY_AAD), host: n.host, detail: n.detail }
  }

  /** What anyone may see: the host, never the path or query. */
  notifyConfig() {
    const n = this.db.kv.notify
    return n ? { host: n.host, detail: n.detail, configured_at: n.configured_at } : null
  }

  clearNotifyWebhook() {
    this.#requireUnlocked()
    if (!this.db.kv.notify) return false
    delete this.db.kv.notify
    this.#persist()
    this.audit.write('notify.removed', {})
    return true
  }

  // ------------------------------------------------------ F17: templates

  /**
   * Save a named session shape (F17): configuration, not standing approval.
   * Creating a session from one still passes the normal gate. The hash is
   * over the canonical operation form, which accepts the floats a spec may
   * carry (spend_usd) where canon.canonicalize would not, and it is what a
   * human's signature binds, so an edit after they looked is refused.
   */
  saveTemplate(name, spec) {
    this.#requireUnlocked()
    const text = this.#checkTemplate(name, spec)
    const templates = this.db.templates || {}
    const old = Object.hasOwn(templates, name) ? templates[name] : null
    if (!old && Object.keys(templates).length >= MAX_TEMPLATES) {
      throw deny('AV_POLICY_DENIED', `at most ${MAX_TEMPLATES} templates`, { rule: 'template_size' })
    }
    const template = this.#templateRecord(name, text, old)
    this.db.templates = { ...templates, [name]: template }
    this.#persist()
    this.audit.write('template.saved', { name, version: template.version, template_hash: template.hash })
    return structuredClone(template)
  }

  /** A template's name and spec, checked; returns the spec's JSON. Shared with a restore. Writes nothing. */
  #checkTemplate(name, spec) {
    if (typeof name !== 'string' || !TEMPLATE_NAME.test(name)) {
      throw deny('AV_POLICY_DENIED', 'a template name is 1-32 characters of [a-z0-9-], starting with a letter or digit', { rule: 'template_name' })
    }
    if (!spec || typeof spec !== 'object' || Array.isArray(spec)) {
      throw deny('AV_POLICY_DENIED', 'a template spec is a session-create object', { rule: 'session_shape' })
    }
    for (const k of ['template', 'template_hash', 'presence']) {
      if (Object.hasOwn(spec, k)) throw deny('AV_POLICY_DENIED', `a template spec cannot carry ${k}`, { rule: 'session_shape' })
    }
    let text
    try { text = JSON.stringify(spec) } catch { throw deny('AV_POLICY_DENIED', 'a template spec must be plain JSON', { rule: 'session_shape' }) }
    if (Buffer.byteLength(text) > MAX_TEMPLATE_BYTES) {
      throw deny('AV_POLICY_DENIED', `a template spec is at most ${MAX_TEMPLATE_BYTES} bytes of JSON`, { rule: 'template_size' })
    }
    return text
  }

  #templateRecord(name, text, old) {
    // Stored as the JSON it will be read back as, so the hash describes
    // exactly what a later read returns.
    const stored = JSON.parse(text)
    const now = new Date().toISOString()
    return {
      name, version: old ? old.version + 1 : 1, spec: stored,
      hash: createHash('sha256').update(canonicalOperation(stored)).digest('hex'),
      created_at: old?.created_at ?? now, updated_at: now,
    }
  }

  getTemplate(name) {
    const t = this.db.templates
    return t && typeof name === 'string' && Object.hasOwn(t, name) ? structuredClone(t[name]) : null
  }

  listTemplates() {
    return Object.values(this.db.templates || {}).sort((a, b) => a.name.localeCompare(b.name)).map((t) => structuredClone(t))
  }

  /** Remove a template. It grants nothing, so removing it narrows only. */
  deleteTemplate(name) {
    this.#requireUnlocked()
    const t = this.db.templates
    if (!t || typeof name !== 'string' || !Object.hasOwn(t, name)) return false
    const { version } = t[name]
    const { [name]: _gone, ...rest } = t
    this.db.templates = rest
    this.#persist()
    this.audit.write('template.deleted', { name, version })
    return true
  }

  // ------------------------------------------------------- F8: backup

  /**
   * Every credential as a backup carries it (F8): current values, sites,
   * scrub patterns, pins, expiry and quarantine. Quarantined ones too, because
   * a backup that left them out would lose them, and with their quarantine as
   * stored, because a restore must not release them. Only the export reads
   * this, behind a fresh proof of presence.
   */
  backupCredentials() {
    this.#requireUnlocked()
    return Object.values(this.db.credentials).map((c) => ({
      slug: c.slug, kind: c.connector_kind, connector: c.connector ?? null, created_at: c.created_at,
      fields: c.fields.map((f) => ({ name: f.name, value: this.#unseal(c, f.name), sites: f.sites || [] })),
      scrub_patterns: (c.scrub_patterns || []).map(({ id: pid, source, added_at }) => ({ id: pid, source, added_at })),
      pins: c.pins ?? {},
      expires_at: c.expires_at ?? null,
      quarantine: c.quarantine ? structuredClone(c.quarantine) : null,
    }))
  }

  /**
   * Put a backup's credentials and templates back (F8), all or nothing. Every
   * rule addCredential, setCredentialExpiry, addScrubPattern and saveTemplate
   * apply is checked over the whole set first, writing nothing, and then all
   * of it is stored in one write. A restore that stored its first credential
   * and then threw on that credential's scrub pattern was a refusal that had
   * changed the vault; now a refusal anywhere, or a write that fails, leaves
   * the vault as it was.
   *
   * A restore never releases a quarantine. A credential quarantined in the
   * bundle comes back quarantined, with the record as it was stored. One this
   * vault holds quarantined under the bundle's slug (`from`, the slug before a
   * rename) or under a renamed copy of it keeps the restored copy quarantined,
   * whatever the bundle says, so restoring an older bundle under `rename`
   * cannot hand out a released copy. Releasing stays clearQuarantine, a
   * human's explicit act.
   *
   * `credentials` are in bundle form with conflicts already resolved: a slug
   * that is taken is refused. A template whose name is taken is skipped, the
   * way the restore has always treated one. Pins are refused until this vault
   * can store them (F11): dropping them would restore a credential with less
   * protection than the human gave it.
   */
  restoreEntries({ credentials = [], templates = [] } = {}) {
    this.#requireUnlocked()
    const format = (why) => deny('AV_POLICY_DENIED', `not a usable backup: ${why}`, { rule: 'backup_format' })
    if (!Array.isArray(credentials) || !Array.isArray(templates)) throw format('credentials and templates are lists')
    const now = new Date().toISOString()
    const taken = new Set(Object.values(this.db.credentials).map((c) => c.slug))
    // A pattern may carry no value this vault will hold: the ones it has, and every one being restored.
    const secrets = [
      ...this.allSecrets().map((s) => s.secret),
      ...credentials.flatMap((c) => (Array.isArray(c?.fields) ? c.fields.map((f) => f?.value) : [])),
    ]
    let patternTotal = Object.values(this.db.credentials).reduce((n, c) => n + (c.scrub_patterns?.length || 0), 0)
    const staged = []
    for (const c of credentials) {
      if (!c || typeof c !== 'object' || !Array.isArray(c.fields) || !c.fields.length) throw format('a credential entry is malformed')
      if (taken.has(c.slug)) throw deny('AV_NOT_FOUND', `credential ${c.slug} already exists`)
      taken.add(c.slug)
      if (c.fields.some((f) => typeof f?.value !== 'string' || !f.value) || new Set(c.fields.map((f) => f.name)).size !== c.fields.length) {
        throw format(`the fields of ${c.slug} are malformed`)
      }
      const cred = this.#sealCredential({
        slug: c.slug, kind: c.kind, connector: c.connector ?? {},
        fields: Object.fromEntries(c.fields.map((f) => [f.name, f.value])),
        sites: Object.fromEntries(c.fields.map((f) => [f.name, f.sites ?? []])),
      })
      // Pins come back as setPins would store them, or the restore is refused:
      // dropping them would restore a credential with less protection than
      // the human gave it.
      const pins = c.pins ?? {}
      if (!pins || typeof pins !== 'object' || Array.isArray(pins)) throw format(`the pins of ${c.slug} are malformed`)
      for (const [host, list] of Object.entries(pins)) {
        if (Array.isArray(list) && list.length === 0) continue
        const key = this.#pinHost(cred, host)
        cred.pins = { ...pinTableOf(cred.pins, key), [key]: pinList(list) }
      }
      if (Object.keys(cred.pins ?? {}).length > MAX_PIN_HOSTS) {
        throw deny('AV_POLICY_DENIED', `at most ${MAX_PIN_HOSTS} hosts can be pinned`, { rule: 'pin_host' })
      }
      if (c.expires_at != null) {
        const expires = isoOrUndefined(c.expires_at)
        if (expires === undefined) throw deny('AV_POLICY_DENIED', 'expires_at must be an ISO date, or null to clear it', { rule: 'expires_at' })
        cred.expires_at = expires
      }
      const patterns = c.scrub_patterns ?? []
      if (!Array.isArray(patterns)) throw format(`the scrub patterns of ${c.slug} are malformed`)
      if (patterns.length > MAX_SCRUB_PER_CRED) throw scrubRefusal(`at most ${MAX_SCRUB_PER_CRED} patterns per credential`)
      patternTotal += patterns.length
      if (patternTotal > MAX_SCRUB_TOTAL) throw scrubRefusal(`at most ${MAX_SCRUB_TOTAL} patterns in the vault`)
      for (const p of patterns) this.#checkScrubSource(p?.source, secrets)
      if (patterns.length) cred.scrub_patterns = patterns.map((p) => ({ id: id.scrubPattern(), source: p.source, added_at: now }))
      if (c.quarantine != null) cred.quarantine = restoredQuarantine(c.quarantine, format)
      else {
        // The earliest, as setQuarantine keeps the first record.
        const names = [c.from ?? c.slug, c.slug]
        const held = Object.values(this.db.credentials)
          .filter((h) => h.quarantine && names.some((n) => sameCredential(h.slug, n)))
          .map((h) => h.quarantine)
          .sort((a, b) => Date.parse(a.since) - Date.parse(b.since))[0]
        if (held) cred.quarantine = structuredClone(held)
      }
      staged.push(cred)
    }
    const before = this.db.templates
    const nextTemplates = { ...(before || {}) }
    const restoredTemplates = []
    const skippedTemplates = []
    for (const t of templates) {
      const text = this.#checkTemplate(t?.name, t?.spec)
      if (Object.hasOwn(nextTemplates, t.name)) { skippedTemplates.push(t.name); continue }
      if (Object.keys(nextTemplates).length >= MAX_TEMPLATES) {
        throw deny('AV_POLICY_DENIED', `at most ${MAX_TEMPLATES} templates`, { rule: 'template_size' })
      }
      nextTemplates[t.name] = this.#templateRecord(t.name, text, null)
      restoredTemplates.push(t.name)
    }
    // Nothing above can reach a factor. Said, on the state about to be stored.
    const factors = { vmk_wraps: this.db.kv.vmk_wraps, webauthn: this.db.kv.webauthn ?? null }
    assertFactorInvariant(factors, factors)

    // One write. Undone in memory if it fails, so the vault is what it was.
    for (const cred of staged) this.db.credentials[cred.id] = cred
    if (restoredTemplates.length) this.db.templates = nextTemplates
    try {
      this.#persist()
    } catch {
      for (const cred of staged) delete this.db.credentials[cred.id]
      if (before === undefined) delete this.db.templates
      else this.db.templates = before
      throw deny('AV_INTERNAL', 'the restore could not be written, so nothing was restored', { rule: 'backup_persist' })
    }
    for (const cred of staged) {
      this.audit.write('cred.added', { credential_slug: cred.slug, connector: cred.connector_kind, fields: cred.fields.map((f) => f.name) })
      if (cred.expires_at !== undefined) this.audit.write('cred.expiry_set', { credential_slug: cred.slug, expires_at: cred.expires_at })
      for (const p of cred.scrub_patterns ?? []) this.#auditScrubPattern(cred, p)
      for (const [host, list] of Object.entries(cred.pins ?? {})) this.audit.write('cred.pins_set', { credential_slug: cred.slug, host, pins: list.length })
      if (cred.quarantine) {
        const { since, by, rule_id, reason_untrusted } = cred.quarantine
        this.audit.write('cred.quarantined', { credential_slug: cred.slug, by, rule_id, reason_untrusted, since, restored: true })
      }
    }
    for (const name of restoredTemplates) {
      const t = this.db.templates[name]
      this.audit.write('template.saved', { name, version: t.version, template_hash: t.hash })
    }
    return { restored: staged.map((c) => c.slug), templates: { restored: restoredTemplates, skipped: skippedTemplates } }
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
   *
   * `infinite` (R3) is a session with no lifetime at all: it ends by being
   * revoked, shortened or panicked, and never from the network. `elevated`
   * (C3) is what made the daemon ask for a fresh proof, recorded with the
   * creation. Every argument is checked before anything is written, and a
   * value that is not exactly what it should be is refused, never coerced:
   * `infinite: 'false'` is truthy, and `ttlMs: NaN` was a session that
   * `new Date(NaN)` threw on halfway through.
   */
  createSession({ workspaceId, label, ttlMs = null, infinite = false, elevated = [], template = null, templateVersion = null, policy = {}, peerUid = process.getuid?.(), remote = false, clientName = null }) {
    this.#requireUnlocked()
    if (ttlMs !== null && (typeof ttlMs !== 'number' || !Number.isFinite(ttlMs) || ttlMs <= 0)) {
      throw deny('AV_POLICY_DENIED', 'a session lifetime must be a positive number', { rule: 'ttl' })
    }
    if (typeof infinite !== 'boolean') throw deny('AV_POLICY_DENIED', 'infinite must be true or false', { rule: 'ttl' })
    if (infinite && ttlMs !== null) throw deny('AV_POLICY_DENIED', 'an infinite session has no lifetime to set', { rule: 'ttl' })
    if (infinite && remote) {
      throw deny('AV_REMOTE_FORBIDDEN', 'an infinite session can never be reached from the network', { rule: 'infinite_remote' })
    }
    if (!Array.isArray(elevated) || elevated.length > ELEVATIONS.size || !elevated.every((e) => ELEVATIONS.has(e))) {
      throw deny('AV_POLICY_DENIED', 'elevated must list only approval_auto_writes and infinite', { rule: 'elevation_invalid' })
    }
    // F17: which template, at which version, a session came from. Both or neither.
    if (template === null ? templateVersion !== null
      : (typeof template !== 'string' || !TEMPLATE_NAME.test(template) || !Number.isSafeInteger(templateVersion) || templateVersion < 1)) {
      throw deny('AV_POLICY_DENIED', 'a session names its template and version together, or neither', { rule: 'template_name' })
    }
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
      // What it was created with, for the detail view (F19). Metadata only:
      // nothing reads these to decide anything.
      elevated: [...new Set(elevated)], template, template_version: templateVersion,
      last_seen_at: new Date(now).toISOString(),
    }
    this.db.sessions[sid] = session
    this.#persist()
    this.audit.write('session.created', {
      session_id: sid, workspace_id: workspaceId, label, remote,
      infinite, expires_at: session.expires_at, elevated: session.elevated,
      template, template_version: templateVersion,
    })
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
    // Ended is final: nothing moves a session back to active, so a date that
    // was later pushed out does not bring one back.
    if (session.state !== 'active') throw deny('AV_SESSION_EXPIRED', `session ${session.id} has ended`)
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

  /**
   * Whether a session may be used on the listener a request arrived on. Every
   * surface that turns a token into a session asks this, and nothing else:
   * the gateway, discovery, the MCP endpoint and its tools. Only /p/ used to
   * apply C12, inside the pipeline, so the same infinite token was refused
   * there and spent its grants over /mcp and /v1 on the same listener.
   *
   * C12 first: a session that never expires is never usable from a network
   * listener, and that is refused before the session is touched. Then
   * liveness. `listener` is the network listener, or null for the machine
   * itself (the built-in gateway, stdio, the control socket). `peek` answers
   * without side effects, for preflight and for the MCP handshake: nothing is
   * marked expired and no placeholder dies. A C12 refusal is recorded here,
   * as `remote.denied`, unless the caller records its own denials (`record:
   * false`: the pipeline, whose every denial is a record already) or peeks.
   */
  assertSessionUsable(session, listener = null, { peek = false, record = true } = {}) {
    if (session && session.infinite === true && listener?.remote) {
      const e = deny('AV_REMOTE_FORBIDDEN', 'a session without expiry cannot be used from a network listener', {
        rule: 'infinite_remote',
        hint: 'Use it on this machine, or start a session with an expiry for remote use.',
      })
      if (record && !peek) {
        this.audit?.write(e.auditKind, {
          decision: 'deny', reason_code: e.code, rule: e.rule, detail: e.detail, session_id: session.id,
          peer: { kind: listener.kind || 'remote', listener_id: listener.id || null },
        })
      }
      throw e
    }
    if (!peek || !session) return this.assertSessionLive(session)
    if (session.state === 'revoked') throw deny('AV_SESSION_REVOKED', `session ${session.id} was revoked`)
    if (session.state !== 'active' || !(sessionExpiryMs(session) > Date.now())) {
      throw deny('AV_SESSION_EXPIRED', `session ${session.id} has expired`)
    }
    return session
  }

  /**
   * Idle extension. Never widens capability, so it needs no presence. Only a
   * live session is extended: one that is revoked, marked ended, or past its
   * date though nothing has noticed yet stays ended, whoever calls this and
   * in whatever order. The pipeline asserts liveness first; this does not
   * rely on it. Never earlier than it was, never past its ceiling. False
   * when nothing was touched.
   */
  touchSession(session) {
    const now = Date.now()
    if (!session || session.state !== 'active' || !(sessionExpiryMs(session) > now)) return false
    // An infinite session has nothing to extend; only its last-seen moves.
    if (session.infinite !== true) {
      const extended = Math.min(now + session.idle_timeout_ms, sessionCeilingMs(session))
      if (extended > sessionExpiryMs(session)) session.expires_at = new Date(extended).toISOString()
    }
    session.last_seen_at = new Date(now).toISOString()
    return true
  }

  /**
   * Bring a session's end closer (R3, F15): never later than it already was,
   * and an infinite session becomes finite. The ceiling idle activity may
   * extend to comes down with it, and so do its live placeholders, so neither
   * an agent that keeps working nor a placeholder minted earlier outlives it.
   */
  shortenSession(sid, ttlMs) {
    this.#requireUnlocked()
    const s = Object.hasOwn(this.db.sessions, sid) ? this.db.sessions[sid] : null
    if (!s) throw deny('AV_NOT_FOUND', `no session ${sid}`)
    if (s.state === 'revoked') throw deny('AV_SESSION_REVOKED', `session ${s.id} was revoked`)
    if (typeof ttlMs !== 'number' || !Number.isFinite(ttlMs) || ttlMs <= 0) {
      throw deny('AV_POLICY_DENIED', 'a session lifetime must be a positive number', { rule: 'ttl' })
    }
    const now = Date.now()
    const wasInfinite = s.infinite === true && s.expires_at === null
    const ceiling = sessionCeilingMs(s)
    const expiresAt = shortenedIso(sessionExpiryMs(s), now, ttlMs)
    const maxExpiresAt = shortenedIso(ceiling, now, ttlMs)
    s.expires_at = expiresAt
    s.max_expires_at = maxExpiresAt
    s.infinite = false
    s.idle_timeout_ms = (s.remote ? 1 : 2) * 3600_000
    const bound = Date.parse(maxExpiresAt)
    for (const p of Object.values(this.db.placeholders)) {
      if (p.sid === s.id && p.state === 'active' && !(rowExpiryMs(p) <= bound)) p.expires_at = maxExpiresAt
    }
    this.#persist()
    this.audit.write('session.shortened', { session_id: s.id, expires_at: expiresAt, was_infinite: wasInfinite })
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
    // Never infinite: a fork of an infinite parent takes the default lifetime.
    const parentEnds = sessionExpiryMs(parent)
    const parentTtl = parentEnds === Infinity ? null : parentEnds - Date.now()
    const { session, token } = this.createSession({
      workspaceId: parent.workspace_id,
      label: label || `${parent.label} (fork)`,
      ttlMs: parentTtl === null ? (ttlMs ?? null) : Math.min(ttlMs ?? parentTtl, parentTtl),
      policy: parent.policy,
      peerUid: parent.owner_uid,
      remote: parent.remote,
      clientName: parent.client_name,
    })
    session.parent_sid = parentSid
    for (const g of Object.values(this.db.grants)) {
      if (g.session_id !== parentSid || g.state !== 'active') continue
      // The child's grant ends no later than the one it copies (F18). Null is
      // "as long as the session", which the child's own session bounds; a
      // parent grant that has ended, or whose end cannot be read, is not copied.
      const ends = expiryMs(g.expires_at)
      if (!(ends > Date.now())) continue
      const ttlMs = ends === Infinity ? null : ends - Date.now()
      this.createGrant({ sessionId: session.id, credentialId: g.credential_id, fields: g.fields, policy: g.policy, narrow, ttlMs })
    }
    this.#persist()
    this.audit.write('session.forked', { session_id: session.id, parent_session_id: parentSid })
    return { session, token }
  }

  // ----------------------------------------------------------------- grants

  /**
   * `ttlMs` (F18) gives the grant a lifetime of its own, never longer than the
   * session's: a grant of an infinite session still ends. Absent, the grant
   * lives as long as its session, as before.
   */
  createGrant({ sessionId, credentialId, fields, policy, narrow = null, ttlMs = null }) {
    // A change that cannot be written to the audit log must not happen.
    // Locking drops the audit key with the master key, so these mutate
    // nothing while locked rather than persisting unrecorded.
    this.#requireUnlocked()
    const session = Object.hasOwn(this.db.sessions, sessionId) ? this.db.sessions[sessionId] : null
    if (!session) throw deny('AV_NOT_FOUND', `no session ${sessionId}`)
    const cred = Object.hasOwn(this.db.credentials, credentialId) ? this.db.credentials[credentialId] : null
    if (!cred) throw deny('AV_NOT_FOUND', `no credential ${credentialId}`)
    if (ttlMs !== null && (typeof ttlMs !== 'number' || !Number.isFinite(ttlMs) || ttlMs <= 0)) {
      throw deny('AV_POLICY_DENIED', 'a grant lifetime must be a positive number', { rule: 'grant_ttl' })
    }
    // Capability is never added to a session that has ended, or for a
    // credential a human has stopped.
    this.assertSessionLive(session)
    if (cred.quarantine) throw quarantined(cred)
    const expires_at = ttlMs === null ? null : new Date(Math.min(Date.now() + ttlMs, sessionExpiryMs(session))).toISOString()
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

  /**
   * The newest grant for a session and credential, in any state (F18), so a
   * caller that finds no active one can say it expired rather than that it
   * never existed. Ties on the timestamp go to the later id (ids are ULIDs).
   */
  findGrant(sid, credId) {
    let newest = null
    for (const g of Object.values(this.db.grants)) {
      if (g.session_id !== sid || g.credential_id !== credId) continue
      if (!newest || String(g.created_at).localeCompare(String(newest.created_at)) > 0 ||
        (g.created_at === newest.created_at && String(g.id) > String(newest.id))) newest = g
    }
    return newest
  }

  /**
   * The one place a grant's lifetime is decided (F18). Every path that uses a
   * grant — issuing, consuming, the gateway's route — asks this, so no two
   * readers can disagree about whether it is over. Noticing the end is a
   * change (the grant and its placeholders die), and a change that cannot be
   * audited must not happen: a locked vault refuses without recording.
   */
  assertGrantLive(grant) {
    if (!grant || grant.state !== 'active') throw deny('AV_NO_GRANT', `no active grant ${grant?.id ?? ''}`.trim())
    if (!(expiryMs(grant.expires_at) > Date.now())) {
      const expired = deny('AV_GRANT_EXPIRED', `grant ${grant.id} expired at ${grant.expires_at}`, {
        next: { mcp: { tool: 'vault_request_session' } },
      })
      if (this.locked) throw expired
      grant.state = 'expired'
      for (const p of Object.values(this.db.placeholders)) {
        if (p.grant_id === grant.id && p.state === 'active') { p.state = 'dead'; p.dead_reason = 'expired' }
      }
      this.#persist()
      this.audit.write('grant.expired', { grant_id: grant.id, session_id: grant.session_id })
      throw expired
    }
    return grant
  }

  grantsForSession(sid) {
    return Object.values(this.db.grants).filter((g) => g.session_id === sid && g.state === 'active')
  }

  /**
   * Charge a grant for a request that spends no placeholder use (F6: each
   * redirect hop). False, and nothing charged, when it would exceed the
   * budget — or when the budget, the count or the grant cannot be read, since
   * `used + NaN > limit` is false forever and that is no budget at all.
   * Ledger churn like a placeholder use, so the write skips the fsync.
   */
  chargeGrant(grantId, n = 1) {
    if (this.locked) return false
    const grant = Object.hasOwn(this.db.grants, grantId) ? this.db.grants[grantId] : null
    if (!grant || grant.state !== 'active' || !(expiryMs(grant.expires_at) > Date.now())) return false
    if (!Number.isSafeInteger(n) || n < 1) return false
    const used = grant.budget_used
    if (!Number.isSafeInteger(used) || used < 0) return false
    const limit = budgetLimit(grant.policy)
    if (limit === null || used + n > limit) return false
    grant.budget_used = used + n
    grant.counters = grant.counters || { requests: 0, denials: 0 }
    grant.counters.requests = (Number.isSafeInteger(grant.counters.requests) ? grant.counters.requests : 0) + n
    this.#persist({ durable: false })
    return true
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

  /**
   * Bring a grant's end closer (F15): `min(current, now + ttlMs)`, never later.
   * Its live placeholders come down with it, so none outlives it.
   */
  shortenGrant(grantId, ttlMs) {
    this.#requireUnlocked()
    const g = Object.hasOwn(this.db.grants, grantId) ? this.db.grants[grantId] : null
    if (!g) throw deny('AV_NOT_FOUND', `no grant ${grantId}`)
    if (g.state !== 'active') throw deny('AV_NO_GRANT', `no active grant ${grantId}`)
    if (typeof ttlMs !== 'number' || !Number.isFinite(ttlMs) || ttlMs <= 0) {
      throw deny('AV_POLICY_DENIED', 'a grant lifetime must be a positive number', { rule: 'grant_ttl' })
    }
    const expiresAt = shortenedIso(expiryMs(g.expires_at), Date.now(), ttlMs)
    const bound = Date.parse(expiresAt)
    g.expires_at = expiresAt
    for (const p of Object.values(this.db.placeholders)) {
      if (p.grant_id === g.id && p.state === 'active' && !(rowExpiryMs(p) <= bound)) p.expires_at = expiresAt
    }
    this.#persist()
    this.audit.write('grant.shortened', { grant_id: g.id, expires_at: expiresAt })
    return g
  }

  /** Narrow an existing grant. Reducing capability never needs presence. */
  narrowGrant(grantId, narrow) {
    // A change that cannot be written to the audit log must not happen.
    // Locking drops the audit key with the master key, so these mutate
    // nothing while locked rather than persisting unrecorded.
    this.#requireUnlocked()
    const g = this.db.grants[grantId]
    if (!g) throw deny('AV_NOT_FOUND', `no grant ${grantId}`)
    if (!narrow || typeof narrow !== 'object' || Array.isArray(narrow)) {
      throw deny('AV_POLICY_DENIED', 'a narrowing must be a policy layer', { rule: 'policy_invalid' })
    }
    // `redirects` is the one field whose absence means "off" (0.6). A grant
    // that never stated it follows none, and intersecting it with a narrow
    // that states 5 would follow five. So a narrow may only say 0.
    if (Object.hasOwn(narrow, 'redirects') && narrow.redirects?.max !== 0) {
      throw deny('AV_POLICY_DENIED', 'a narrowing can only turn redirect following off', { rule: 'narrow_widens' })
    }
    // The same intersection every request is checked against, so this can
    // only ever remove capability. It was an object spread, which replaced
    // whatever `narrow` named: a "narrowing" to DELETE on /admin/** with
    // approval: 'auto' widened every one of them.
    g.policy = policyMod.intersect([g.policy, narrow])
    this.#persist()
    // The names, not the values: a narrow can carry floats and long lists.
    this.audit.write('grant.narrowed', { grant_id: grantId, session_id: g.session_id, fields: Object.keys(narrow) })
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
    const grant = Object.hasOwn(this.db.grants, grantId) ? this.db.grants[grantId] : null
    if (!grant || grant.state !== 'active') throw deny('AV_NO_GRANT', `no active grant ${grantId}`)
    this.assertGrantLive(grant)
    const session = this.assertSessionLive(this.db.sessions[grant.session_id])
    const cred = this.db.credentials[grant.credential_id]
    const fieldName = field || grant.fields[0]
    if (!grant.fields.includes(fieldName)) throw deny('AV_NO_GRANT', `grant does not cover field ${fieldName}`)
    if (cred.quarantine) throw quarantined(cred)

    // `?? 1000` does not catch NaN, only null and undefined, so a malformed
    // budget propagated straight into the placeholder's use ceiling — and
    // `Math.min(asked, NaN)` is NaN, which no `uses >= max_uses` ever stops.
    // A budget of 0 is no uses, not a thousand: it issues nothing. One that
    // cannot be read is refused when it is used, here and at the gateway.
    const limit = budgetLimit(grant.policy)
    if (limit === 0) throw budgetSpent(limit)
    const useLimit = limit === null || limit === Infinity ? 1000 : limit
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
    const ceiling = Number.isFinite(phPolicy.max_uses) ? phPolicy.max_uses : useLimit
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
    // (#authenticate asserts it for token and carrier alike). An infinite
    // session sets no bound, and a grant with a lifetime of its own (F18) does.
    const expires = Math.min(Date.now() + ttl, sessionCeilingMs(session), expiryMs(grant.expires_at))
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
    // The session at the moment of use. A placeholder is bounded by how long
    // its session COULD live (idle extension included), so a session that
    // went idle and expired early still has placeholders whose own date has
    // not passed: they must die with it here, whoever called.
    this.assertSessionLive(this.db.sessions[row.sid])
    // The grant's own lifetime (F18), asked of the one function that decides
    // it, so a placeholder minted before the grant ended dies with it.
    const grant = this.assertGrantLive(this.db.grants[row.grant_id])
    // A quarantine stops a placeholder issued before it, too (F16). Paused,
    // not killed: the row works again when a human releases the credential.
    const cred = this.db.credentials[row.credential_id]
    if (!cred) throw deny('AV_NO_GRANT', `no credential ${row.credential_id}`)
    if (cred.quarantine) throw quarantined(cred)
    if (!(rowExpiryMs(row) > Date.now())) {
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
    // The grant as it is now, not as it was at issue: a narrowed placeholder
    // ceiling, and the budget other placeholders and redirect hops spent.
    const phMax = grant.policy?.placeholder_policy?.max_uses
    if (Number.isFinite(phMax) && row.uses >= phMax) {
      row.state = 'dead'; row.dead_reason = 'exhausted'; this.#persist({ durable: false })
      throw deny('AV_PH_EXHAUSTED', `placeholder used ${row.uses}/${phMax} times`, {
        next: { cli: ['agent-vault ph next <cred>'], mcp: { tool: 'vault_get_placeholder' } },
      })
    }
    const limit = budgetLimit(grant.policy)
    if (limit === null || !Number.isSafeInteger(grant.budget_used) || grant.budget_used + 1 > limit) throw budgetSpent(limit)
    row.uses += 1
    row.last_used_at = new Date().toISOString()
    if (row.uses >= row.max_uses) { row.state = 'dead'; row.dead_reason = 'exhausted' }
    grant.budget_used += 1
    grant.counters = grant.counters || { requests: 0, denials: 0 }
    grant.counters.requests = (Number.isSafeInteger(grant.counters.requests) ? grant.counters.requests : 0) + 1
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
      .filter(([, p]) => p.state !== 'active' || !(rowExpiryMs(p) > now))
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
      credentials_expiring: Object.values(this.db.credentials).filter((c) => expiryWarning(c) !== null).length,
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
