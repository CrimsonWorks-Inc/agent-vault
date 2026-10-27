// Store slice A: infinite sessions and the expiry helpers (R3), grant
// lifetimes (F18), redirect-hop charging (F6), credential expiry and health
// (F10), settings and quarantine (F16), shortening (F15) and the elevation a
// session was created with (C3).
//
// Each protection has a test that it fires and a test that it does not fire on
// ordinary input. A refusal is also checked for what it did NOT do: nothing in
// memory, nothing on disk, nothing in the audit log.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Vault, expiryMs, sessionExpiryMs } from '../../src/store/vault.js'

const SECRET = 'ghp_SLICEATEST00112233445566778899aabb'
const HOUR = 3_600_000
const DAY = 24 * HOUR
const POLICY = { hosts: ['api.example.com'], methods: ['GET'], paths: ['/**'], budget: { unit: 'requests', limit: 100 }, approval: 'on-write' }

function fresh() {
  const dir = mkdtempSync(join(tmpdir(), 'av-store-a-'))
  const vault = Vault.create(dir, { factor: 'none' })
  const cred = vault.addCredential({
    slug: 'demo', kind: 'http', connector: { host: 'api.example.com', scheme: 'https' },
    fields: { token: SECRET }, sites: { token: ['header:authorization:Bearer'] },
  })
  const other = vault.addCredential({
    slug: 'other', kind: 'http', connector: { host: 'api.example.com', scheme: 'https' },
    fields: { token: 'tok_OTHER00112233445566778899' }, sites: { token: ['header:authorization:Bearer'] },
  })
  return { dir, vault, cred, other, done: () => rmSync(dir, { recursive: true, force: true }) }
}

/** Run `fn` with the vault's clock at `ms`. Every expiry check reads Date.now. */
function at(ms, fn) {
  const real = Date.now
  Date.now = () => ms
  try { return fn() } finally { Date.now = real }
}

function code(fn) {
  try { fn() } catch (e) { return { code: e.code, rule: e.rule } }
  return { code: 'none' }
}

const records = (v, kind) => v.vault.audit.read({ limit: 100000, kind }).filter((r) => r.kind === kind)
const onDisk = (v) => JSON.parse(readFileSync(join(v.dir, 'vault.json'), 'utf8'))

/** Asserts `fn` is refused with `expected`, and changed nothing anywhere. */
function refusedCleanly(v, fn, expected) {
  const before = JSON.stringify(v.vault.db)
  const disk = JSON.stringify(onDisk(v))
  const seq = v.vault.audit.seq
  assert.deepEqual(code(fn), expected)
  assert.equal(JSON.stringify(v.vault.db), before, 'a refusal changed the vault in memory')
  assert.equal(JSON.stringify(onDisk(v)), disk, 'a refusal changed the vault on disk')
  assert.equal(v.vault.audit.seq, seq, 'a refusal wrote to the audit log')
}

function grantFor(v, session, cred = v.cred, extra = {}) {
  return v.vault.createGrant({ sessionId: session.id, credentialId: cred.id, fields: ['token'], policy: POLICY, ...extra })
}

// ------------------------------------------------------------ R3: infinite

test('an infinite session never expires, and says so in its record and its audit', () => {
  const v = fresh()
  try {
    const { session } = v.vault.createSession({ label: 'forever', infinite: true, elevated: ['infinite'] })
    assert.equal(session.infinite, true)
    assert.equal(session.expires_at, null)
    assert.equal(session.max_expires_at, null)
    assert.equal(session.idle_timeout_ms, null)
    // A century from now, it is still live.
    at(Date.now() + 100 * 365 * DAY, () => v.vault.assertSessionLive(session))
    assert.equal(v.vault.stats().sessions_active, 1)

    const [rec] = records(v, 'session.created')
    assert.equal(rec.infinite, true)
    assert.equal(rec.expires_at, null)
    assert.deepEqual(rec.elevated, ['infinite'])

    // Its placeholders are bounded by nothing but their own ttl.
    const g = grantFor(v, session)
    const { row } = v.vault.issuePlaceholder({ grantId: g.id })
    assert.equal(row.expires_at, null)
    at(Date.now() + 10 * 365 * DAY, () => v.vault.consumePlaceholder(row.id))

    // Idle activity moves only last_seen_at.
    v.vault.touchSession(session)
    assert.equal(session.expires_at, null)
    assert.equal(session.max_expires_at, null)
  } finally { v.done() }
})

test('an infinite session is revocable, and its placeholders die with it', () => {
  const v = fresh()
  try {
    const { session } = v.vault.createSession({ infinite: true })
    const g = grantFor(v, session)
    const { row } = v.vault.issuePlaceholder({ grantId: g.id })
    v.vault.revokeSession(session.id)
    assert.deepEqual(code(() => v.vault.assertSessionLive(session)), { code: 'AV_SESSION_REVOKED', rule: undefined })
    assert.equal(row.state, 'dead')
    assert.equal(row.dead_reason, 'session_ended')
    assert.equal(code(() => v.vault.consumePlaceholder(row.id)).code, 'AV_PH_STALE')
    assert.equal(v.vault.stats().sessions_active, 0)
  } finally { v.done() }
})

test('a finite session is unchanged: it expires, and idle activity extends it only up to its ceiling', () => {
  const v = fresh()
  try {
    const { session } = v.vault.createSession({ label: 'default' })
    assert.equal(session.infinite, false)
    assert.equal(typeof session.expires_at, 'string')
    const created = Date.parse(session.created_at)
    // Seven hours in, a request moves the end out by the idle timeout.
    at(created + 7 * HOUR, () => v.vault.touchSession(session))
    assert.equal(Date.parse(session.expires_at), created + 9 * HOUR)
    // But never past the 24-hour ceiling, however long it is kept busy. (A
    // single touch at 23.5 hours used to do this, on a session that had been
    // idle-expired since hour 9: finding 2 of the round-1 review.)
    for (let t = 8.5; t <= 23.5; t += 1.5) at(created + t * HOUR, () => v.vault.touchSession(session))
    assert.equal(Date.parse(session.expires_at), Date.parse(session.max_expires_at))
    assert.equal(at(created + 25 * HOUR, () => code(() => v.vault.assertSessionLive(session))).code, 'AV_SESSION_EXPIRED')

    // An asked-for lifetime is its own ceiling, as before.
    const short = v.vault.createSession({ ttlMs: HOUR }).session
    assert.equal(at(Date.now() + 2 * HOUR, () => code(() => v.vault.assertSessionLive(short))).code, 'AV_SESSION_EXPIRED')
    assert.deepEqual(records(v, 'session.created').map((r) => r.infinite), [false, false])
  } finally { v.done() }
})

test('a lifetime that is not a positive number, or infinite combined with one, is refused and writes nothing', () => {
  const v = fresh()
  try {
    for (const ttlMs of [NaN, 0, -1, '5', Infinity, -Infinity, {}]) {
      refusedCleanly(v, () => v.vault.createSession({ ttlMs }), { code: 'AV_POLICY_DENIED', rule: 'ttl' })
    }
    for (const infinite of ['true', 1, 'false', null]) {
      refusedCleanly(v, () => v.vault.createSession({ infinite }), { code: 'AV_POLICY_DENIED', rule: 'ttl' })
    }
    refusedCleanly(v, () => v.vault.createSession({ infinite: true, ttlMs: HOUR }), { code: 'AV_POLICY_DENIED', rule: 'ttl' })
    refusedCleanly(v, () => v.vault.createSession({ infinite: true, remote: true }), { code: 'AV_REMOTE_FORBIDDEN', rule: 'infinite_remote' })
    // And the ordinary combinations still work.
    assert.ok(v.vault.createSession({ remote: true }).session.expires_at)
    assert.ok(v.vault.createSession({ ttlMs: HOUR, infinite: false }).session.expires_at)
  } finally { v.done() }
})

test('a fork of an infinite session is finite', () => {
  const v = fresh()
  try {
    const { session } = v.vault.createSession({ infinite: true })
    const fork = v.vault.forkSession(session.id).session
    assert.equal(fork.infinite, false)
    assert.ok(sessionExpiryMs(fork) < Date.now() + 25 * HOUR)
  } finally { v.done() }
})

// ------------------------------------------------------- the expiry helpers

test('expiryMs: absent is no limit, a date is that date, and anything else has already passed', () => {
  assert.equal(expiryMs(null), Infinity)
  assert.equal(expiryMs(undefined), Infinity)
  assert.equal(expiryMs('2030-01-01T00:00:00.000Z'), Date.parse('2030-01-01T00:00:00.000Z'))
  for (const bad of ['garbage', '', 'NaN', 123, true, {}, []]) assert.equal(expiryMs(bad), -Infinity, JSON.stringify(bad))
})

test('sessionExpiryMs: only exactly infinite with exactly null lives forever', () => {
  const iso = new Date(Date.now() + HOUR).toISOString()
  assert.equal(sessionExpiryMs({ infinite: true, expires_at: null }), Infinity)
  assert.equal(sessionExpiryMs({ infinite: false, expires_at: iso }), Date.parse(iso))
  assert.equal(sessionExpiryMs({ expires_at: iso }), Date.parse(iso)) // a legacy finite row
  assert.equal(sessionExpiryMs({ infinite: true, expires_at: iso }), Date.parse(iso))
  for (const s of [
    { expires_at: null }, // null, not infinite
    {}, // a legacy row with no expires_at at all
    { infinite: true }, // the flag with the date dropped
    { infinite: 'yes', expires_at: null }, // truthy is not true
    { infinite: 1, expires_at: null },
    { infinite: false, expires_at: 'garbage' },
    { infinite: true, expires_at: 'garbage' },
  ]) assert.equal(sessionExpiryMs(s), -Infinity, JSON.stringify(s))
})

test('a session record with an unreadable or missing expiry is expired, not live forever', () => {
  const v = fresh()
  try {
    for (const patch of [{ expires_at: 'garbage' }, { expires_at: null }, { expires_at: undefined }, { infinite: 'yes', expires_at: null }]) {
      const { session } = v.vault.createSession({})
      const g = grantFor(v, session)
      const { row } = v.vault.issuePlaceholder({ grantId: g.id })
      Object.assign(session, patch)
      if (patch.expires_at === undefined) delete session.expires_at
      assert.equal(code(() => v.vault.assertSessionLive(session)).code, 'AV_SESSION_EXPIRED', JSON.stringify(patch))
      assert.equal(row.state, 'dead')
    }
    assert.equal(v.vault.stats().sessions_active, 0)
    // An ordinary session beside them is live and counted.
    v.vault.assertSessionLive(v.vault.createSession({}).session)
    assert.equal(v.vault.stats().sessions_active, 1)
  } finally { v.done() }
})

test('a placeholder row: exactly null never expires, an unreadable date always has', () => {
  const v = fresh()
  try {
    const { session } = v.vault.createSession({})
    const g = grantFor(v, session)
    const ok = v.vault.issuePlaceholder({ grantId: g.id }).row
    v.vault.consumePlaceholder(ok.id) // an ordinary row is fine
    const never = v.vault.issuePlaceholder({ grantId: g.id }).row
    never.expires_at = null
    v.vault.consumePlaceholder(never.id)
    for (const bad of ['garbage', undefined, 0]) {
      const row = v.vault.issuePlaceholder({ grantId: g.id }).row
      row.expires_at = bad
      assert.equal(code(() => v.vault.consumePlaceholder(row.id)).code, 'AV_PH_STALE', String(bad))
    }
  } finally { v.done() }
})

// ------------------------------------------------------- F18: grant lifetime

test('a grant with a lifetime ends on its own, kills its placeholders, and leaves the session\'s other grant working', () => {
  const v = fresh()
  try {
    const { session } = v.vault.createSession({})
    const short = grantFor(v, session, v.cred, { ttlMs: 60_000 })
    const long = grantFor(v, session, v.other)
    assert.ok(Math.abs(Date.parse(short.expires_at) - (Date.now() + 60_000)) < 1000)
    assert.equal(long.expires_at, null)
    assert.equal(records(v, 'grant.created')[0].expires_at, short.expires_at)

    // Minted before the end, bounded by it, and used after it.
    const { row } = v.vault.issuePlaceholder({ grantId: short.id })
    assert.equal(row.expires_at, short.expires_at)
    const longRow = v.vault.issuePlaceholder({ grantId: long.id }).row
    const later = Date.now() + 2 * 60_000
    assert.equal(at(later, () => code(() => v.vault.consumePlaceholder(row.id))).code, 'AV_GRANT_EXPIRED')
    assert.equal(short.state, 'expired')
    assert.equal(row.state, 'dead')
    assert.equal(row.dead_reason, 'expired')
    assert.deepEqual(records(v, 'grant.expired').map((r) => r.grant_id), [short.id])
    assert.equal(onDisk(v).grants[short.id].state, 'expired')

    // Afterwards it is simply not an active grant, and the other one works.
    assert.equal(at(later, () => code(() => v.vault.assertGrantLive(short))).code, 'AV_NO_GRANT')
    assert.equal(at(later, () => code(() => v.vault.issuePlaceholder({ grantId: short.id }))).code, 'AV_NO_GRANT')
    at(later, () => v.vault.consumePlaceholder(longRow.id))
    at(later, () => v.vault.assertGrantLive(long))
    assert.deepEqual(v.vault.grantsForSession(session.id).map((g) => g.id), [long.id])
    assert.equal(v.vault.findGrant(session.id, v.cred.id).state, 'expired')
  } finally { v.done() }
})

test('an expired grant refuses issuance with its own code', () => {
  const v = fresh()
  try {
    const { session } = v.vault.createSession({})
    const g = grantFor(v, session, v.cred, { ttlMs: 60_000 })
    assert.equal(at(Date.now() + 120_000, () => code(() => v.vault.issuePlaceholder({ grantId: g.id }))).code, 'AV_GRANT_EXPIRED')
  } finally { v.done() }
})

test('idle activity on the session does not revive a grant', () => {
  const v = fresh()
  try {
    const { session } = v.vault.createSession({})
    const g = grantFor(v, session, v.cred, { ttlMs: 60_000 })
    const end = g.expires_at
    at(Date.now() + 30_000, () => v.vault.touchSession(session))
    assert.equal(g.expires_at, end)
    assert.equal(at(Date.now() + 90_000, () => code(() => v.vault.assertGrantLive(g))).code, 'AV_GRANT_EXPIRED')
  } finally { v.done() }
})

test('a grant lifetime longer than the session is clamped to it; a grant of an infinite session still ends', () => {
  const v = fresh()
  try {
    const { session } = v.vault.createSession({ ttlMs: HOUR })
    const g = grantFor(v, session, v.cred, { ttlMs: 10 * HOUR })
    assert.equal(g.expires_at, session.expires_at)
    const inf = v.vault.createSession({ infinite: true }).session
    const g2 = grantFor(v, inf, v.cred, { ttlMs: HOUR })
    assert.ok(Date.parse(g2.expires_at) <= Date.now() + HOUR)
  } finally { v.done() }
})

test('a grant lifetime that is not a positive number is refused and writes nothing', () => {
  const v = fresh()
  try {
    const { session } = v.vault.createSession({})
    for (const ttlMs of [0, -5, 'x', NaN, Infinity, '60000']) {
      refusedCleanly(v, () => grantFor(v, session, v.cred, { ttlMs }), { code: 'AV_POLICY_DENIED', rule: 'grant_ttl' })
    }
  } finally { v.done() }
})

test('no grant is added to a session that has ended', () => {
  const v = fresh()
  try {
    const { session } = v.vault.createSession({})
    v.vault.revokeSession(session.id)
    refusedCleanly(v, () => grantFor(v, session), { code: 'AV_SESSION_REVOKED', rule: undefined })
  } finally { v.done() }
})

test('a locked vault refuses an expired grant without recording what it cannot audit', () => {
  const v = fresh()
  try {
    const { session } = v.vault.createSession({})
    const g = grantFor(v, session, v.cred, { ttlMs: 60_000 })
    v.vault.lock()
    assert.equal(at(Date.now() + 120_000, () => code(() => v.vault.assertGrantLive(g))).code, 'AV_GRANT_EXPIRED')
    assert.equal(g.state, 'active')
  } finally { v.done() }
})

test('findGrant returns the newest grant for the pair in any state, and null for none', () => {
  const v = fresh()
  try {
    const { session } = v.vault.createSession({})
    const first = grantFor(v, session)
    v.vault.revokeGrant(first.id)
    const second = grantFor(v, session)
    second.created_at = first.created_at // a tie goes to the later id
    assert.equal(v.vault.findGrant(session.id, v.cred.id).id, second.id)
    assert.equal(v.vault.findGrant(session.id, v.other.id), null)
    assert.equal(v.vault.findGrant('nope', v.cred.id), null)
  } finally { v.done() }
})

// ------------------------------------------------------- F6: chargeGrant

test('chargeGrant charges up to the budget and refuses past it', () => {
  const v = fresh()
  try {
    const { session } = v.vault.createSession({})
    const g = grantFor(v, session, v.cred, { policy: { ...POLICY, budget: { unit: 'requests', limit: 3 } } })
    assert.deepEqual([1, 2, 3, 4].map(() => v.vault.chargeGrant(g.id)), [true, true, true, false])
    assert.equal(g.budget_used, 3)
    assert.equal(g.counters.requests, 3)
    assert.equal(onDisk(v).grants[g.id].budget_used, 3)
    // A charge of more than one is all or nothing.
    const g2 = grantFor(v, session, v.cred, { policy: { ...POLICY, budget: { unit: 'requests', limit: 3 } } })
    assert.equal(v.vault.chargeGrant(g2.id, 2), true)
    assert.equal(v.vault.chargeGrant(g2.id, 2), false)
    assert.equal(g2.budget_used, 2)
    // No budget stated means no limit.
    const open = grantFor(v, session, v.cred, { policy: { ...POLICY, budget: undefined } })
    assert.equal(v.vault.chargeGrant(open.id, 500), true)
  } finally { v.done() }
})

test('chargeGrant reads a decimal-string budget as its integer (C4)', () => {
  const v = fresh()
  try {
    const { session } = v.vault.createSession({})
    const g = grantFor(v, session, v.cred, { policy: { ...POLICY, budget: { unit: 'requests', limit: '2' } } })
    assert.deepEqual([1, 2, 3].map(() => v.vault.chargeGrant(g.id)), [true, true, false])
  } finally { v.done() }
})

test('chargeGrant charges nothing when the budget, the count or the grant cannot be read', () => {
  const v = fresh()
  try {
    const { session } = v.vault.createSession({})
    const charge = (budget, n = 1, patch = {}) => {
      const g = grantFor(v, session, v.cred, { policy: { ...POLICY, budget } })
      Object.assign(g, patch)
      const before = JSON.stringify(g)
      const ok = v.vault.chargeGrant(g.id, n)
      if (!ok) assert.equal(JSON.stringify(g), before, 'a refused charge changed the grant')
      return ok
    }
    for (const limit of ['abc', '', '5.5', '-1', '1e3', -1, 5.5, NaN, null, {}]) {
      assert.equal(charge({ unit: 'requests', limit }), false, `limit ${String(limit)}`)
    }
    // A layer that names no limit constrains nothing at this layer, as the
    // gateway reads it (C4, one reader): the session's layer, checked by the
    // gateway before the hop, is what bounds it.
    assert.equal(charge({ unit: 'requests', limit: undefined }), true)
    assert.equal(charge({ unit: 'requests' }), true)
    assert.equal(charge({ unit: 'tokens', limit: 10 }), false)
    assert.equal(charge({ unit: 'requests', limit: 10, invalid: true }), false)
    assert.equal(charge('lots'), false)
    for (const n of [0, -1, 1.5, NaN, '1', Infinity]) assert.equal(charge({ unit: 'requests', limit: 10 }, n), false, `n ${String(n)}`)
    assert.equal(charge({ unit: 'requests', limit: 10 }, 1, { budget_used: NaN }), false)
    assert.equal(charge({ unit: 'requests', limit: 10 }, 1, { state: 'revoked' }), false)
    assert.equal(charge({ unit: 'requests', limit: 10 }, 1, { expires_at: new Date(Date.now() - 1000).toISOString() }), false)
    assert.equal(v.vault.chargeGrant('gr_nope'), false)
    assert.equal(v.vault.chargeGrant('__proto__'), false)
    // And the ordinary case beside them.
    assert.equal(charge({ unit: 'requests', limit: 10 }), true)
    const g = grantFor(v, session)
    v.vault.lock()
    assert.equal(v.vault.chargeGrant(g.id), false)
    assert.equal(g.budget_used, 0)
  } finally { v.done() }
})

// ------------------------------------------------- F10: expiry and health

test('credential expiry is stored as one ISO date, audited, and flagged when near', () => {
  const v = fresh()
  try {
    const soon = new Date(Date.now() + 3 * DAY).toISOString()
    const pub = v.vault.setCredentialExpiry('demo', soon)
    assert.equal(pub.expires_at, soon)
    assert.equal(pub.expiry_warning, 'soon')
    assert.deepEqual(records(v, 'cred.expiry_set').map((r) => [r.credential_slug, r.expires_at]), [['demo', soon]])
    assert.equal(v.vault.stats().credentials_expiring, 1)

    assert.equal(v.vault.setCredentialExpiry('demo', '2099-01-31').expires_at, '2099-01-31T00:00:00.000Z')
    assert.equal(v.vault.listCredentials().find((c) => c.slug === 'demo').expiry_warning, null)
    assert.equal(v.vault.setCredentialExpiry('demo', new Date(Date.now() - DAY).toISOString()).expiry_warning, 'expired')
    assert.equal(v.vault.stats().credentials_expiring, 1)
    assert.equal(v.vault.setCredentialExpiry('demo', null).expires_at, null)
    assert.equal(v.vault.stats().credentials_expiring, 0)
    assert.equal(onDisk(v).credentials[v.cred.id].expires_at, null)
  } finally { v.done() }
})

test('a credential expiry that is not a date is refused and writes nothing', () => {
  const v = fresh()
  try {
    for (const bad of ['garbage', '', 123, undefined, {}, true]) {
      refusedCleanly(v, () => v.vault.setCredentialExpiry('demo', bad), { code: 'AV_POLICY_DENIED', rule: 'expires_at' })
    }
    refusedCleanly(v, () => v.vault.setCredentialExpiry('nope', null), { code: 'AV_NOT_FOUND', rule: undefined })
    v.vault.lock()
    assert.equal(code(() => v.vault.setCredentialExpiry('demo', null)).code, 'AV_LOCKED')
  } finally { v.done() }
})

test('a thousand identical health observations write one audit record', () => {
  const v = fresh()
  try {
    const observed = new Date(Date.now() + 2 * DAY).toISOString()
    for (let i = 0; i < 1000; i++) {
      v.vault.recordHealth(v.cred.id, { observed_expires_at: observed, source: 'response', checked_at: new Date().toISOString() })
    }
    const recs = records(v, 'cred.health_recorded')
    assert.equal(recs.length, 1)
    assert.equal(recs[0].observed_expires_at, observed)
    assert.equal(recs[0].source, 'response')
    assert.equal(v.vault.listCredentials().find((c) => c.slug === 'demo').expiry_warning, 'soon')
    assert.equal(v.vault.stats().credentials_expiring, 1)

    // A change of status is a change, and is recorded.
    v.vault.recordHealth('demo', { status: 'unauthorized', http_status: 401, source: 'response' })
    v.vault.recordHealth('demo', { status: 'unauthorized', http_status: 401, source: 'response' })
    assert.deepEqual(records(v, 'cred.health_recorded').map((r) => [r.status, r.http_status]), [['unknown', null], ['unauthorized', 401]])
  } finally { v.done() }
})

test('the sooner of the human\'s expiry and the observed one wins', () => {
  const v = fresh()
  try {
    v.vault.setCredentialExpiry('demo', new Date(Date.now() + 2 * DAY).toISOString())
    v.vault.recordHealth('demo', { observed_expires_at: new Date(Date.now() + 90 * DAY).toISOString() })
    assert.equal(v.vault.listCredentials().find((c) => c.slug === 'demo').expiry_warning, 'soon')
    v.vault.setCredentialExpiry('demo', new Date(Date.now() + 90 * DAY).toISOString())
    v.vault.recordHealth('demo', { observed_expires_at: new Date(Date.now() - DAY).toISOString() })
    assert.equal(v.vault.listCredentials().find((c) => c.slug === 'demo').expiry_warning, 'expired')
  } finally { v.done() }
})

test('a health patch keeps only well-formed fields, and a locked vault records nothing', () => {
  const v = fresh()
  try {
    const health = v.vault.recordHealth('demo', {
      status: 'pwned', http_status: 401.5, observed_expires_at: 'garbage', source: 'agent',
      checked_at: 'yesterday', scopes: [1, 2], value: SECRET, ratelimit_remaining: 5,
    })
    assert.deepEqual(Object.keys(health).sort(), ['checked_at', 'http_status', 'observed_expires_at', 'scopes', 'source', 'status'])
    assert.equal(health.status, 'unknown')
    assert.equal(health.http_status, null)
    assert.equal(health.observed_expires_at, null)
    assert.ok(!JSON.stringify(v.vault.db).includes(SECRET), 'a stray field reached the stored record')
    assert.equal(records(v, 'cred.health_recorded').length, 1, 'the audit record must still be writable')

    // Ordinary, well-formed input is kept as given.
    const ok = v.vault.recordHealth('demo', { status: 'ok', http_status: 200, source: 'probe', scopes: ['repo'] })
    assert.deepEqual([ok.status, ok.http_status, ok.source, ok.scopes], ['ok', 200, 'probe', ['repo']])

    assert.equal(v.vault.recordHealth('nope', { status: 'ok' }), null)
    assert.equal(v.vault.recordHealth('__proto__', { status: 'ok' }), null)
    assert.equal(({}).health, undefined)
    v.vault.lock()
    const before = JSON.stringify(v.vault.db)
    assert.equal(v.vault.recordHealth('demo', { status: 'forbidden' }), null)
    assert.equal(JSON.stringify(v.vault.db), before)
  } finally { v.done() }
})

// ------------------------------------------------ F16: settings, quarantine

const DEFAULT_RULES = [
  { id: 'replay', codes: ['AV_PH_REPLAY'], threshold: 1, window_s: 600, action: 'revoke_session' },
  { id: 'bad_location', codes: ['AV_BAD_LOCATION'], threshold: 3, window_s: 600, action: 'revoke_session' },
  { id: 'cross_session', codes: ['AV_PH_CROSS_SESSION', 'AV_PH_WRONG_CONNECTOR'], threshold: 3, window_s: 600, action: 'revoke_session' },
  { id: 'deny_paths', rule_prefix: 'deny_paths:', threshold: 5, window_s: 600, action: 'revoke_session' },
]

test('settings: the default tripwire rules are stored, merged per key, audited and handed out as a copy', () => {
  const v = fresh()
  try {
    const out = v.vault.updateSettings({ tripwires: { enabled: true, rules: DEFAULT_RULES } })
    assert.deepEqual(out.tripwires.rules, DEFAULT_RULES)
    assert.deepEqual(records(v, 'settings.changed').map((r) => r.keys), [['tripwires']])
    v.vault.updateSettings({ theme: 'dark' })
    assert.equal(v.vault.getSettings().tripwires.enabled, true, 'a merge per key keeps the other keys')
    assert.deepEqual(onDisk(v).kv.settings.tripwires.rules, DEFAULT_RULES)

    const copy = v.vault.getSettings()
    copy.tripwires.enabled = false
    copy.tripwires.rules.length = 0
    assert.equal(v.vault.getSettings().tripwires.enabled, true)
    assert.equal(v.vault.getSettings().tripwires.rules.length, 4)

    // Reading needs no key; the gateway reads them on every denial.
    v.vault.lock()
    assert.equal(v.vault.getSettings().tripwires.enabled, true)
    assert.equal(code(() => v.vault.updateSettings({ theme: 'light' })).code, 'AV_LOCKED')
  } finally { v.done() }
})

test('a tripwire rule that is not the Rule shape is refused, and nothing is kept', () => {
  const v = fresh()
  try {
    v.vault.updateSettings({ tripwires: { enabled: false, rules: DEFAULT_RULES } })
    const rule = DEFAULT_RULES[0]
    const bad = [
      null, 'on', [], { enabled: true }, { enabled: 'yes', rules: [] }, { enabled: true, rules: 'defaults' },
      { enabled: true, rules: [], extra: 1 },
      { enabled: true, rules: [{ ...rule, threshold: 0 }] },
      { enabled: true, rules: [{ ...rule, threshold: 1001 }] },
      { enabled: true, rules: [{ ...rule, threshold: 1.5 }] },
      { enabled: true, rules: [{ ...rule, threshold: '5' }] },
      { enabled: true, rules: [{ ...rule, window_s: 9 }] },
      { enabled: true, rules: [{ ...rule, window_s: 86_401 }] },
      { enabled: true, rules: [{ ...rule, action: 'nuke' }] },
      { enabled: true, rules: [{ ...rule, id: 'BAD ID' }] },
      { enabled: true, rules: [{ ...rule, codes: [] }] },
      { enabled: true, rules: [{ ...rule, codes: ['not-a-code'] }] },
      { enabled: true, rules: [{ id: 'all', rule_prefix: '', threshold: 1, window_s: 60, action: 'panic' }] },
      { enabled: true, rules: [{ id: 'none', threshold: 1, window_s: 60, action: 'panic' }] },
      { enabled: true, rules: [{ ...rule, surprise: true }] },
      { enabled: true, rules: [rule, rule] },
      { enabled: true, rules: Array.from({ length: 33 }, (_, i) => ({ ...rule, id: `r${i}` })) },
    ]
    for (const tripwires of bad) {
      refusedCleanly(v, () => v.vault.updateSettings({ tripwires }), { code: 'AV_POLICY_DENIED', rule: 'tripwire_rule' })
    }
    refusedCleanly(v, () => v.vault.updateSettings(JSON.parse('{"__proto__":{"polluted":true}}')), { code: 'AV_POLICY_DENIED', rule: 'policy_invalid' })
    refusedCleanly(v, () => v.vault.updateSettings(null), { code: 'AV_POLICY_DENIED', rule: 'policy_invalid' })
    assert.equal(({}).polluted, undefined)
    // An ordinary custom rule beside them is accepted.
    v.vault.updateSettings({ tripwires: { enabled: true, rules: [{ id: 'lots', rule_prefix: 'deny_paths:', threshold: 1000, window_s: 86_400, action: 'quarantine_credential' }] } })
    assert.equal(v.vault.getSettings().tripwires.rules[0].id, 'lots')
  } finally { v.done() }
})

test('a quarantined credential issues nothing and gets no new grant, and release restores a live session', () => {
  const v = fresh()
  try {
    const { session } = v.vault.createSession({})
    const g = grantFor(v, session)
    const q = v.vault.setQuarantine('demo', { by: 'control', reason: 'looks odd' })
    assert.equal(q.by, 'control')
    assert.equal(q.reason_untrusted, 'looks odd')
    assert.equal(v.vault.listCredentials().find((c) => c.slug === 'demo').quarantine.by, 'control')
    assert.deepEqual(code(() => v.vault.issuePlaceholder({ grantId: g.id })), { code: 'AV_QUARANTINED', rule: 'quarantine' })
    assert.deepEqual(code(() => grantFor(v, session)), { code: 'AV_QUARANTINED', rule: 'quarantine' })
    const [rec] = records(v, 'cred.quarantined')
    assert.deepEqual([rec.credential_slug, rec.by, rec.rule_id, rec.reason_untrusted], ['demo', 'control', null, 'looks odd'])
    assert.ok(onDisk(v).credentials[v.cred.id].quarantine)

    // The other credential is untouched.
    v.vault.issuePlaceholder({ grantId: grantFor(v, session, v.other).id })

    assert.equal(v.vault.clearQuarantine('demo'), true)
    assert.equal(v.vault.clearQuarantine('demo'), false)
    assert.equal(records(v, 'cred.released').length, 1)
    v.vault.issuePlaceholder({ grantId: g.id })
  } finally { v.done() }
})

test('quarantining twice keeps who did it first; a bad quarantine is refused', () => {
  const v = fresh()
  try {
    const first = v.vault.setQuarantine('demo', { by: 'tripwire', rule_id: 'replay' })
    const again = v.vault.setQuarantine('demo', { by: 'control', reason: 'me too' })
    assert.deepEqual(again, first)
    assert.equal(records(v, 'cred.quarantined').length, 1)
    assert.equal(v.vault.setQuarantine('other', { reason: 'x'.repeat(5000) }).reason_untrusted.length, 200)

    refusedCleanly(v, () => v.vault.setQuarantine('demo2', {}), { code: 'AV_NOT_FOUND', rule: undefined })
    v.vault.clearQuarantine('other')
    refusedCleanly(v, () => v.vault.setQuarantine('other', { by: 'agent' }), { code: 'AV_POLICY_DENIED', rule: 'quarantine' })
    refusedCleanly(v, () => v.vault.setQuarantine('other', { by: 'tripwire', rule_id: 'Not OK' }), { code: 'AV_POLICY_DENIED', rule: 'quarantine' })
    v.vault.lock()
    assert.equal(code(() => v.vault.setQuarantine('other', {})).code, 'AV_LOCKED')
    assert.equal(code(() => v.vault.clearQuarantine('demo')).code, 'AV_LOCKED')
  } finally { v.done() }
})

// ------------------------------------------------------ F15: shortening

test('shortening an infinite session makes it finite, and brings its placeholders down with it', () => {
  const v = fresh()
  try {
    const { session } = v.vault.createSession({ infinite: true })
    const { row } = v.vault.issuePlaceholder({ grantId: grantFor(v, session).id })
    assert.equal(row.expires_at, null)
    const s = v.vault.shortenSession(session.id, HOUR)
    assert.equal(s.infinite, false)
    assert.ok(Math.abs(Date.parse(s.expires_at) - (Date.now() + HOUR)) < 1000)
    assert.equal(s.max_expires_at, s.expires_at)
    assert.equal(s.idle_timeout_ms, 2 * HOUR)
    assert.equal(row.expires_at, s.max_expires_at)
    const [rec] = records(v, 'session.shortened')
    assert.deepEqual([rec.session_id, rec.expires_at, rec.was_infinite], [session.id, s.expires_at, true])
    assert.equal(onDisk(v).sessions[session.id].infinite, false)
    assert.equal(at(Date.now() + 2 * HOUR, () => code(() => v.vault.assertSessionLive(s))).code, 'AV_SESSION_EXPIRED')
  } finally { v.done() }
})

test('shortening never lengthens', () => {
  const v = fresh()
  try {
    const { session } = v.vault.createSession({ ttlMs: HOUR })
    const end = session.expires_at
    const ceiling = session.max_expires_at
    v.vault.shortenSession(session.id, 10 * HOUR)
    assert.equal(session.expires_at, end)
    assert.equal(session.max_expires_at, ceiling)
    assert.equal(records(v, 'session.shortened')[0].was_infinite, false)

    const g = grantFor(v, session, v.cred, { ttlMs: 60_000 })
    const gEnd = g.expires_at
    v.vault.shortenGrant(g.id, HOUR)
    assert.equal(g.expires_at, gEnd)
  } finally { v.done() }
})

test('shortening a session whose expiry cannot be read ends it now instead of throwing', () => {
  const v = fresh()
  try {
    const { session } = v.vault.createSession({})
    session.expires_at = 'garbage'
    session.max_expires_at = 'garbage'
    const before = Date.now()
    v.vault.shortenSession(session.id, HOUR)
    assert.ok(Date.parse(session.expires_at) >= before && Date.parse(session.expires_at) <= Date.now())

    const g = grantFor(v, v.vault.createSession({}).session)
    g.expires_at = 'garbage'
    v.vault.shortenGrant(g.id, HOUR)
    assert.ok(Date.parse(g.expires_at) <= Date.now())
  } finally { v.done() }
})

test('shortening with a lifetime that is not a positive number, or a session that is gone, is refused', () => {
  const v = fresh()
  try {
    const { session } = v.vault.createSession({})
    const g = grantFor(v, session)
    for (const ttl of [0, -1, NaN, '60000', Infinity]) {
      refusedCleanly(v, () => v.vault.shortenSession(session.id, ttl), { code: 'AV_POLICY_DENIED', rule: 'ttl' })
      refusedCleanly(v, () => v.vault.shortenGrant(g.id, ttl), { code: 'AV_POLICY_DENIED', rule: 'grant_ttl' })
    }
    refusedCleanly(v, () => v.vault.shortenSession('nope', HOUR), { code: 'AV_NOT_FOUND', rule: undefined })
    refusedCleanly(v, () => v.vault.shortenGrant('nope', HOUR), { code: 'AV_NOT_FOUND', rule: undefined })
    v.vault.revokeSession(session.id)
    refusedCleanly(v, () => v.vault.shortenSession(session.id, HOUR), { code: 'AV_SESSION_REVOKED', rule: undefined })
    refusedCleanly(v, () => v.vault.shortenGrant(g.id, HOUR), { code: 'AV_NO_GRANT', rule: undefined })
  } finally { v.done() }
})

test('shortening a grant bounds it and its live placeholders, and is audited', () => {
  const v = fresh()
  try {
    const { session } = v.vault.createSession({ infinite: true })
    const g = grantFor(v, session)
    const { row } = v.vault.issuePlaceholder({ grantId: g.id })
    v.vault.shortenGrant(g.id, 60_000)
    assert.ok(Math.abs(Date.parse(g.expires_at) - (Date.now() + 60_000)) < 1000)
    assert.equal(row.expires_at, g.expires_at)
    assert.deepEqual(records(v, 'grant.shortened').map((r) => [r.grant_id, r.expires_at]), [[g.id, g.expires_at]])
    assert.equal(at(Date.now() + 120_000, () => code(() => v.vault.consumePlaceholder(row.id))).code, 'AV_GRANT_EXPIRED')
  } finally { v.done() }
})

test('a narrow is audited by field name, and may only turn redirects off', () => {
  const v = fresh()
  try {
    const g = grantFor(v, v.vault.createSession({}).session)
    v.vault.narrowGrant(g.id, { methods: ['GET'], redirects: { max: 0 } })
    const [rec] = records(v, 'grant.narrowed')
    assert.deepEqual(rec.fields, ['methods', 'redirects'])
    assert.equal(rec.narrow, undefined)
    assert.equal(rec.session_id, g.session_id)
    for (const redirects of [{ max: 5 }, { max: 1 }, 5, null, { max: NaN }]) {
      refusedCleanly(v, () => v.vault.narrowGrant(g.id, { redirects }), { code: 'AV_POLICY_DENIED', rule: 'narrow_widens' })
    }
  } finally { v.done() }
})

// ---------------------------------------------------- C3: elevation

test('the elevation a session was created with is recorded, [] by default', () => {
  const v = fresh()
  try {
    v.vault.createSession({})
    v.vault.createSession({ elevated: ['approval_auto_writes'] })
    v.vault.createSession({ infinite: true, elevated: ['approval_auto_writes', 'infinite'] })
    assert.deepEqual(records(v, 'session.created').map((r) => r.elevated), [[], ['approval_auto_writes'], ['approval_auto_writes', 'infinite']])
  } finally { v.done() }
})

test('an elevation the store does not recognise is refused, and nothing is written', () => {
  const v = fresh()
  try {
    for (const elevated of [['root'], 'infinite', [1], null, ['infinite', 'x'], {}, ['infinite', 'infinite', 'infinite']]) {
      refusedCleanly(v, () => v.vault.createSession({ elevated }), { code: 'AV_POLICY_DENIED', rule: 'elevation_invalid' })
    }
    assert.equal(Object.keys(v.vault.db.sessions).length, 0)
  } finally { v.done() }
})

// A placeholder lives as long as its session COULD (idle extension included),
// so a session that went idle and expired early still has placeholders whose
// own date has not passed. The session is asked at the moment of use.
test('a placeholder of a session that expired idle is refused at use, though its own date has not passed', () => {
  const v = fresh()
  try {
    const { session } = v.vault.createSession({}) // 8 hours, idle-extensible to 24
    const { row } = v.vault.issuePlaceholder({ grantId: grantFor(v, session).id })
    assert.equal(row.expires_at, session.max_expires_at)
    const idle = Date.parse(session.expires_at) + HOUR
    assert.ok(idle < Date.parse(row.expires_at), 'the fixture must leave the row itself in date')
    assert.equal(at(idle, () => code(() => v.vault.consumePlaceholder(row.id))).code, 'AV_SESSION_EXPIRED')
    assert.equal(row.state, 'dead')
    // An ordinary use inside the session's life is fine.
    const live = v.vault.createSession({}).session
    v.vault.consumePlaceholder(v.vault.issuePlaceholder({ grantId: grantFor(v, live).id }).row.id)
  } finally { v.done() }
})

test('settings never carry the webhook URL, locked or unlocked', () => {
  const v = fresh()
  try {
    const url = 'https://hooks.example/services/T0/B0/WEBHOOKSECRETPATH?token=QUERYSECRET'
    v.vault.setNotifyWebhook({ url })
    v.vault.updateSettings({ tripwires: { enabled: true, rules: DEFAULT_RULES } })
    const seen = [JSON.stringify(v.vault.getSettings())]
    v.vault.lock()
    seen.push(JSON.stringify(v.vault.getSettings()))
    for (const text of seen) {
      for (const part of ['WEBHOOKSECRETPATH', 'QUERYSECRET', 'hooks.example/services', v.vault.db.kv.notify.sealed.ct.slice(0, 24)]) {
        assert.ok(!text.includes(part), `getSettings carried ${part}`)
      }
    }
  } finally { v.done() }
})
