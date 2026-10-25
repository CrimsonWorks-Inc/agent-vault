// The vault's own bookkeeping: narrowing that can only narrow, a ledger that
// stays bounded, placeholders that live as long as their session, and a
// locked vault that boots without pretending to have been unlocked.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Vault } from '../../src/store/vault.js'

const SECRET = 'ghp_STORETEST00112233445566778899aabb'

function fresh() {
  const dir = mkdtempSync(join(tmpdir(), 'av-fc-store-'))
  const vault = Vault.create(dir, { factor: 'none' })
  const cred = vault.addCredential({
    slug: 'demo', kind: 'http', connector: { host: 'api.example.com', scheme: 'https' },
    fields: { token: SECRET }, sites: { token: ['header:authorization:Bearer'] },
  })
  const done = () => rmSync(dir, { recursive: true, force: true })
  return { dir, vault, cred, done }
}

const POLICY = {
  hosts: ['api.example.com'], methods: ['GET', 'POST'], paths: ['/repos/**'],
  budget: { unit: 'requests', limit: 100 }, approval: 'on-write',
}

function grantOn(v, policy = POLICY) {
  const { session, token } = v.vault.createSession({ label: 'parent' })
  const grant = v.vault.createGrant({ sessionId: session.id, credentialId: v.cred.id, fields: ['token'], policy })
  return { session, token, grant }
}

// A "narrowing" that tries to widen every dimension at once.
const WIDER = {
  methods: ['DELETE'], paths: ['/admin/**'], approval: 'auto',
  hosts: ['evil.example'], budget: { unit: 'requests', limit: 1e9 },
}

function assertNoWider(policy) {
  assert.ok(!(policy.methods || []).includes('DELETE'), `methods widened: ${policy.methods}`)
  assert.ok(!(policy.paths || []).includes('/admin/**'), `paths widened: ${policy.paths}`)
  assert.ok(!(policy.hosts || []).includes('evil.example'), `hosts widened: ${policy.hosts}`)
  assert.notEqual(policy.approval, 'auto', 'approval loosened')
  assert.ok(policy.budget.limit <= 100, `budget widened: ${policy.budget.limit}`)
}

test('narrowGrant can only intersect, never widen', () => {
  const v = fresh()
  try {
    const { grant } = grantOn(v)
    assertNoWider(v.vault.narrowGrant(grant.id, WIDER).policy)
  } finally { v.done() }
})

test('narrowGrant still narrows', () => {
  const v = fresh()
  try {
    const { grant } = grantOn(v)
    const p = v.vault.narrowGrant(grant.id, { methods: ['GET'], paths: ['/repos/mine/**'], approval: 'each', budget: { unit: 'requests', limit: 5 } }).policy
    assert.deepEqual(p.methods, ['GET'])
    assert.deepEqual(p.paths, ['/repos/mine/**'])
    assert.equal(p.approval, 'each')
    assert.equal(p.budget.limit, 5)
    assert.deepEqual(p.hosts, ['api.example.com'])
  } finally { v.done() }
})

test('a forked session can only narrow its parent\'s grants', () => {
  const v = fresh()
  try {
    const { session } = grantOn(v)
    const child = v.vault.forkSession(session.id, { narrow: WIDER })
    const [g] = v.vault.grantsForSession(child.session.id)
    assertNoWider(g.policy)

    const narrowed = v.vault.forkSession(session.id, { narrow: { methods: ['GET'] } })
    const [n] = v.vault.grantsForSession(narrowed.session.id)
    assert.deepEqual(n.policy.methods, ['GET'])
    assert.deepEqual(n.policy.paths, ['/repos/**'], 'what the narrowing does not mention is kept')
  } finally { v.done() }
})

test('an expired session takes its placeholders with it', async () => {
  const v = fresh()
  try {
    const { session } = v.vault.createSession({ label: 'short', ttlMs: 400 })
    const grant = v.vault.createGrant({ sessionId: session.id, credentialId: v.cred.id, fields: ['token'], policy: POLICY })
    v.vault.issuePlaceholder({ grantId: grant.id })
    await new Promise((r) => setTimeout(r, 450))
    assert.throws(() => v.vault.assertSessionLive(session), /expired/)
    assert.ok(v.vault.listPlaceholders(session.id).every((p) => p.state === 'dead'))
    assert.equal(v.vault.stats().placeholders_live, 0)
  } finally { v.done() }
})

test('the ledger bound collects active rows whose time has passed', () => {
  const v = fresh()
  try {
    const { grant } = grantOn(v)
    const past = new Date(Date.now() - 1000).toISOString()
    // Rows a session that was never touched again left behind: still marked
    // active, long expired. They used to be exempt from collection forever.
    for (let i = 0; i < 600; i++) {
      v.vault.db.placeholders[`ph_old${i}`] = {
        id: `ph_old${i}`, grant_id: grant.id, field: 'token', sid: 'gone', nonce_hash: `x${i}`,
        uses: 1, max_uses: 10, state: 'active', created_at: past, expires_at: past,
      }
    }
    v.vault.issuePlaceholder({ grantId: grant.id })
    // The collector runs just before the new row goes in: 512 plus that one.
    assert.ok(Object.keys(v.vault.db.placeholders).length <= 513, `${Object.keys(v.vault.db.placeholders).length} rows kept`)
  } finally { v.done() }
})

test('a placeholder lives as long as its session, idle extension included', async () => {
  const v = fresh()
  try {
    const { session } = v.vault.createSession({ label: 'idle' })
    const grant = v.vault.createGrant({ sessionId: session.id, credentialId: v.cred.id, fields: ['token'], policy: POLICY })
    // Moments from its initial expiry, with the idle ceiling still hours away.
    session.expires_at = new Date(Date.now() + 300).toISOString()
    const { row } = v.vault.issuePlaceholder({ grantId: grant.id })
    v.vault.touchSession(session) // activity: the session is extended
    await new Promise((r) => setTimeout(r, 400))
    v.vault.assertSessionLive(session)
    assert.doesNotThrow(() => v.vault.consumePlaceholder(row.id), 'the placeholder died before its session')
  } finally { v.done() }
})

test('a placeholder with its own ttl still expires on time', async () => {
  const v = fresh()
  try {
    const { grant } = grantOn(v)
    const { row } = v.vault.issuePlaceholder({ grantId: grant.id, ttlMs: 200 })
    await new Promise((r) => setTimeout(r, 300))
    assert.throws(() => v.vault.consumePlaceholder(row.id), /expired/)
  } finally { v.done() }
})

test('booting a locked vault does not record an unlock nobody performed', () => {
  const v = fresh()
  try {
    v.vault.lock()
    const booted = Vault.open(v.dir)
    assert.equal(booted.startInRecordedState(), false, 'it must come up locked')
    assert.equal(booted.audit, null, 'and holding no audit key, as after an explicit lock')
    assert.equal(Vault.open(v.dir).lockedOnDisk, true, 'the lock is never cleared on disk, even briefly')

    booted.unlockWith({})
    const kinds = booted.audit.read({ limit: 50 }).map((r) => r.kind)
    const fromLock = kinds.slice(kinds.lastIndexOf('vault.lock'))
    assert.deepEqual(fromLock, ['vault.lock', 'vault.started_locked', 'vault.unlock'])
  } finally { v.done() }
})

test('booting an unlocked vault still unlocks it', () => {
  const v = fresh()
  try {
    const booted = Vault.open(v.dir)
    assert.equal(booted.startInRecordedState(), true)
    assert.equal(booted.locked, false)
    assert.ok(booted.audit.read({ limit: 5 }).some((r) => r.kind === 'vault.unlock'))
  } finally { v.done() }
})
