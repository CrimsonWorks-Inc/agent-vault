// The vault's own bookkeeping: narrowing that can only narrow, a ledger that
// stays bounded, placeholders that live as long as their session, and a
// locked vault that boots without pretending to have been unlocked.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Vault } from '../../src/store/vault.js'
import * as policyMod from '../../src/core/policy.js'

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

// Requests to probe a policy with: every method, hosts in and out of the
// grant, paths in and out of it, and the spellings that normalise onto them.
const PROBE_METHODS = ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE']
const PROBE_HOSTS = ['api.example.com', 'API.Example.com', 'evil.example', 'sub.api.example.com', 'example.com']
const PROBE_PATHS = ['/repos/a', '/repos/a/b/c', '/repos', '/admin/x', '/admin', '/', '/other/thing', '/repos/../admin/x']
const APPROVAL_STRICTNESS = ['auto', 'first-use', 'on-write', 'each']

/** Whether `policy` lets a request through. */
function allows(policy, req) {
  try { policyMod.evaluateHttp(policy, req); return true } catch { return false }
}

/**
 * That `after` permits nothing `before` refused. By behaviour, not by looking
 * for particular strings: an absent list is UNRESTRICTED to the policy engine,
 * and the old version of this read `(policy.methods || [])` — so a result that
 * dropped a constraint altogether looked emptier than the original, and passed.
 */
function assertNoWider(after, before = POLICY) {
  // Shape first: where the original restricted a dimension, the result must
  // still be a list. null or absent there is "anything".
  for (const k of ['methods', 'paths', 'hosts']) {
    if (Array.isArray(before[k])) assert.ok(Array.isArray(after[k]), `${k} is no longer restricted: ${JSON.stringify(after[k])}`)
  }
  for (const method of PROBE_METHODS) {
    for (const host of PROBE_HOSTS) {
      for (const path of PROBE_PATHS) {
        const req = { method, host, path }
        if (!allows(before, req)) assert.ok(!allows(after, req), `${method} ${host}${path} was refused before and is allowed now`)
        // Approval can only get stricter, for every request still allowed.
        if (allows(after, req)) {
          for (const firstUse of [true, false]) {
            if (policyMod.needsApproval(before, { method, firstUse })) {
              assert.ok(policyMod.needsApproval(after, { method, firstUse }), `${method} no longer needs approval`)
            }
          }
        }
      }
    }
  }
  // An absent approval is 'auto' to needsApproval; an unknown one is too.
  assert.ok(APPROVAL_STRICTNESS.indexOf(after.approval ?? 'auto') >= APPROVAL_STRICTNESS.indexOf(before.approval ?? 'auto'),
    `approval loosened from ${before.approval} to ${after.approval}`)
  assert.ok(after.budget && Number.isFinite(after.budget.limit), `budget is no longer bounded: ${JSON.stringify(after.budget)}`)
  assert.ok(after.budget.limit <= before.budget.limit, `budget widened: ${after.budget.limit}`)
}

test('the no-wider check itself refuses a result that dropped a constraint', () => {
  // Every way a broken narrowing could pass the old check by deleting rather
  // than adding: each must make the check fail.
  for (const broken of [
    { ...POLICY, methods: null }, { ...POLICY, paths: null }, { ...POLICY, hosts: null },
    { ...POLICY, methods: undefined }, { ...POLICY, approval: undefined }, { ...POLICY, budget: null },
    { ...POLICY, methods: ['GET', 'PUT'] }, { ...POLICY, paths: ['/**'] }, { ...POLICY, hosts: ['*.example.com'] },
    { ...POLICY, approval: 'first-use' }, { ...POLICY, budget: { unit: 'requests', limit: NaN } },
  ]) {
    assert.throws(() => assertNoWider(broken), `passed: ${JSON.stringify(broken)}`)
  }
  // And it does not refuse the original, or an honest narrowing of it.
  assert.doesNotThrow(() => assertNoWider(POLICY))
  assert.doesNotThrow(() => assertNoWider({ ...POLICY, methods: ['GET'], paths: ['/repos/a/**'], approval: 'each', budget: { unit: 'requests', limit: 3 } }))
})

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
