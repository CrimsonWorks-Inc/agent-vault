// F17, store side: template CRUD. A template is configuration, not standing
// approval; its hash is what a human's signature binds, so it has to describe
// exactly the spec a later read returns.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { Vault } from '../../src/store/vault.js'
import { canonicalOperation } from '../../src/ui/webauthn.js'
import { fresh, code, records, refusedCleanly } from './store-helpers.js'

const SPEC = { cred: 'demo', methods: ['GET'], paths: ['/repos/**'], budget: 50, spend_usd: 0.25, approval: 'on-write' }
const sha = (spec) => createHash('sha256').update(canonicalOperation(spec)).digest('hex')

test('a template is saved with a version and the hash of its canonical form, and audited', () => {
  const v = fresh()
  try {
    const t = v.vault.saveTemplate('gh-read', SPEC)
    assert.deepEqual([t.name, t.version, t.spec, t.hash], ['gh-read', 1, SPEC, sha(SPEC)])
    assert.ok(Date.parse(t.created_at) && t.created_at === t.updated_at)
    // Key order does not change the hash; content does.
    const reordered = Object.fromEntries(Object.entries(SPEC).reverse())
    assert.equal(sha(reordered), t.hash)

    const t2 = v.vault.saveTemplate('gh-read', { ...SPEC, methods: ['GET', 'HEAD'] })
    assert.equal(t2.version, 2)
    assert.notEqual(t2.hash, t.hash)
    assert.equal(t2.created_at, t.created_at)
    assert.deepEqual(records(v, 'template.saved').map((r) => [r.name, r.version, r.template_hash]), [['gh-read', 1, t.hash], ['gh-read', 2, t2.hash]])

    // It survives a restart, hash and all.
    const again = Vault.open(v.dir)
    assert.deepEqual(again.getTemplate('gh-read'), t2)
    assert.equal(sha(again.getTemplate('gh-read').spec), t2.hash)
  } finally { v.done() }
})

test('reads hand out copies, sorted, and know nothing of names that are not templates', () => {
  const v = fresh()
  try {
    v.vault.saveTemplate('zeta', SPEC)
    v.vault.saveTemplate('alpha', SPEC)
    assert.deepEqual(v.vault.listTemplates().map((t) => t.name), ['alpha', 'zeta'])
    const copy = v.vault.getTemplate('alpha')
    copy.spec.methods.push('DELETE')
    copy.version = 99
    assert.deepEqual(v.vault.getTemplate('alpha').spec.methods, ['GET'])
    v.vault.listTemplates()[0].spec.methods.push('DELETE')
    assert.deepEqual(v.vault.getTemplate('alpha').spec.methods, ['GET'])
    for (const name of ['nope', '__proto__', 'constructor', 42, null]) assert.equal(v.vault.getTemplate(name), null, String(name))
    assert.equal(v.vault.deleteTemplate('__proto__'), false)
  } finally { v.done() }
})

test('deleting a template removes it once and records the version it had', () => {
  const v = fresh()
  try {
    v.vault.saveTemplate('gh-read', SPEC)
    v.vault.saveTemplate('gh-read', { ...SPEC, budget: 10 })
    assert.equal(v.vault.deleteTemplate('gh-read'), true)
    assert.equal(v.vault.deleteTemplate('gh-read'), false)
    assert.equal(v.vault.getTemplate('gh-read'), null)
    assert.deepEqual(records(v, 'template.deleted').map((r) => [r.name, r.version]), [['gh-read', 2]])
    // A name reused after deletion starts again at 1.
    assert.equal(v.vault.saveTemplate('gh-read', SPEC).version, 1)
  } finally { v.done() }
})

test('a bad template name, shape or size is refused, and nothing is kept', () => {
  const v = fresh()
  try {
    for (const name of ['Bad', '-lead', 'a'.repeat(33), '', 'a b', 'a_b', 42, null]) {
      refusedCleanly(v, () => v.vault.saveTemplate(name, SPEC), { code: 'AV_POLICY_DENIED', rule: 'template_name' })
    }
    for (const spec of [null, [], 'spec', 7, { ...SPEC, template: 'x' }, { ...SPEC, template_hash: 'ab' }, { ...SPEC, presence: { passphrase: 'pw' } }, { n: 1n }]) {
      refusedCleanly(v, () => v.vault.saveTemplate('ok', spec), { code: 'AV_POLICY_DENIED', rule: 'session_shape' })
    }
    refusedCleanly(v, () => v.vault.saveTemplate('big', { cred: 'demo', label: 'x'.repeat(16 * 1024) }), { code: 'AV_POLICY_DENIED', rule: 'template_size' })
    // Just under the size bound is fine.
    v.vault.saveTemplate('fits', { label: 'x'.repeat(16 * 1024 - 20) })
    for (let i = 1; i < 64; i++) v.vault.saveTemplate(`t${i}`, SPEC)
    refusedCleanly(v, () => v.vault.saveTemplate('one-more', SPEC), { code: 'AV_POLICY_DENIED', rule: 'template_size' })
    // Replacing an existing one at the cap is still allowed.
    assert.equal(v.vault.saveTemplate('t1', { ...SPEC, budget: 1 }).version, 2)
    v.vault.lock()
    assert.equal(code(() => v.vault.saveTemplate('t2', SPEC)).code, 'AV_LOCKED')
    assert.equal(code(() => v.vault.deleteTemplate('t2')).code, 'AV_LOCKED')
    assert.equal(v.vault.getTemplate('t2').version, 1)
  } finally { v.done() }
})

test('session.created records the template and version a session came from, or null', () => {
  const v = fresh()
  try {
    v.vault.createSession({})
    const { session } = v.vault.createSession({ template: 'gh-read', templateVersion: 2 })
    assert.deepEqual([session.template, session.template_version], ['gh-read', 2])
    assert.deepEqual(records(v, 'session.created').map((r) => [r.template, r.template_version]), [[null, null], ['gh-read', 2]])
    for (const [template, templateVersion] of [['gh-read', null], [null, 2], ['Bad Name', 1], ['gh-read', 0], ['gh-read', 1.5], ['gh-read', '2']]) {
      refusedCleanly(v, () => v.vault.createSession({ template, templateVersion }), { code: 'AV_POLICY_DENIED', rule: 'template_name' })
    }
  } finally { v.done() }
})
