// What a signature binds, for the secret-bearing fields wave 3 adds (0.5, C19).
//
// A secret is bound by its digest, so the signature covers WHICH secret
// without the secret sitting in a structure that is canonicalised and
// compared. The digest of a non-string used to be the digest of
// String(value), which is "[object Object]" for every backup bundle there is:
// a signature for restoring one bundle would have restored any other.
//
// The page builds the same operation in the browser, so its builder is run
// here too and must agree with the server's on every field.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, webcrypto } from 'node:crypto'
import { operationFor, canonicalOperation, DIGESTED } from '../../src/ui/webauthn.js'
import { pageFunctions, pageConst } from './control-ui-helpers.js'

const sha = (s) => createHash('sha256').update(s).digest('hex')

const BUNDLE = { format: 'agent-vault-backup', version: 1, created_at: '2026-10-27T00:00:00.000Z', nonce: 'bm9uY2U', ct: 'Y2lwaGVy' }

test('every secret-bearing field is bound by digest, never in clear', () => {
  assert.deepEqual([...DIGESTED].sort(), ['bundle', 'prf_secret', 'recovery_passphrase', 'value', 'webhook_url'])
  const params = {
    value: 'ghp_SECRETVALUE', prf_secret: 'cHJmc2VjcmV0', recovery_passphrase: 'a recovery passphrase',
    bundle: BUNDLE, webhook_url: 'https://hooks.slack.com/services/T000/B000/XXXX',
  }
  const op = operationFor('x', params)
  const text = canonicalOperation(op)
  for (const [k, v] of Object.entries(params)) {
    assert.ok(!(k in op), `${k} is bound in clear`)
    assert.match(op[`${k}_sha256`], /^[0-9a-f]{64}$/)
    if (typeof v === 'string') assert.ok(!text.includes(v), `${k}'s value appears in the operation`)
  }
  assert.ok(!text.includes('Y2lwaGVy'), 'the bundle ciphertext appears in the operation')
})

test('a string digests exactly as it always did', () => {
  assert.equal(operationFor('cred.add', { value: 'v' }).value_sha256, sha('v'))
  assert.equal(operationFor('touchid.enroll', { prf_secret: 'p' }).prf_secret_sha256, sha('p'))
  assert.equal(operationFor('notify.set', { webhook_url: 'https://h/x' }).webhook_url_sha256, sha('https://h/x'))
  // null was String(null) before, which is what its canonical form is too.
  assert.equal(operationFor('x', { value: null }).value_sha256, sha('null'))
})

test('two different bundles give two different operations', () => {
  const a = operationFor('backup.restore', { bundle: BUNDLE })
  const b = operationFor('backup.restore', { bundle: { ...BUNDLE, ct: 'b3RoZXI' } })
  assert.notEqual(a.bundle_sha256, b.bundle_sha256, 'a signature for one bundle would restore the other')
  assert.notEqual(a.bundle_sha256, sha('[object Object]'))
})

test('the same bundle with its keys in another order is the same operation', () => {
  const reordered = Object.fromEntries(Object.entries(BUNDLE).reverse())
  assert.equal(operationFor('backup.restore', { bundle: reordered }).bundle_sha256,
    operationFor('backup.restore', { bundle: BUNDLE }).bundle_sha256)
})

test('the page builds the same operation as the servers, field for field', async () => {
  globalThis.crypto ??= webcrypto
  const { operationFor: pageOperationFor } = pageFunctions(
    [{ name: 'operationFor', async: true }, 'canonicalJson'], pageConst('DIGESTED'),
  )
  const cases = [
    ['cred.rotate', { slug: 'demo', value: 'ghp_NEW', mode: 'keep', retire_hours: 24 }],
    ['backup.restore', { bundle: BUNDLE, recovery_passphrase: 'twelve chars plus', on_conflict: 'rename' }],
    ['notify.set', { webhook_url: 'https://hooks.example/abc', detail: 'minimal' }],
    ['template.save', { name: 't', spec: { cred: 'demo', spend_usd: 1.25, methods: ['GET'] } }],
    ['session.narrow', { sid: 's', narrow: { methods: ['GET', 'HEAD'] }, presence: { challengeId: 'x' } }],
  ]
  for (const [op, params] of cases) {
    assert.equal(canonicalOperation(await pageOperationFor(op, params)), canonicalOperation(operationFor(op, params)), op)
  }
})

test("the page's digested fields are the servers' digested fields", () => {
  const page = [...pageConst('DIGESTED').matchAll(/'([a-z_]+)'/g)].map((m) => m[1]).sort()
  assert.deepEqual(page, [...DIGESTED].sort())
})
