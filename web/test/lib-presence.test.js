// lib/presence.js must describe an operation byte for byte as the servers do
// (src/ui/webauthn.js operationFor / canonicalOperation), or no signature the
// page makes would verify, and a looser one could authorise more than it said.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as page from '../src/lib/presence.js'
import * as server from '../../src/ui/webauthn.js'

const SAMPLES = [
  ['cred.add', { slug: 'gh-work', kind: 'github', value: 'sk-test-abc', host: undefined }],
  ['session.create', { label: 'ui session', grants: [{ cred: 'gh', methods: ['GET'], paths: ['/user'], budget: 50, approval: 'each' }], ttl_hours: 8 }],
  ['session.create', { label: 'forever', grants: [{ cred: 'gh' }], infinite: true }],
  ['touchid.enroll', { credential_id: 'abc_-', prf_secret: 'AAECAw==' }],
  ['cred.rotate', { slug: 'gh', value: { nested: [1, 2, { b: 1, a: 2 }] } }],
  ['tripwires.set', { enabled: true, rules: 'defaults' }],
  ['tripwires.set', { rules: [{ id: 'replay', codes: ['AV_PH_REPLAY'], threshold: 1, window_s: 600, action: 'revoke_session' }] }],
  ['session.revoke', { sid: 's_123' }],
  ['pending.decide_many', { decisions: [{ id: 'a', kind: 'request', granted: true }, { id: 'b', kind: 'session', granted: false }] }],
  ['cred.expiry_set', { slug: 'gh', expires_at: null }],
  ['presence.enroll', { credentialId: 'x', publicKey: 'y', counter: 0 }],
  ['vault.lock', {}],
]

test('the digested fields are the servers\' list', () => {
  assert.deepEqual([...page.DIGESTED].sort(), [...server.DIGESTED].sort())
})

test('canonicalJson is canonicalOperation', () => {
  for (const v of [null, 1, 'a', [3, 1], { b: 1, a: [{ d: 1, c: undefined }] }, { x: undefined }, true]) {
    assert.equal(page.canonicalJson(v), server.canonicalOperation(v))
  }
})

test('operationFor describes every request exactly as the server rebuilds it', async () => {
  for (const [op, params] of SAMPLES) {
    const mine = await page.operationFor(op, { ...params, presence: { challengeId: 'ignored' } })
    const theirs = server.operationFor(op, params)
    assert.equal(page.canonicalJson(mine), server.canonicalOperation(theirs), `${op} differs`)
  }
})

test('a secret is bound by its digest and never appears in the operation', async () => {
  const op = await page.operationFor('cred.add', { slug: 'gh', value: 'sk-test-SECRET' })
  assert.ok(!JSON.stringify(op).includes('sk-test-SECRET'))
  assert.match(op.value_sha256, /^[0-9a-f]{64}$/)
})

test('the base64 helpers round-trip', () => {
  const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255])
  assert.deepEqual(page.b64uToBuf(page.bufToB64u(bytes)), bytes)
  assert.deepEqual(page.b64ToBuf(page.bufToB64(bytes)), bytes)
  assert.ok(!page.bufToB64u(bytes).includes('='))
})

// ---- the flows, against a fake server and a fake authenticator ------------

function harness({ enrolled = true, lockstate = {}, getError = null } = {}) {
  const calls = []
  const call = async (method, path, body) => {
    calls.push({ method, path, body })
    if (path === 'presence/state') return { enrolled, credentialId: 'cred1', rpId: 'localhost' }
    if (path === 'presence/challenge') return { challengeId: 'ch1', challenge: 'AAEC', allowCredentials: [{ id: 'Y3JlZDE' }], rpId: 'localhost' }
    if (path === 'lockstate') return lockstate
    if (path === 'presence/enroll/begin') return { challenge: 'AAEC', rp: { id: 'localhost', name: 'agent-vault' }, user: { id: 'dXNlcg', name: 'operator', displayName: 'Vault operator' } }
    return { ok: true, path }
  }
  const got = []
  const credentials = {
    async get(opts) {
      got.push(opts)
      if (getError) throw getError
      return {
        rawId: new Uint8Array([1, 2, 3]).buffer,
        response: {
          authenticatorData: new Uint8Array([4]).buffer,
          clientDataJSON: new Uint8Array([5]).buffer,
          signature: new Uint8Array([6]).buffer,
        },
      }
    },
    async create(opts) {
      got.push(opts)
      return { rawId: new Uint8Array([9]).buffer, response: { attestationObject: new Uint8Array([7]).buffer, clientDataJSON: new Uint8Array([8]).buffer } }
    },
  }
  const p = page.createPresence({ call, credentials: () => credentials, random: (n) => new Uint8Array(n) })
  return { p, calls, got }
}

test('gated asks for a challenge over the exact operation, then sends the proof', async () => {
  const { p, calls, got } = harness()
  await p.refresh()
  const operation = await page.operationFor('session.revoke', { sid: 's_123' })
  const sent = await p.gated(operation, async (proof) => proof)
  const ch = calls.find((c) => c.path === 'presence/challenge')
  assert.deepEqual(ch, { method: 'POST', path: 'presence/challenge', body: { operation: { op: 'session.revoke', sid: 's_123' } } })
  assert.equal(got[0].publicKey.userVerification, 'required')
  assert.equal(got[0].publicKey.rpId, 'localhost')
  assert.deepEqual([...got[0].publicKey.challenge], [0, 1, 2])
  assert.deepEqual(Object.keys(sent).sort(), ['authenticatorData', 'challengeId', 'clientDataJSON', 'credentialId', 'signature'])
  assert.equal(sent.challengeId, 'ch1')
  assert.equal(sent.credentialId, 'AQID')
})

test('nothing is signed or sent without an enrolled authenticator', async () => {
  const { p, calls } = harness({ enrolled: false })
  await p.refresh()
  let sent = false
  await assert.rejects(p.gated({ op: 'vault.lock' }, async () => { sent = true }), /No authenticator enrolled/)
  assert.equal(sent, false)
  assert.ok(!calls.some((c) => c.path === 'presence/challenge'))
})

test('a cancelled Touch ID changes nothing and says so', async () => {
  const { p } = harness({ getError: Object.assign(new Error('x'), { name: 'NotAllowedError' }) })
  await p.refresh()
  let sent = false
  await assert.rejects(p.gated({ op: 'vault.lock' }, async () => { sent = true }), /Not confirmed\. Nothing was changed\./)
  assert.equal(sent, false)
})

test('lock and turning off Touch ID unlock sign the same bare operations the old page did', async () => {
  const { p, calls } = harness()
  await p.refresh()
  await p.lock()
  await p.disableTouchId()
  const ops = calls.filter((c) => c.path === 'presence/challenge').map((c) => c.body.operation)
  assert.deepEqual(ops, [{ op: 'vault.lock' }, { op: 'touchid.remove' }])
  assert.ok(calls.some((c) => c.method === 'POST' && c.path === 'lock' && c.body.presence.challengeId === 'ch1'))
  assert.ok(calls.some((c) => c.method === 'POST' && c.path === 'touchid/remove' && c.body.presence))
})

test('enrolling sends the passphrase with the enrolment, only when the vault has one', async () => {
  const asked = []
  const { p, calls } = harness({ lockstate: { has_passphrase: true } })
  await p.enroll({ askPassphrase: async (label) => { asked.push(label); return 'correct horse' } })
  const finish = calls.find((c) => c.path === 'presence/enroll/finish')
  assert.equal(finish.body.passphrase, 'correct horse')
  assert.equal(asked.length, 1)

  const none = harness({ lockstate: { has_passphrase: false } })
  await none.p.enroll({ askPassphrase: async () => { throw new Error('should not ask') } })
  assert.equal(none.calls.find((c) => c.path === 'presence/enroll/finish').body.passphrase, undefined)

  const cancel = harness({ lockstate: { has_passphrase: true } })
  await assert.rejects(cancel.p.enroll({ askPassphrase: async () => null }), /Cancelled\. Nothing was enrolled\./)
  assert.ok(!cancel.calls.some((c) => c.path === 'presence/enroll/begin'))
})

test('every operation the page signs has words for the status line', () => {
  for (const [op, params] of SAMPLES) assert.ok(!page.describeOperation({ op, ...params }).startsWith(op), `${op} has no words`)
  assert.equal(page.describeOperation({ op: 'session.revoke', sid: 's_123' }), 'revoke session s_123')
})
