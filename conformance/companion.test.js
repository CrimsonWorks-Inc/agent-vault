// Touch ID in the companion, driven through the CLI as the companion drives it:
// a challenge for the exact request a command would send (which sends nothing
// that changes anything), then the same command with the signed proof on stdin.
// A software P-256 key stands in for the Secure Enclave.
import { describe, test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto'
import { rustSkipReason, implName, openWorld, runCli, seed, leaksSecret } from './lib/harness.js'

const skip = rustSkipReason() || (implName() === 'js' ? 'the companion factor is new in the Rust daemon' : null)
const PASSPHRASE = 'conformance-companion-passphrase'
const PREFIX = Buffer.from('agent-vault companion presence v1\n')

function enclave() {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  return {
    spki: publicKey.export({ type: 'spki', format: 'der' }),
    sign: (challenge) => sign(
      'sha256',
      Buffer.concat([PREFIX, Buffer.from(challenge, 'base64url')]),
      { key: privateKey, dsaEncoding: 'der' },
    ).toString('base64url'),
  }
}

function ok(res, label) {
  assert.equal(res.code, 0, `${label}\nexit ${res.code}\n${res.stderr}\n${res.stdout.slice(0, 800)}`)
  assert.equal(res.json?.ok, true, `${label} envelope ${res.stdout.slice(0, 400)}`)
  assert.equal(leaksSecret(res.stdout + res.stderr), null, label)
  return res.json.data
}

function refused(res, label) {
  assert.notEqual(res.code, 0, `${label}: ${res.stdout.slice(0, 400)}`)
  assert.equal(res.json?.ok, false, label)
  return res.json.error
}

async function credential(w, slug) {
  const list = await w.control('GET', '/v1/credentials')
  return list.json.find((c) => c.slug === slug)
}

if (skip) {
  test('companion', { skip }, () => {})
} else {
  describe('companion', { concurrency: false, timeout: 180_000 }, () => {
    let w
    const key = enclave()
    before(async () => {
      w = await seed(await openWorld())
      const set = await w.control('POST', '/v1/passphrase', { passphrase: PASSPHRASE })
      assert.equal(set.status, 200, set.text)
    })
    after(async () => { await w?.close() })

    test('enrolling needs the passphrase, typed at a terminal', async () => {
      assert.equal(ok(await runCli(w, ['companion', 'status', '--json']), 'status').enrolled, false)
      // No terminal here, so the CLI cannot ask, and nothing is enrolled.
      refused(await runCli(w, ['companion', 'enroll', key.spki.toString('base64url'), '--json']), 'enroll without a terminal')
      assert.equal(ok(await runCli(w, ['companion', 'status', '--json']), 'status').enrolled, false)
      const enrolled = await w.control('POST', '/v1/presence/companion', {
        publicKeySpki: key.spki.toString('base64'),
        label: 'Conformance Mac',
        presence: { passphrase: PASSPHRASE },
      })
      assert.equal(enrolled.status, 200, enrolled.text)
      const status = ok(await runCli(w, ['companion', 'status', '--json']), 'status')
      assert.equal(status.enrolled, true)
      assert.equal(status.label, 'Conformance Mac')
      assert.equal(status.key_id, enrolled.json.key_id)
    })

    test('a challenge sends nothing; the signed command does what it says once', async () => {
      const q = await w.control('POST', '/v1/credentials/quarantine', { slug: 'demo', reason: 'conformance' })
      assert.equal(q.status, 200, q.text)

      const issued = ok(await runCli(w, ['cred', 'release', 'demo', '--companion-challenge', '--json']), 'challenge')
      assert.equal(issued.operation.op, 'cred.release')
      assert.equal(issued.operation.slug, 'demo')
      assert.ok((await credential(w, 'demo')).quarantine, 'still stopped: the challenge changed nothing')

      const proof = JSON.stringify({ challengeId: issued.challengeId, companionSignature: key.sign(issued.challenge) })
      ok(await runCli(w, ['cred', 'release', 'demo', '--presence-stdin', '--json'], { input: `${proof}\n` }), 'release')
      assert.equal((await credential(w, 'demo')).quarantine ?? null, null)

      // The same proof again is refused: a challenge is used once.
      await w.control('POST', '/v1/credentials/quarantine', { slug: 'demo', reason: 'conformance' })
      const again = refused(await runCli(w, ['cred', 'release', 'demo', '--presence-stdin', '--json'], { input: `${proof}\n` }), 'replay')
      assert.equal(again.code, 'AV_PRESENCE_REQUIRED')
      assert.ok((await credential(w, 'demo')).quarantine)

      // Another key's signature is refused too.
      const other = enclave()
      const next = ok(await runCli(w, ['cred', 'release', 'demo', '--companion-challenge', '--json']), 'challenge')
      const forged = JSON.stringify({ challengeId: next.challengeId, companionSignature: other.sign(next.challenge) })
      refused(await runCli(w, ['cred', 'release', 'demo', '--presence-stdin', '--json'], { input: `${forged}\n` }), 'forged')
      assert.ok((await credential(w, 'demo')).quarantine)
    })

    test('a new key value follows the proof on stdin', async () => {
      const value = 'conformance-rotated-value-0123456789'
      const issued = ok(await runCli(w, ['cred', 'rotate', 'demo', '--companion-challenge', '--json'], { input: `${value}\n` }), 'challenge')
      assert.equal(issued.operation.op, 'cred.rotate')
      assert.equal(typeof issued.operation.value_sha256, 'string', 'the value is bound by digest, never in clear')
      assert.ok(!JSON.stringify(issued).includes(value))
      const proof = JSON.stringify({ challengeId: issued.challengeId, companionSignature: key.sign(issued.challenge) })
      const done = ok(await runCli(w, ['cred', 'rotate', 'demo', '--presence-stdin', '--json'], { input: `${proof}\n${value}\n` }), 'rotate')
      assert.ok(!JSON.stringify(done).includes(value))
    })

    test('another service\'s key added in the island is bound with its host and header', async () => {
      const value = 'conformance-eleven-value-0123456789'
      const add = ['cred', 'add', 'eleven', '--kind', 'http', '--host', 'api.elevenlabs.io', '--site', 'header:xi-api-key']
      const asked = ok(await runCli(w, [...add, '--companion-challenge', '--json'], { input: `${value}\n` }), 'add challenge')
      // What SignedRequest.add in desktop/Sources/CompanionCore/Signing.swift expects.
      assert.deepEqual(Object.keys(asked.operation).sort(), ['host', 'kind', 'op', 'sites', 'slug', 'value_sha256'])
      assert.equal(asked.operation.host, 'api.elevenlabs.io')
      assert.deepEqual(asked.operation.sites, ['header:xi-api-key'])
      const proof = JSON.stringify({ challengeId: asked.challengeId, companionSignature: key.sign(asked.challenge) })
      ok(await runCli(w, [...add, '--presence-stdin', '--json'], { input: `${proof}\n${value}\n` }), 'add')
      const made = await credential(w, 'eleven')
      assert.deepEqual(made.fields[0].sites, ['header:xi-api-key'])
    })

    test('a key an agent proposed is finished as the island finishes it: hosts and key bound', async () => {
      const res = await fetch(`http://127.0.0.1:${w.port}/mcp`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'vault_propose_credential', arguments: { slug: 'linear', host: 'api.linear.app' } } }),
      })
      const asked = JSON.parse((await res.json()).result.content[0].text)
      assert.equal(asked.state, 'pending', JSON.stringify(asked))
      const value = 'conformance-proposed-value-0123456789'
      const approve = ['approve', asked.request_id]
      const issued = ok(await runCli(w, [...approve, '--companion-challenge', '--json'], { input: `${value}\n` }), 'challenge')
      // What the island checks before it asks for a fingerprint
      // (SignedRequest.finish in desktop/Sources/CompanionCore/Signing.swift).
      assert.deepEqual(Object.keys(issued.operation).sort(), ['granted', 'hosts', 'id', 'op', 'value_sha256'])
      assert.equal(issued.operation.op, 'cred_proposal.approve')
      assert.deepEqual(issued.operation.hosts, ['api.linear.app'])
      assert.equal(issued.operation.value_sha256, createHash('sha256').update(value).digest('hex'))
      assert.ok(!JSON.stringify(issued).includes(value))
      assert.equal(await credential(w, 'linear'), undefined, 'the challenge saved nothing')
      const proof = JSON.stringify({ challengeId: issued.challengeId, companionSignature: key.sign(issued.challenge) })
      // Signed for one key, sent with another: refused.
      refused(await runCli(w, [...approve, '--presence-stdin', '--json'], { input: `${proof}\nanother-value-0123456789\n` }), 'other key')
      assert.equal(await credential(w, 'linear'), undefined)
      const again = ok(await runCli(w, [...approve, '--companion-challenge', '--json'], { input: `${value}\n` }), 'challenge')
      const signed = JSON.stringify({ challengeId: again.challengeId, companionSignature: key.sign(again.challenge) })
      const done = ok(await runCli(w, [...approve, '--presence-stdin', '--json'], { input: `${signed}\n${value}\n` }), 'finish')
      assert.equal(done.state, 'approved')
      assert.ok(!JSON.stringify(done).includes(value))
      assert.equal((await credential(w, 'linear')).connector.host, 'api.linear.app')
    })

    test('a session made in the island is bound whole', async () => {
      // Two keys, added as the island adds one (demo is stopped by now).
      for (const slug of ['one', 'two']) {
        const value = `conformance-${slug}-value-0123456789`
        const add = ['cred', 'add', slug, '--kind', 'github']
        const asked = ok(await runCli(w, [...add, '--companion-challenge', '--json'], { input: `${value}\n` }), 'add challenge')
        const addProof = JSON.stringify({ challengeId: asked.challengeId, companionSignature: key.sign(asked.challenge) })
        ok(await runCli(w, [...add, '--presence-stdin', '--json'], { input: `${addProof}\n${value}\n` }), 'add')
      }
      // The commands and operations the companion builds (SignedRequest.create
      // and sessionOperation in desktop/Sources/CompanionCore/Signing.swift):
      // it signs only an operation equal to the one it expects.
      const label = ['--label', 'companion session']
      const one = ok(await runCli(w, ['session', 'create', '--cred', 'one', '--ttl', '8', ...label, '--methods', 'GET', '--companion-challenge', '--json']), 'one key')
      assert.deepEqual(one.operation, { op: 'session.create', cred: 'one', label: 'companion session', ttl_hours: 8, methods: ['GET'] })
      const args = ['session', 'create', '--cred', 'one,two', '--ttl', '24', ...label]
      const two = ok(await runCli(w, [...args, '--companion-challenge', '--json']), 'two keys')
      assert.deepEqual(two.operation, { op: 'session.create', grants: [{ cred: 'one' }, { cred: 'two' }], label: 'companion session', ttl_hours: 24 })

      const proof = JSON.stringify({ challengeId: two.challengeId, companionSignature: key.sign(two.challenge) })
      const made = ok(await runCli(w, [...args, '--presence-stdin', '--json'], { input: `${proof}\n` }), 'start')
      assert.equal(typeof made.session_id, 'string')
      const listed = await w.control('GET', '/v1/sessions')
      assert.equal(listed.json.find((s) => s.id === made.session_id)?.label, 'companion session')
    })

    test('the companion modes refuse what they are not for', async () => {
      // A command that would change something before any presence check.
      const lock = refused(await runCli(w, ['lock', '--companion-challenge', '--json']), 'lock')
      assert.match(lock.message, /nothing was sent/)
      const state = await w.control('GET', '/v1/lockstate')
      assert.equal(state.json.locked, false)
      // Stdin carries the companion's proof and nothing else: never a passphrase.
      const piped = JSON.stringify({ passphrase: PASSPHRASE })
      refused(await runCli(w, ['cred', 'release', 'demo', '--presence-stdin', '--json'], { input: `${piped}\n` }), 'passphrase on stdin')
      refused(await runCli(w, ['cred', 'release', 'demo', '--presence-stdin', '--companion-challenge', '--json']), 'both modes')
      assert.ok((await credential(w, 'demo')).quarantine)
    })

    test('Touch ID unlock: set up with a signed proof, opens the vault, goes with the key', async () => {
      // The secret the Secure Enclave derives after Touch ID; random here.
      const secret = randomBytes(32).toString('base64url')
      const enable = ['companion', 'enable-unlock']
      const issued = ok(await runCli(w, [...enable, '--companion-challenge', '--json'], { input: `${secret}\n` }), 'challenge')
      assert.equal(issued.operation.op, 'companion.unlock_enroll')
      assert.equal(issued.operation.prf_secret_sha256, createHash('sha256').update(secret).digest('hex'), 'bound by digest')
      assert.ok(!JSON.stringify(issued).includes(secret))
      // A secret that is not 32 bytes is refused before any proof is spent.
      refused(await runCli(w, [...enable, '--presence-stdin', '--json'], {
        input: `${JSON.stringify({ challengeId: issued.challengeId, companionSignature: key.sign(issued.challenge) })}\nshort\n`,
      }), 'short secret')
      const again = ok(await runCli(w, [...enable, '--companion-challenge', '--json'], { input: `${secret}\n` }), 'challenge')
      const proof = JSON.stringify({ challengeId: again.challengeId, companionSignature: key.sign(again.challenge) })
      ok(await runCli(w, [...enable, '--presence-stdin', '--json'], { input: `${proof}\n${secret}\n` }), 'enable')
      assert.equal(ok(await runCli(w, ['companion', 'status', '--json']), 'status').unlock, true)

      ok(await runCli(w, ['lock', '--json']), 'lock')
      const state = await w.control('GET', '/v1/lockstate')
      assert.equal(state.json.locked, true)
      assert.equal(state.json.has_companion_unlock, true, 'readable while locked')
      assert.equal(ok(await runCli(w, ['companion', 'status', '--json']), 'status locked').unlock, true)

      const wrong = randomBytes(32).toString('base64url')
      refused(await runCli(w, ['unlock', '--companion', '--json'], { input: `${wrong}\n` }), 'another secret')
      assert.equal((await w.control('GET', '/v1/lockstate')).json.locked, true)
      ok(await runCli(w, ['unlock', '--companion', '--json'], { input: `${secret}\n` }), 'unlock')
      assert.equal((await w.control('GET', '/v1/lockstate')).json.locked, false)

      // Removing the companion key removes its unlock: the secret opens nothing.
      const rm = ok(await runCli(w, ['companion', 'remove', '--companion-challenge', '--json']), 'remove challenge')
      const rmProof = JSON.stringify({ challengeId: rm.challengeId, companionSignature: key.sign(rm.challenge) })
      ok(await runCli(w, ['companion', 'remove', '--presence-stdin', '--json'], { input: `${rmProof}\n` }), 'remove')
      assert.equal((await w.control('GET', '/v1/lockstate')).json.has_companion_unlock, false)
      ok(await runCli(w, ['lock', '--json']), 'lock')
      refused(await runCli(w, ['unlock', '--companion', '--json'], { input: `${secret}\n` }), 'removed')
      ok(await runCli(w, ['unlock', '--json'], { input: `${PASSPHRASE}\n` }), 'passphrase')
      assert.equal((await w.control('GET', '/v1/lockstate')).json.locked, false)
    })
  })
}
