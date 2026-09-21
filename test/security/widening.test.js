// The daemon's widening gate, and the UI's fingerprint as a proof it accepts.
//
// There are two human factors in this system: a passphrase on the control
// socket (the CLI's) and a WebAuthn assertion from the web UI. They used to be
// unaware of each other, so a vault with a passphrase refused every change made
// from the UI — the human had already touched the sensor, and was then told to
// "confirm your passphrase" with nowhere to type it.
//
// The fix is not for the UI to assert that a human was present. That process
// runs as the human's account, which is exactly the account an agent has. The
// daemon mints the challenge and checks the signature itself.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { request as unixRequest } from 'node:http'
import { generateKeyPairSync, createHash, sign as cryptoSign, randomBytes } from 'node:crypto'
import { operationFor } from '../../src/ui/webauthn.js'
import { Vault } from '../../src/store/vault.js'
import { Daemon } from '../../src/daemon/server.js'
import { UiServer } from '../../src/ui/server.js'

const PASSPHRASE = 'correct horse battery staple'
let dir, vault, daemon, ui, sock, cookie, origin

// --- a synthetic platform authenticator ------------------------------------
function cborUint(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n])
  if (n < 256) return Buffer.from([(major << 5) | 24, n])
  const b = Buffer.alloc(3); b[0] = (major << 5) | 25; b.writeUInt16BE(n, 1); return b
}
function cbor(v) {
  if (typeof v === 'number') return v >= 0 ? cborUint(0, v) : cborUint(1, -1 - v)
  if (typeof v === 'string') return Buffer.concat([cborUint(3, Buffer.byteLength(v)), Buffer.from(v)])
  if (Buffer.isBuffer(v)) return Buffer.concat([cborUint(2, v.length), v])
  if (v instanceof Map) return Buffer.concat([cborUint(5, v.size), ...[...v].map(([k, x]) => Buffer.concat([cbor(k), cbor(x)]))])
  throw new Error('unsupported')
}
function makeAuthenticator() {
  const credentialId = randomBytes(16)
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const raw = publicKey.export({ format: 'der', type: 'spki' })
  const point = raw.subarray(raw.length - 65)
  const cose = new Map([[1, 2], [3, -7], [-1, 1], [-2, point.subarray(1, 33)], [-3, point.subarray(33, 65)]])
  const rpIdHash = createHash('sha256').update('localhost').digest()
  const head = (flags) => Buffer.concat([rpIdHash, Buffer.from([flags]), Buffer.alloc(4)])
  return {
    register(challenge) {
      const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge, origin }))
      const len = Buffer.alloc(2); len.writeUInt16BE(credentialId.length)
      const authData = Buffer.concat([head(0x45), Buffer.alloc(16), len, credentialId, cbor(cose)])
      const att = new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]])
      return { attestationObject: cbor(att).toString('base64url'), clientDataJSON: clientDataJSON.toString('base64url') }
    },
    assert(challenge) {
      const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin }))
      const ad = head(0x05)
      const signature = cryptoSign('sha256', Buffer.concat([ad, createHash('sha256').update(clientDataJSON).digest()]), privateKey)
      return {
        credentialId: credentialId.toString('base64url'),
        authenticatorData: ad.toString('base64url'),
        clientDataJSON: clientDataJSON.toString('base64url'),
        signature: signature.toString('base64url'),
      }
    },
  }
}

const api = (method, path, body) => fetch(`${origin}/api/${path}`, {
  method,
  headers: { 'x-av-ui': '1', cookie, 'content-type': 'application/json' },
  body: body ? JSON.stringify(body) : undefined,
})

const control = (method, path, body) => new Promise((resolve, reject) => {
  const req = unixRequest({ socketPath: sock, path, method, headers: { 'content-type': 'application/json' } }, (res) => {
    const chunks = []
    res.on('data', (c) => chunks.push(c))
    res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString() || '{}') }))
  })
  req.on('error', reject)
  req.end(body ? JSON.stringify(body) : undefined)
})

let auth

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'av-widen-'))
  vault = Vault.create(dir, { factor: 'none' })
  vault.addCredential({
    slug: 'demo', kind: 'http', connector: { host: 'api.example.com', scheme: 'https' },
    fields: { token: 'ghp_WIDENTEST00112233445566778899aa' }, sites: { token: ['header:authorization:Bearer'] },
  })
  // A passphrase is what turns the widening gate on. This is the configuration
  // the bug appeared in: a passphrase set, and changes attempted from the UI.
  vault.setPassphrase(PASSPHRASE)

  sock = join(dir, 'c.sock')
  daemon = await new Daemon(vault, { port: 0, socketPath: sock }).start()
  ui = await new UiServer(sock, { port: 0 }).start()
  origin = ui.origin
  cookie = (await fetch(ui.url, { redirect: 'manual' })).headers.get('set-cookie').split(';')[0]

  auth = makeAuthenticator()
  // Enrolling is passphrase-gated, which is what the page now asks for once.
  await api('POST', 'presence/window', { passphrase: PASSPHRASE })
  const begin = await (await api('POST', 'presence/enroll/begin')).json()
  await api('POST', 'presence/enroll/finish', auth.register(begin.challenge))
  // Close the window again: every test below is about the fingerprint.
  daemon.presenceGraceUntil = 0
})

after(async () => {
  if (ui) await ui.stop()
  if (daemon) await daemon.stop()
  rmSync(dir, { recursive: true, force: true })
})

/** Do what the page does: ask for a challenge, sign it, send it with the call. */
async function withPresence(operation, send) {
  const ch = await (await api('POST', 'presence/challenge', { operation })).json()
  return send({ challengeId: ch.challengeId, ...auth.assert(ch.challenge) })
}

test('the passphrase gate is on, so an unsigned call is refused', async () => {
  const res = await control('POST', '/v1/sessions', { cred: 'demo', methods: ['GET'], paths: ['/**'] })
  assert.equal(res.status, 401)
  assert.equal(res.body.code, 'AV_PRESENCE_REQUIRED')
})

test('creating a session from the UI works with one fingerprint', async () => {
  // The bug: this answered "session create needs a human: confirm your
  // passphrase" even though the human had just confirmed with Touch ID.
  const body = { cred: 'demo', methods: ['GET'], paths: ['/**'] }
  const res = await withPresence(
    operationFor('session.create', body),
    (presence) => api('POST', 'sessions', { ...body, presence }),
  )
  const created = await res.json()
  assert.equal(res.status, 200, JSON.stringify(created))
  assert.ok(created.session_id, 'a session should come back')

  // And it must come back usable. A session made in the UI used to withhold
  // the token and the placeholder, neither of which can be recovered from
  // anywhere else, so it could not be handed to an agent at all.
  assert.ok(created.token, 'the agent needs the session token')
  assert.ok(created.placeholder, 'and the placeholder')
  assert.match(created.base_url, /\/p\/demo$/)
  assert.ok(created.usage?.length, 'and a statement of where the placeholder goes')
  assert.ok(!JSON.stringify(created).includes('ghp_WIDENTEST'), 'but never the credential itself')
})

test('the credential list says where a placeholder may go', async () => {
  // The page builds its example request from this; a wrong site would produce
  // an example that is refused with AV_BAD_LOCATION.
  const { body: creds } = await control('GET', '/v1/credentials')
  const demo = creds.find((c) => c.slug === 'demo')
  assert.deepEqual(demo.fields[0].sites, ['header:authorization:Bearer'])
  assert.ok(!JSON.stringify(creds).includes('ghp_WIDENTEST'))
})

test('adding a credential from the UI works the same way', async () => {
  const body = { slug: 'second', kind: 'http', host: 'api.other.com', value: 'sk-test-000111222333444' }
  const res = await withPresence(
    operationFor('cred.add', body),
    (presence) => api('POST', 'credentials', { ...body, presence }),
  )
  assert.equal(res.status, 200, JSON.stringify(await res.json()))
  assert.ok(vault.findCredential('second'))
})

test('removing a credential from the UI works, signature and all', async () => {
  // This one is structurally different: the proof rides in the body of a
  // DELETE, which is easy to drop by accident.
  const res = await withPresence(
    operationFor('cred.remove', { slug: 'second' }),
    (presence) => api('DELETE', 'credentials?slug=second', { presence }),
  )
  assert.equal(res.status, 200, JSON.stringify(await res.json()))
  assert.ok(!vault.findCredential('second'), 'the credential should be gone')
})

test('a signature for one operation cannot authorise another', async () => {
  // The phishing case: the page shows a harmless action, the human touches the
  // sensor, and something else is submitted. The daemon compares the signed
  // operation against the call it actually received, so the swap is caught
  // even if the UI process is the one doing the lying.
  const ch = await (await api('POST', 'presence/challenge', {
    operation: operationFor('session.create', { cred: 'demo', methods: ['GET'], paths: ['/**'] }),
  })).json()
  const presence = { challengeId: ch.challengeId, ...auth.assert(ch.challenge) }

  const res = await control('POST', '/v1/sessions', {
    cred: 'demo', methods: ['GET', 'POST', 'DELETE'], paths: ['/**'], presence,
  })
  assert.equal(res.status, 401, 'a widened method list must not ride on that signature')
  assert.equal(res.body.code, 'AV_PRESENCE_REQUIRED')
})

test('a signature is good for exactly one call', async () => {
  const operation = operationFor('session.create', { cred: 'demo', methods: ['GET'], paths: ['/**'] })
  const ch = await (await api('POST', 'presence/challenge', { operation })).json()
  const presence = { challengeId: ch.challengeId, ...auth.assert(ch.challenge) }
  const body = { cred: 'demo', methods: ['GET'], paths: ['/**'], presence }

  assert.equal((await control('POST', '/v1/sessions', body)).status, 200)
  const replay = await control('POST', '/v1/sessions', body)
  assert.equal(replay.status, 401, 'the challenge must be consumed')
})

test('a challenge the daemon never minted proves nothing', async () => {
  // An agent that reached the socket can invent a challenge id and sign its own
  // bytes. Neither helps: the daemon only honours ids it issued.
  const presence = {
    challengeId: randomBytes(12).toString('base64url'),
    ...auth.assert(Buffer.from(randomBytes(32)).toString('base64url')),
  }
  const res = await control('POST', '/v1/sessions', { cred: 'demo', methods: ['GET'], paths: ['/**'], presence })
  assert.equal(res.status, 401)
})

test('a key the daemon never enrolled proves nothing', async () => {
  const stranger = makeAuthenticator()
  const operation = operationFor('session.create', { cred: 'demo', methods: ['GET'], paths: ['/**'] })
  const ch = await (await api('POST', 'presence/challenge', { operation })).json()
  const presence = { challengeId: ch.challengeId, ...stranger.assert(ch.challenge) }

  const res = await control('POST', '/v1/sessions', { cred: 'demo', methods: ['GET'], paths: ['/**'], presence })
  assert.equal(res.status, 401, 'only the enrolled credential counts')
})

test('an agent at the socket cannot enrol its own key and sign for itself', async () => {
  // Without this, the whole gate is circular: reach the socket, install your
  // own authenticator, and then authorise every change with it. Enrolling is
  // passphrase-only for exactly that reason.
  daemon.presenceGraceUntil = 0
  const mine = makeAuthenticator()
  const begin = await (await api('POST', 'presence/enroll/begin')).json()
  const registered = mine.register(begin.challenge)

  const res = await control('POST', '/v1/presence', {
    credentialId: 'aGVsbG8', publicKeySpki: 'x', signCount: 0, attestation: registered,
  })
  assert.equal(res.status, 401, 'enrolling must need the passphrase')
  assert.equal(res.body.code, 'AV_PRESENCE_REQUIRED')

  // And the credential that was there before is untouched.
  const still = await control('GET', '/v1/presence')
  assert.notEqual(still.body.credentialId, 'aGVsbG8')
})

test('the passphrase window still works, for the CLI', async () => {
  // The other factor must keep working; this is how the command line widens.
  const opened = await control('POST', '/v1/presence/window', { passphrase: PASSPHRASE })
  assert.equal(opened.status, 200)
  const res = await control('POST', '/v1/sessions', { cred: 'demo', methods: ['GET'], paths: ['/**'] })
  assert.equal(res.status, 200)
})

test('a wrong passphrase opens nothing', async () => {
  daemon.presenceGraceUntil = 0
  const res = await control('POST', '/v1/presence/window', { passphrase: 'not it' })
  assert.equal(res.status, 403)
  assert.equal(res.body.code, 'AV_PRESENCE_DENIED')
})

test('a signature does not authorise fields it never covered', async () => {
  // Found by an independent audit. The signed operation was a hand-listed
  // subset of the request, so a fingerprint given for "demo, GET, /**" also
  // authorised whatever the agent put in the fields nobody listed: the same
  // signature created a remote, auto-approving, billion-request, decade-long
  // session. Both the UI and the daemon derived the same incomplete operation,
  // so the daemon's independent check could not catch it either.
  const benign = { cred: 'demo', methods: ['GET'], paths: ['/**'] }
  const hostile = {
    ...benign,
    remote: true,              // reachable from the network
    approval: 'auto',          // no human on writes
    budget: 1_000_000_000,
    ttl_hours: 87_600,         // ten years
    uses: 1_000_000,
  }

  const ch = await (await api('POST', 'presence/challenge', {
    operation: operationFor('session.create', benign),
  })).json()
  const presence = { challengeId: ch.challengeId, ...auth.assert(ch.challenge) }

  const res = await control('POST', '/v1/sessions', { ...hostile, presence })
  assert.equal(res.status, 401, `a benign signature created: ${JSON.stringify(res.body).slice(0, 200)}`)
  assert.equal(res.body.code, 'AV_PRESENCE_REQUIRED')
})

test('the value stored under a cred.add signature is bound to it', async () => {
  // Only slug and kind were signed, so the same signature could store any
  // secret, at any host, with any injection sites.
  const intended = { slug: 'bound', kind: 'http', host: 'api.example.com', value: 'INTENDED-SECRET-0001' }
  const ch = await (await api('POST', 'presence/challenge', {
    operation: operationFor('cred.add', intended),
  })).json()
  const presence = { challengeId: ch.challengeId, ...auth.assert(ch.challenge) }

  const swapped = { ...intended, value: 'ATTACKER-SUBSTITUTED-VALUE-0002' }
  const res = await control('POST', '/v1/credentials', { ...swapped, presence })
  assert.equal(res.status, 401, 'a different value must not ride on that signature')
  assert.ok(!vault.findCredential('bound'), 'and nothing should have been stored')
})
