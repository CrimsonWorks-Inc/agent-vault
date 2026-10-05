// The web UI end to end: session claiming, the read/write split, and the
// presence gate as the server actually wires it.
//
// The adversary modelled here is an agent that has complete control of the
// page: it holds the cookie, it can set any header, and it can call the API
// directly without touching the DOM. It should be able to read metadata and
// change nothing.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, readFileSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { generateKeyPairSync, createHash, sign as cryptoSign, randomBytes } from 'node:crypto'
import { Vault } from '../../src/store/vault.js'
import { Daemon } from '../../src/daemon/server.js'
import { UiServer } from '../../src/ui/server.js'
import { operationFor } from '../../src/ui/webauthn.js'

const PASSPHRASE = 'ui-test-passphrase'
const SECRET = 'ghp_UITEST00112233445566778899aabbccddee'
let dir, vault, daemon, ui, cookie, origin

// --- the same synthetic authenticator the webauthn tests use ---------------
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

const api = (method, path, body, headers = {}) => fetch(`${origin}/api/${path}`, {
  method,
  headers: { 'x-av-ui': '1', cookie, 'content-type': 'application/json', ...headers },
  body: body ? JSON.stringify(body) : undefined,
})

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'av-ui-'))
  vault = Vault.create(dir, { factor: 'none' })
  const cred = vault.addCredential({
    slug: 'demo', kind: 'http', connector: { host: 'api.example.com', scheme: 'https' },
    fields: { token: SECRET }, sites: { token: ['header:authorization:Bearer'] },
  })
  const s = vault.createSession({ label: 'ui', policy: {} })
  vault.createGrant({
    sessionId: s.session.id, credentialId: cred.id, fields: ['token'],
    policy: { hosts: ['api.example.com'], methods: ['GET'], paths: ['/**'], budget: { unit: 'requests', limit: 10 } },
  })
  // A passphrase first, because enrolling an authenticator now requires one.
  // Without that ordering an agent on a fresh vault could enrol a key of its
  // own, become the only party able to satisfy the presence gate, and leave
  // the owner permanently unable to set a passphrase — which is itself gated,
  // and would by then need the agent's authenticator.
  vault.setPassphrase(PASSPHRASE)
  daemon = await new Daemon(vault, { port: 0, socketPath: join(dir, 'c.sock') }).start()
  // The human is present: this is what the CLI's passphrase prompt opens.
  daemon.presenceGraceUntil = Date.now() + 60_000
  ui = await new UiServer(join(dir, 'c.sock'), { port: 0 }).start()
  origin = ui.origin

  // Claim the session the way a browser does.
  const res = await fetch(ui.url, { redirect: 'manual' })
  cookie = res.headers.get('set-cookie').split(';')[0]
})

after(async () => {
  if (ui) await ui.stop()
  if (daemon) await daemon.stop()
  rmSync(dir, { recursive: true, force: true })
})

// ------------------------------------------------------------ session claiming

test('the relying party id is a domain, not an IP literal', async () => {
  // An IP is not a registrable domain, so a browser refuses the ceremony with
  // "invalid domain" and no authenticator can ever be enrolled.
  const state = await (await api('GET', 'presence/state')).json()
  assert.equal(state.rpId, 'localhost')
  assert.ok(!/^\d+\.\d+\.\d+\.\d+$/.test(state.rpId), 'an IP literal cannot be a relying party id')
  assert.match(state.origin, /^http:\/\/localhost:\d+$/)
})

test('arriving by IP is redirected to the domain the authenticator accepts', async () => {
  const res = await fetch(`http://127.0.0.1:${new URL(origin).port}/`, { redirect: 'manual' })
  assert.equal(res.status, 302)
  assert.match(res.headers.get('location'), /^http:\/\/localhost:\d+\//)
})

test('the launch link works exactly once', async () => {
  const second = await fetch(ui.url, { redirect: 'manual' })
  assert.equal(second.status, 409)
  assert.match(await second.text(), /already used/)
})

test('without the session cookie the API answers nothing', async () => {
  const res = await fetch(`${origin}/api/credentials`, { headers: { 'x-av-ui': '1' } })
  assert.equal(res.status, 401)
})

test('a cross-origin caller is refused', async () => {
  const res = await api('GET', 'credentials', null, { origin: 'https://evil.test' })
  assert.equal(res.status, 403)
})

test('a request without the custom header is refused, which stops a form post', async () => {
  const res = await fetch(`${origin}/api/lock`, { method: 'POST', headers: { cookie } })
  assert.equal(res.status, 403)
})

// -------------------------------------------------------- reads reveal nothing

test('the credential list carries no value, in any field', async () => {
  const creds = await (await api('GET', 'credentials')).json()
  const asText = JSON.stringify(creds)
  assert.ok(!asText.includes(SECRET), 'a credential value reached the page')
  assert.equal(creds[0].fields[0].value, undefined)
  assert.ok(creds[0].fields[0].fp8, 'a fingerprint stands in for the value')
  // The page needs the injection site to show where a placeholder may go.
  assert.deepEqual(creds[0].fields[0].sites, ['header:authorization:Bearer'])
})

test('there is no endpoint that returns a secret at all', async () => {
  for (const path of ['credentials/demo', 'secrets', 'reveal', 'credentials/demo/value']) {
    const res = await api('GET', path)
    assert.ok(res.status >= 400, `${path} answered ${res.status}`)
  }
})

// -------------------------------------------------------------------- docs

test('the docs context describes this install and carries no secret', async () => {
  const ctx = await (await api('GET', 'docs/context')).json()
  assert.ok(ctx.gateway_port > 0, 'the docs need the real port to print real commands')
  assert.match(ctx.mcp_url, /\/mcp$/)
  assert.ok(ctx.cli, 'the docs need to know how the reader invokes the CLI')
  assert.deepEqual(ctx.cred_slugs, ['demo'], 'slug names make the examples the reader’s own')

  const asText = JSON.stringify(ctx)
  assert.ok(!asText.includes(SECRET), 'a credential value reached the docs page')
  // A session token here would be a capability handed to whoever reads the page.
  assert.ok(!/avs1\.|av1\./.test(asText), 'the docs context must carry no token or placeholder')
})

test('the docs page is reachable without changing anything', async () => {
  // Reading the docs is a read. It must not be in the gated set, and it must
  // not need an enrolled authenticator.
  assert.ok(!UiServer.GATED.has('GET docs/context'))
  assert.equal((await api('GET', 'docs/context')).status, 200)
})

// ------------------------------------------------------------- the gate itself

test('before enrollment, every mutating call is refused', async () => {
  for (const [method, path, body] of [
    ['POST', 'lock', {}],
    ['POST', 'credentials', { slug: 'x', kind: 'http', value: 'y' }],
    ['POST', 'sessions', { cred: 'demo' }],
    ['DELETE', 'credentials?slug=demo', null],
    // Deciding several at once is a mutating call like any other. A bulk
    // action that skipped the gate would be the cheapest way to approve
    // everything in the queue without a human anywhere near it.
    ['POST', 'pending/decide-many', { decisions: [{ id: 'sr_x', kind: 'session', granted: true }] }],
  ]) {
    const res = await api(method, path, body)
    assert.equal(res.status, 412, `${method} ${path} was not refused`)
    assert.match((await res.json()).error, /no authenticator/)
  }
})

test('a forged presence payload is refused', async () => {
  const res = await api('POST', 'lock', {
    presence: { challengeId: 'made-up', credentialId: 'made-up', authenticatorData: 'AA', clientDataJSON: 'e30', signature: 'AA' },
  })
  assert.ok(res.status >= 400)
})

test('enrollment registers the authenticator', async () => {
  const auth = makeAuthenticator()
  const begin = await (await api('POST', 'presence/enroll/begin')).json()
  const finish = await api('POST', 'presence/enroll/finish', auth.register(begin.challenge))
  assert.equal(finish.status, 200)
  const state = await (await api('GET', 'presence/state')).json()
  assert.equal(state.enrolled, true)
  globalThis.__auth = auth
})

test('a second enrollment is refused, so an agent cannot add its own key', async () => {
  const res = await api('POST', 'presence/enroll/begin')
  assert.equal(res.status, 409)
})

test('after enrollment, a mutating call still fails without a signature', async () => {
  const res = await api('POST', 'lock', {})
  assert.equal(res.status, 401)
  assert.match((await res.json()).error, /needs a fresh authenticator signature/)
})

test('a signature for the wrong operation is refused', async () => {
  const auth = globalThis.__auth
  // Sign for a harmless operation, then try to spend it on a different one.
  const ch = await (await api('POST', 'presence/challenge', { operation: { op: 'session.revoke', sid: 'harmless' } })).json()
  const proof = { challengeId: ch.challengeId, ...auth.assert(ch.challenge) }
  const res = await api('POST', 'lock', { presence: proof })
  assert.equal(res.status, 409)
  assert.match((await res.json()).error, /different operation/)
})

test('a valid signature for the right operation is accepted exactly once', async () => {
  const auth = globalThis.__auth
  const ch = await (await api('POST', 'presence/challenge', { operation: { op: 'vault.lock' } })).json()
  const proof = { challengeId: ch.challengeId, ...auth.assert(ch.challenge) }

  const first = await api('POST', 'lock', { presence: proof })
  assert.equal(first.status, 200, 'a correct proof must work')

  // Replaying the same proof must not work: the challenge is consumed.
  const replay = await api('POST', 'lock', { presence: proof })
  assert.equal(replay.status, 401)
  assert.match((await replay.json()).error, /already-used/)
})

test('a session created here reaches the store every local client reads', async () => {
  // The vault keeps only token_hash, so a token's plaintext exists exactly
  // once — at creation — and nothing can ever hand it back. That makes
  // whoever created the session the only thing able to record it.
  //
  // The CLI recorded its sessions and this page recorded nothing, so a session
  // made here lived in the vault and on the screen and nowhere else, while the
  // MCP stdio bridge went on reading the CLI's copy. On a machine where the
  // CLI had made one days earlier that was not "no session" but confidently
  // the wrong one: an expired token, used with conviction, and a client that
  // hung for thirty seconds rather than saying so.
  // An earlier test locked the vault; creating a session needs it open.
  if (vault.locked) vault.unlockWith({ passphrase: PASSPHRASE })

  const auth = globalThis.__auth
  const operation = { op: 'session.create', cred: 'demo', methods: ['GET'], paths: ['/**'] }
  const ch = await (await api('POST', 'presence/challenge', { operation })).json()
  const proof = { challengeId: ch.challengeId, ...auth.assert(ch.challenge) }

  const res = await api('POST', 'sessions', { ...operation, presence: proof })
  const created = await res.json()
  assert.equal(res.status, 200, `the UI could not create a session: ${JSON.stringify(created)}`)
  assert.ok(created.token, 'the page must return a token to show the human')

  const state = JSON.parse(readFileSync(join(dir, 'cli-state.json'), 'utf8'))
  assert.equal(state.token, created.token,
    'a session created in the UI did not reach the store the CLI and the bridge read')
  assert.equal(state.session_id, created.session_id)
  assert.equal(statSync(join(dir, 'cli-state.json')).mode & 0o077, 0,
    'the state file must not be readable by other accounts')
})

test('the enrollment is recorded in the audit log', () => {
  // The test above locked the vault, which drops the audit key along with the
  // master key it came from. Reading the log means unlocking first — with the
  // passphrase, since this vault has one now.
  vault.unlockWith({ passphrase: PASSPHRASE })
  const kinds = vault.audit.read({ limit: 100 }).map((r) => r.kind)
  assert.ok(kinds.includes('presence.factor_added'))
})

// The page must not be able to settle a batch by leaving the proof out.
test('a batch with no signature is refused, like a single decision', async () => {
  const res = await api('POST', 'pending/decide-many', {
    decisions: [{ id: 'sr_whatever', kind: 'session', granted: true }],
  })
  assert.notEqual(res.status, 200, 'an unsigned batch was accepted')
})

// What the page signs and what this process verifies must be the same list.
test('the operation bound for a batch is the list exactly as it was sent', async () => {
  const decisions = [
    { id: 'sr_b', kind: 'session', granted: true },
    { id: 'sr_a', kind: 'request', granted: false },
  ]
  // Built through the server's own builder, over the body the page sends -
  // the same call #requirePresence makes before it compares.
  const op = operationFor('pending.decide_many', { decisions })
  assert.equal(op.op, 'pending.decide_many')
  // Verbatim: order kept, nothing normalised away. Normalising on one side
  // only would let the signature and the execution describe different sets.
  assert.deepEqual(op.decisions, decisions)
  assert.equal(op.decisions[0].id, 'sr_b', 'the list was reordered on the way to being signed')
})
