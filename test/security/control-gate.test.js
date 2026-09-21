// Every mutating control-socket route, audited for whether it needs a human.
//
// The control socket is mode 0660 with a group ACL so the human's account can
// reach it — which means an agent running as that human can too. The passphrase
// gate is the only thing between the two. Three separate holes in it have been
// found by looking at one route at a time, so this file walks the whole surface
// and states, for each route, which side of the line it is on.
//
// The line: gate what WIDENS. What narrows can stay open, because an agent
// that locks the vault or denies its own request has not gained anything.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { request as unixRequest, createServer } from 'node:http'
import { Vault } from '../../src/store/vault.js'
import { Daemon } from '../../src/daemon/server.js'

const PASS = 'correct horse battery staple'
const SECRET = 'GATE-SECRET-00011122233344'
let dir, vault, daemon, sock, cred, session, token, placeholder, upstream, upPort, seen

const ctl = (method, path, body) => new Promise((resolve) => {
  const req = unixRequest({ socketPath: sock, path, method, headers: { 'content-type': 'application/json' } }, (res) => {
    const c = []
    res.on('data', (x) => c.push(x))
    res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(c).toString() || '{}') }))
  })
  req.on('error', () => resolve({ status: 0, body: {} }))
  req.end(body ? JSON.stringify(body) : undefined)
})

const gateway = (path, headers) => new Promise((resolve) => {
  const req = unixRequest({ host: '127.0.0.1', port: daemon.gatewayPort, path, headers }, (res) => {
    const c = []
    res.on('data', (x) => c.push(x))
    res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(c).toString() }))
  })
  req.on('error', (e) => resolve({ status: 0, text: e.message }))
  req.end()
})

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'av-gate-'))
  seen = []
  upstream = createServer((req, res) => { seen.push(req.headers.authorization); res.end('{}') })
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r))
  upPort = upstream.address().port

  vault = Vault.create(dir, { factor: 'none' })
  cred = vault.addCredential({
    slug: 'prod', kind: 'http', connector: { host: `127.0.0.1:${upPort}`, scheme: 'http' },
    fields: { token: SECRET }, sites: { token: ['header:authorization:Bearer'] },
  })
  const made = vault.createSession({ label: 'agent' })
  session = made.session
  token = made.token
  const grant = vault.createGrant({
    sessionId: session.id, credentialId: cred.id, fields: ['token'],
    // Every call needs a human. This is what a careful operator sets.
    policy: {
      hosts: ['127.0.0.1'], methods: ['GET', 'POST'], paths: ['/**'],
      budget: { unit: 'requests', limit: 20 }, approval: 'each',
    },
  })
  placeholder = vault.issuePlaceholder({ grantId: grant.id, field: 'token' }).placeholder
  vault.setPassphrase(PASS) // the gate is on

  sock = join(dir, 'c.sock')
  daemon = await new Daemon(vault, { port: 0, socketPath: sock }).start()
})

after(async () => {
  if (daemon) await daemon.stop()
  if (upstream) upstream.close()
  rmSync(dir, { recursive: true, force: true })
})

// ------------------------------------------------------------- the approval

test('an agent cannot approve its own held request', async () => {
  // The worst of the three: `approval: each` is what a careful operator sets,
  // and the agent simply approved itself and collected the credential.
  seen.length = 0
  const held = await gateway('/p/prod/x', { authorization: `Bearer ${placeholder}` })
  assert.equal(held.status, 202)
  const { approval_id: id, code } = JSON.parse(held.text)
  assert.equal(code, 'AV_APPROVAL_PENDING')

  const decided = await ctl('POST', '/v1/approvals', { id, granted: true })
  assert.equal(decided.status, 401, `self-approval must be refused: ${JSON.stringify(decided.body)}`)
  assert.equal(decided.body.code, 'AV_PRESENCE_REQUIRED')

  // And the retry still waits, rather than going through.
  const retried = await gateway('/p/prod/x', { authorization: `Bearer ${placeholder}` })
  assert.equal(retried.status, 202)
  assert.deepEqual(seen, [], 'the credential must not have reached the upstream')
})

test('denying is left open, because it only narrows', async () => {
  // An agent abandoning its own request gains nothing, and refusing to let it
  // would be gating something that fails safe.
  const held = await gateway('/p/prod/y', { authorization: `Bearer ${placeholder}` })
  const { approval_id: id } = JSON.parse(held.text)
  const denied = await ctl('POST', '/v1/approvals', { id, granted: false })
  assert.equal(denied.status, 200)
  assert.equal(denied.body.state, 'denied')
})

test('a human with a window can approve, so the gate is not a wall', async () => {
  seen.length = 0
  const held = await gateway('/p/prod/z', { authorization: `Bearer ${placeholder}` })
  const { approval_id: id } = JSON.parse(held.text)

  assert.equal((await ctl('POST', '/v1/presence/window', { passphrase: PASS })).status, 200)
  assert.equal((await ctl('POST', '/v1/approvals', { id, granted: true })).status, 200)

  const done = await gateway('/p/prod/z', { authorization: `Bearer ${placeholder}` })
  assert.equal(done.status, 200)
  assert.ok(seen.some((a) => String(a).includes(SECRET)), 'the approved request should go through')
  daemon.presenceGraceUntil = 0
})

// ------------------------------------------------------------- the listener

test('an agent cannot bind a new listener', async () => {
  // A listener widens what can reach this vault. On a network address that is
  // the whole LAN, which is not a change an agent gets to make.
  const res = await ctl('POST', '/v1/listeners', {
    id: 'agent-added', address: '0.0.0.0:7999', surfaces: ['gateway', 'mcp'], tls: { managed: true },
  })
  assert.equal(res.status, 401)
  assert.equal(res.body.code, 'AV_PRESENCE_REQUIRED')
  const listed = await ctl('GET', '/v1/listeners')
  assert.ok(!listed.body.some((l) => l.id === 'agent-added'), 'nothing should have been stored')
})

// ------------------------------------------------ the authenticator counter

test('the signature counter cannot be driven up to disable the gate', async () => {
  // A counter below what we stored means "cloned credential" and is refused
  // forever. Setting it to a huge number would therefore switch the presence
  // gate off permanently — a denial of service against the control that stops
  // an agent widening anything at all.
  await ctl('POST', '/v1/presence', { credentialId: 'x', publicKeySpki: 'y', signCount: 5 })
    .catch(() => {})
  vault.db.kv.webauthn = { credentialId: 'x', publicKeySpki: 'y', signCount: 5 }

  await ctl('PATCH', '/v1/presence', { signCount: 2_000_000_000 })
  assert.equal(vault.db.kv.webauthn.signCount, 5, 'an absurd jump must be ignored')

  await ctl('PATCH', '/v1/presence', { signCount: 3 })
  assert.equal(vault.db.kv.webauthn.signCount, 5, 'going backwards must be ignored')

  await ctl('PATCH', '/v1/presence', { signCount: 6 })
  assert.equal(vault.db.kv.webauthn.signCount, 6, 'a normal step must still be recorded')
  delete vault.db.kv.webauthn
})

// ------------------------------------------------------------ certificates

test('an agent cannot force a new certificate and break existing trust', async () => {
  const first = await ctl('POST', '/v1/tls/ensure', {})
  assert.equal(first.status, 200, 'creating the first certificate is not gated')

  const forced = await ctl('POST', '/v1/tls/ensure', { force: true })
  assert.equal(forced.status, 401, 'replacing a working certificate needs a human')
  assert.equal(forced.body.code, 'AV_PRESENCE_REQUIRED')

  const after = await ctl('POST', '/v1/tls/ensure', {})
  assert.equal(after.body.fingerprint, first.body.fingerprint, 'the certificate must be unchanged')
})

// -------------------------------------------------------- the whole surface

test('no mutating control route widens capability without a human', async () => {
  // A standing inventory. When a route is added, it lands in one of these two
  // lists deliberately rather than defaulting to open, which is how the last
  // three holes got in.
  const widening = [
    ['POST', '/v1/credentials', { slug: 'x', kind: 'http', value: 'v' }],
    ['DELETE', '/v1/credentials?slug=prod', null],
    ['POST', '/v1/sessions', { cred: 'prod' }],
    ['POST', '/v1/placeholders', { cred: 'prod' }],
    ['POST', '/v1/approvals', { id: 'whatever', granted: true }],
    ['POST', '/v1/listeners', { id: 'n', address: '127.0.0.1:7998', surfaces: ['mcp'] }],
    ['POST', '/v1/presence', { credentialId: 'c', publicKeySpki: 'k' }],
  ]
  for (const [method, path, body] of widening) {
    const res = await ctl(method, path, body)
    assert.equal(res.status, 401, `${method} ${path} answered ${res.status}, not a presence refusal`)
    assert.equal(res.body.code, 'AV_PRESENCE_REQUIRED', `${method} ${path}`)
  }

  // Reads never need a human: the unlock screen depends on them.
  for (const path of ['/v1/status', '/v1/lockstate', '/v1/credentials', '/v1/sessions', '/v1/listeners', '/v1/approvals']) {
    assert.equal((await ctl('GET', path)).status, 200, `GET ${path} should stay open`)
  }
})

// ------------------------------------------------- the factors, and lockout

test('an enrolled authenticator counts as a human factor on its own', async () => {
  // The gate used to ask only "is there a passphrase?". Anyone who set up
  // Touch ID confirmation in the UI and nothing else therefore had a wide open
  // control socket — the exact opposite of what they had just configured.
  const d2 = mkdtempSync(join(tmpdir(), 'av-fac-'))
  const v2 = Vault.create(d2, { factor: 'none' })
  v2.addCredential({
    slug: 'prod', kind: 'http', connector: { host: 'api.example.com', scheme: 'https' },
    fields: { token: 'FACTOR-SECRET-0001112' }, sites: { token: ['header:authorization:Bearer'] },
  })
  const s2 = join(d2, 'c.sock')
  const dm = await new Daemon(v2, { port: 0, socketPath: s2 }).start()
  const call = (m, p, b) => new Promise((resolve) => {
    const req = unixRequest({ socketPath: s2, path: p, method: m, headers: { 'content-type': 'application/json' } }, (res) => {
      const c = []
      res.on('data', (x) => c.push(x))
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(c).toString() || '{}') }))
    })
    req.on('error', () => resolve({ status: 0, body: {} }))
    req.end(b ? JSON.stringify(b) : undefined)
  })
  try {
    // No factor at all: open, and audited as such. That is documented.
    assert.equal((await call('POST', '/v1/sessions', { cred: 'prod' })).status, 200)

    // Enrol a confirmation authenticator, still with no passphrase.
    v2.db.kv.webauthn = { credentialId: 'c', publicKeySpki: 'k', signCount: 0 }
    v2.save()

    const refused = await call('POST', '/v1/sessions', { cred: 'prod' })
    assert.equal(refused.status, 401, 'an enrolled authenticator must gate the socket')
    assert.equal(refused.body.code, 'AV_PRESENCE_REQUIRED')
    // And it must not tell the caller to confirm a passphrase it does not have.
    assert.deepEqual(refused.body.factors, ['authenticator'])
    assert.match(refused.body.hint, /web UI/)
  } finally {
    await dm.stop()
    rmSync(d2, { recursive: true, force: true })
  }
})

test('an agent cannot set the first passphrase and lock the owner out', async () => {
  // Setting the first passphrase drops the 'none' wrap, so afterwards only
  // whoever chose the phrase can open the vault. On a vault whose owner has
  // enrolled anything at all, that is theirs to do, not an agent's.
  const d3 = mkdtempSync(join(tmpdir(), 'av-ransom-'))
  const v3 = Vault.create(d3, { factor: 'none' })
  v3.db.kv.webauthn = { credentialId: 'c', publicKeySpki: 'k', signCount: 0 }
  v3.save()
  const s3 = join(d3, 'c.sock')
  const dm = await new Daemon(v3, { port: 0, socketPath: s3 }).start()
  const call = (m, p, b) => new Promise((resolve) => {
    const req = unixRequest({ socketPath: s3, path: p, method: m, headers: { 'content-type': 'application/json' } }, (res) => {
      const c = []
      res.on('data', (x) => c.push(x))
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(c).toString() || '{}') }))
    })
    req.on('error', () => resolve({ status: 0, body: {} }))
    req.end(b ? JSON.stringify(b) : undefined)
  })
  try {
    const res = await call('POST', '/v1/passphrase', { passphrase: 'agent-chosen-ransom-phrase' })
    assert.equal(res.status, 401, 'setting the first passphrase must need the human')
    assert.equal(res.body.code, 'AV_PRESENCE_REQUIRED')

    // The owner can still open their own vault.
    v3.lock()
    v3.unlockWith({})
    assert.equal(v3.locked, false, 'the owner must not have been locked out')
  } finally {
    await dm.stop()
    rmSync(d3, { recursive: true, force: true })
  }
})

test('the CLI names the factor that exists, not the one it expects', () => {
  // Checking the terminal before checking which factors exist meant a vault
  // whose only factor is an authenticator answered "needs your passphrase",
  // naming a secret that does not exist. The order matters more than it looks:
  // one of these messages sends the reader somewhere useful and the other
  // sends them looking for a passphrase they never set.
  const cli = readFileSync(new URL('../../src/cli/index.js', import.meta.url), 'utf8')
  const factorsAt = cli.indexOf("const factors = e.problem?.factors")
  const ttyAt = cli.indexOf('!process.stdin.isTTY', factorsAt - 2000)
  assert.ok(factorsAt > 0, 'the presence handler should consult the offered factors')
  assert.ok(factorsAt < cli.indexOf('!process.stdin.isTTY', factorsAt),
    'the factor check must come before the terminal check')
  assert.match(cli.slice(factorsAt, factorsAt + 600), /agent-vault ui/,
    'and point at the UI when only an authenticator can satisfy it')
  void ttyAt
})
