// The rules that only apply to a request arriving over the network.
//
// These were dead code until listeners actually bound: `req.listener` was
// permanently undefined, so every branch below was unreachable and had never
// executed once. Newly-live security code is exactly the code most likely to
// be wrong, so it gets tested before anyone relies on it.
//
// The pipeline is driven directly rather than through a bound socket, because
// making a request genuinely remote means binding a public port, and a test
// suite should not open one on the machine running it. Binding itself is
// covered in listener.test.js; these are the rules that binding switches on.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createServer } from 'node:http'
import { Vault } from '../../src/store/vault.js'
import { Pipeline } from '../../src/daemon/pipeline.js'

const SECRET = 'ghp_REMOTE00112233445566778899aab'
let dir, vault, pipeline, upstream, upPort, seen, cred, token, placeholder

const LOCAL = { id: 'local', kind: 'loopback', remote: false, advertise: [] }
const REMOTE = { id: 'lan', kind: 'tls', remote: true, advertise: [] }

const call = (headers, listener) => pipeline.handle({
  method: 'GET', path: `/p/${cred.slug}/x`, query: '',
  headers, body: null, listener,
})

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'av-remote-'))
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
  token = made.token
  const grant = vault.createGrant({
    sessionId: made.session.id, credentialId: cred.id, fields: ['token'],
    policy: {
      hosts: ['127.0.0.1'], methods: ['GET'], paths: ['/**'],
      budget: { unit: 'requests', limit: 100 }, approval: 'auto',
    },
  })
  placeholder = vault.issuePlaceholder({ grantId: grant.id, field: 'token' }).placeholder
  pipeline = new Pipeline(vault)
})

after(() => {
  if (upstream) upstream.close()
  rmSync(dir, { recursive: true, force: true })
})

test('on loopback a placeholder alone authenticates, which is the point', async () => {
  // This is what lets git, gh and SDK constructors work with no custom header.
  // The remote restriction below only means something if this works locally.
  seen = []
  const res = await call([['authorization', `Bearer ${placeholder}`]], LOCAL)
  assert.equal(res.status, 200)
  assert.equal(seen[0], `Bearer ${SECRET}`)
})

test('over the network a placeholder alone does not authenticate', async () => {
  // Across a network a placeholder in a URL or a proxy log would become a
  // bearer credential on its own. It has to be accompanied by the session
  // token, which is not something a log or a referer header leaks.
  seen = []
  const res = await call([['authorization', `Bearer ${placeholder}`]], REMOTE)
  assert.equal(res.status, 401, `remote carrier was accepted: ${res.body}`)
  const problem = JSON.parse(res.body)
  assert.equal(problem.code, 'AV_SESSION_REQUIRED')
  assert.equal(problem.rule, 'remote_carrier')
  assert.match(problem.hint, /session token/)
  assert.deepEqual(seen, [], 'nothing may reach the upstream')
})

test('over the network the same request works with the session token alongside', async () => {
  // The rule narrows how you authenticate, not what you may do. A remote
  // caller that holds the session token is still a legitimate caller.
  seen = []
  const res = await call([
    ['av-session', token],
    ['authorization', `Bearer ${placeholder}`],
  ], REMOTE)
  assert.equal(res.status, 200, `remote call with a token was refused: ${res.body}`)
  assert.equal(seen[0], `Bearer ${SECRET}`)
})

test('a listener serving a surface that may never leave the machine is refused', async () => {
  // The control API, the approver socket and the database proxies are not
  // networkable at any address. Refusing the whole entry rather than quietly
  // dropping the surface is deliberate: a misconfigured listener must be loud.
  for (const surface of ['control', 'approver', 'l4']) {
    assert.throws(
      () => vault.addListener({ id: `bad-${surface}`, address: '0.0.0.0:9999', surfaces: [surface] }),
      /AV_REMOTE_FORBIDDEN|never be bound/,
      `${surface} was allowed onto a network address`,
    )
  }
  // The same surfaces are fine on loopback.
  const ok = vault.addListener({ id: 'loopback-control', address: '127.0.0.1:9998', surfaces: ['control'] })
  assert.equal(ok.id, 'loopback-control')
  vault.removeListener('loopback-control')
})

test('a refused listener is recorded, not silently dropped', async () => {
  try { vault.addListener({ id: 'noisy', address: '0.0.0.0:9997', surfaces: ['control'] }) } catch { /* expected */ }
  const kinds = vault.audit.read({ limit: 40 }).map((r) => r.kind)
  assert.ok(kinds.includes('listen.refused'), `expected listen.refused, saw ${[...new Set(kinds)].join(', ')}`)
})

test('a remote session carries its own shorter ceiling', async () => {
  // A session created for a network caller expires sooner and idles out
  // faster than a local one, because losing one matters more.
  const local = vault.createSession({ label: 'local', remote: false })
  const remote = vault.createSession({ label: 'remote', remote: true })
  assert.equal(remote.session.remote, true)
  assert.ok(
    Date.parse(remote.session.max_expires_at) < Date.parse(local.session.max_expires_at),
    'a remote session should not be allowed to live as long as a local one',
  )
  assert.ok(
    remote.session.idle_timeout_ms < local.session.idle_timeout_ms,
    'a remote session should idle out sooner',
  )
})
