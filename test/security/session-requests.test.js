// An agent asking for a session, and a human answering.
//
// An agent cannot create a session: that is capability, and capability needs a
// human. It could not ask for one either, which left it at a dead end — while
// two error paths told it to call `vault_request_session`, a tool that did not
// exist. This is the other half of that.
//
// The properties that make it safe rather than a hole in the gate:
//   1. Asking creates nothing. No session, no token, no grant.
//   2. An agent cannot answer its own request.
//   3. What the human approves is what gets created, including their edits.
//   4. Approval supplies presence, never permission: every ceiling still binds.
//   5. The token is collected once.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { request as unixRequest } from 'node:http'
import { Vault } from '../../src/store/vault.js'
import { Daemon } from '../../src/daemon/server.js'

const PASS = 'correct horse battery staple'
let dir, vault, daemon, sock

const ctl = (method, path, body) => new Promise((resolve) => {
  const req = unixRequest({ socketPath: sock, path, method, headers: { 'content-type': 'application/json' } }, (res) => {
    const c = []
    res.on('data', (x) => c.push(x))
    res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(c).toString() || '{}') }))
  })
  req.on('error', () => resolve({ status: 0, body: {} }))
  req.end(body ? JSON.stringify(body) : undefined)
})

/** The human is at the keyboard. */
const present = async () => { assert.equal((await ctl('POST', '/v1/presence/window', { passphrase: PASS })).status, 200) }
const absent = () => { daemon.presenceGraceUntil = 0 }

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'av-sr-'))
  vault = Vault.create(dir, { factor: 'none' })
  vault.addCredential({
    slug: 'gh', kind: 'github', connector: { host: 'api.github.com' },
    fields: { token: 'ghp_SESSIONREQUEST00112233445566' },
    sites: { token: ['header:authorization:Bearer'] },
  })
  vault.setPassphrase(PASS)
  sock = join(dir, 'c.sock')
  daemon = await new Daemon(vault, { port: 0, socketPath: sock }).start()
})

after(async () => {
  if (daemon) await daemon.stop()
  rmSync(dir, { recursive: true, force: true })
})

test('asking for a session creates nothing at all', async () => {
  absent()
  const before = Object.keys(vault.db.sessions).length
  const res = await ctl('POST', '/v1/session-requests', {
    cred: 'gh', methods: ['GET'], paths: ['/user'], budget: 5, reason: 'to read the profile',
  })
  assert.equal(res.status, 200, JSON.stringify(res.body))
  assert.equal(res.body.state, 'pending')
  assert.ok(res.body.id.startsWith('sr_'))

  // Nothing exists yet. This is the whole point: asking is not getting.
  assert.equal(Object.keys(vault.db.sessions).length, before, 'a session was created by asking')
  assert.equal(res.body.token, undefined, 'a token was handed out without a human')
  assert.equal(JSON.stringify(res.body).includes('avs1.'), false)

  // And the agent's reason is carried as a claim, not as a fact.
  assert.equal(res.body.agent_reason_untrusted, 'to read the profile')
})

test('an agent cannot answer its own request', async () => {
  absent()
  const asked = await ctl('POST', '/v1/session-requests', { cred: 'gh', methods: ['GET'], paths: ['/user'] })
  const decided = await ctl('POST', '/v1/session-requests/decide', { id: asked.body.id, granted: true })
  assert.equal(decided.status, 401, `an agent approved itself: ${JSON.stringify(decided.body)}`)
  assert.equal(decided.body.code, 'AV_PRESENCE_REQUIRED')

  // And nothing was created on the way to refusing.
  const collect = await ctl('GET', `/v1/session-requests/collect?id=${asked.body.id}`)
  assert.equal(collect.body.state, 'pending')
})

test('a human approving gets a working session, collected exactly once', async () => {
  absent()
  const asked = await ctl('POST', '/v1/session-requests', {
    cred: 'gh', methods: ['GET'], paths: ['/user'], budget: 5, reason: 'reading the profile',
  })

  await present()
  const decided = await ctl('POST', '/v1/session-requests/decide', { id: asked.body.id, granted: true })
  assert.equal(decided.status, 200, JSON.stringify(decided.body))
  // Even the approval response carries no token: the agent collects it.
  assert.equal(JSON.stringify(decided.body).includes('avs1.'), false, 'the token leaked into the decision')

  absent()
  const got = await ctl('GET', `/v1/session-requests/collect?id=${asked.body.id}`)
  assert.equal(got.body.state, 'approved')
  assert.match(got.body.token, /^avs1\./)
  assert.match(got.body.placeholder, /^av1\./)
  assert.ok(vault.sessionByToken(got.body.token), 'the collected token must name a real session')

  // Once. A second collection must not hand out another live copy.
  const again = await ctl('GET', `/v1/session-requests/collect?id=${asked.body.id}`)
  assert.notEqual(again.body.token, got.body.token)
  assert.equal(again.body.state, 'collected')
})

test('what the human edits is what gets created', async () => {
  // The agent asks wide; the human narrows before approving. The session that
  // exists afterwards must be the human's version, not the agent's.
  absent()
  const asked = await ctl('POST', '/v1/session-requests', {
    cred: 'gh', methods: ['GET', 'POST', 'DELETE'], paths: ['/**'], budget: 1000,
  })

  await present()
  await ctl('POST', '/v1/session-requests/decide', {
    id: asked.body.id,
    granted: true,
    overrides: { methods: ['GET'], paths: ['/user'], budget: 3 },
  })
  absent()
  const got = await ctl('GET', `/v1/session-requests/collect?id=${asked.body.id}`)

  const session = vault.sessionByToken(got.body.token)
  const grant = vault.grantsForSession(session.id)[0]
  assert.deepEqual(grant.policy.methods, ['GET'], 'the agent got the methods it asked for, not the ones allowed')
  assert.deepEqual(grant.policy.paths, ['/user'])
  assert.equal(grant.policy.budget.limit, 3)
})

test('approval supplies a human, never permission', async () => {
  // A greedy proposal that a human approves still cannot exceed the
  // credential's own hosts. Approval is presence; the ceilings are policy.
  absent()
  const asked = await ctl('POST', '/v1/session-requests', {
    cred: 'gh', methods: ['GET'], paths: ['/**'],
  })
  await present()
  await ctl('POST', '/v1/session-requests/decide', {
    id: asked.body.id, granted: true, overrides: { hosts: ['evil.test'] },
  })
  absent()
  const got = await ctl('GET', `/v1/session-requests/collect?id=${asked.body.id}`)
  const session = vault.sessionByToken(got.body.token)
  const grant = vault.grantsForSession(session.id)[0]
  assert.ok(!grant.policy.hosts.includes('evil.test'),
    'a host outside the credential survived a human approval')
  assert.ok(grant.policy.hosts.some((h) => String(h).includes('github')),
    `expected the credential's own hosts, got ${JSON.stringify(grant.policy.hosts)}`)
})

test('a denial creates nothing and cannot be reversed by asking again', async () => {
  absent()
  const asked = await ctl('POST', '/v1/session-requests', { cred: 'gh', methods: ['GET'], paths: ['/user'] })
  await present()
  const denied = await ctl('POST', '/v1/session-requests/decide', { id: asked.body.id, granted: false })
  assert.equal(denied.status, 200)
  assert.equal(denied.body.state, 'denied')

  // Re-deciding a settled request is refused, so an agent cannot wait for a
  // presence window it did not earn and flip its own denial.
  const flipped = await ctl('POST', '/v1/session-requests/decide', { id: asked.body.id, granted: true })
  assert.equal(flipped.status, 403)
  absent()
  const collect = await ctl('GET', `/v1/session-requests/collect?id=${asked.body.id}`)
  assert.equal(collect.body.state, 'denied')
  assert.equal(collect.body.token, undefined)
})

test('an agent cannot flood out a request a human is reading', async () => {
  absent()
  let refused = 0
  for (let i = 0; i < 90; i++) {
    const r = await ctl('POST', '/v1/session-requests', { cred: 'gh', methods: ['GET'], paths: [`/u/${i}`] })
    if (r.status !== 200) { refused++; assert.match(r.body.detail, /too many/) }
  }
  assert.ok(refused > 0, '90 requests were all accepted; the store is unbounded')
  assert.ok(daemon.sessionRequests.pending().length <= 64)
})

test('every request and answer is in the audit log', async () => {
  const kinds = vault.audit.read({ limit: 400 }).map((r) => r.kind)
  for (const kind of ['session_request.opened', 'session_request.approved', 'session_request.denied', 'session_request.collected']) {
    assert.ok(kinds.includes(kind), `${kind} was never recorded`)
  }
  // The agent's stated reason is recorded as a claim, and no token is.
  const raw = JSON.stringify(vault.audit.read({ limit: 400 }))
  assert.ok(raw.includes('agent_reason_untrusted'))
  assert.ok(!raw.includes('avs1.'), 'a session token reached the audit log')
})
