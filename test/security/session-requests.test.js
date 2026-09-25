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
import { mkdtempSync, rmSync, existsSync, readFileSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { request as unixRequest } from 'node:http'
import { Vault } from '../../src/store/vault.js'
import { Daemon } from '../../src/daemon/server.js'
import { collectApproved } from '../../src/pending.js'
import { rememberSession } from '../../src/client-state.js'

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

test('a request is audited on a vault that started locked, which is every real one', async () => {
  // The store used to be handed `vault.audit` at construction. A vault with a
  // passphrase comes up LOCKED and sets that to null until someone unlocks it,
  // so the store captured null and every write after was a silent no-op: an
  // agent asking for capability went unrecorded on exactly the vaults where
  // recording it matters. Locking sets it back to null too, so there is no
  // moment at which caching it is safe.
  //
  // The tests above missed it because their vault has no passphrase and so is
  // unlocked when the daemon is built. This one reproduces the real startup:
  // a locked vault, a daemon built against it, then a human unlocking.
  const d = mkdtempSync(join(tmpdir(), 'av-sr-locked-'))
  let daemon2
  try {
    const v = Vault.create(d, { factor: 'none' })
    v.addCredential({
      slug: 'gh', kind: 'github', connector: { host: 'api.github.com' },
      fields: { token: 'ghp_LOCKEDSTART0011223344556677' },
      sites: { token: ['header:authorization:Bearer'] },
    })
    v.setPassphrase(PASS)
    v.lock()

    // Exactly what the service does at boot.
    const reopened = Vault.open(d)
    reopened.startInRecordedState(null)
    assert.equal(reopened.locked, true, 'a passphrase vault must come up locked')
    assert.equal(reopened.audit, null, 'and with no audit handle, which is the trap')

    const s2 = join(d, 'c.sock')
    daemon2 = await new Daemon(reopened, { port: 0, socketPath: s2 }).start()
    const call = (method, path, body) => new Promise((resolve) => {
      const req = unixRequest({ socketPath: s2, path, method, headers: { 'content-type': 'application/json' } }, (res) => {
        const c = []
        res.on('data', (x) => c.push(x))
        res.on('end', () => resolve(JSON.parse(Buffer.concat(c).toString() || '{}')))
      })
      req.on('error', () => resolve({}))
      req.end(body ? JSON.stringify(body) : undefined)
    })

    // The human unlocks, which is when an audit handle appears.
    await call('POST', '/v1/unlock', { passphrase: PASS })
    assert.ok(reopened.audit, 'unlocking should give the vault an audit log')

    const asked = await call('POST', '/v1/session-requests', {
      cred: 'gh', methods: ['GET'], paths: ['/user'], reason: 'after an unlock',
    })
    assert.ok(asked.id, `the request should have opened: ${JSON.stringify(asked)}`)

    const kinds = reopened.audit.read({ limit: 50 }).map((r) => r.kind)
    assert.ok(kinds.includes('session_request.opened'),
      'an agent asked for capability and nothing recorded it')

    // And again across a lock. Caching the handle lazily instead of eagerly
    // survives the first half of this test and fails here: locking wipes the
    // audit key and unlocking builds a NEW log, so a handle cached at any point
    // is stale the moment the vault is locked. There is no safe moment to keep
    // one — it has to be read through the vault every time.
    await call('POST', '/v1/lock', {})
    assert.equal(reopened.audit, null, 'locking must drop the audit handle')
    await call('POST', '/v1/unlock', { passphrase: PASS })

    const second = await call('POST', '/v1/session-requests', {
      cred: 'gh', methods: ['GET'], paths: ['/repos'], reason: 'after a lock and unlock',
    })
    assert.ok(second.id, `the second request should have opened: ${JSON.stringify(second)}`)

    const after = reopened.audit.read({ limit: 50 })
    const opened = after.filter((r) => r.kind === 'session_request.opened')
    assert.equal(opened.length, 2,
      `both requests must be recorded; found ${opened.length}. A cached handle writes to a log with a wiped key.`)
    assert.equal(reopened.audit.verify().ok, true, 'and the chain must still verify')
  } finally {
    if (daemon2) await daemon2.stop()
    rmSync(d, { recursive: true, force: true })
  }
})

test('approving records the session where a running agent will find it', async () => {
  // The whole point of the flow: a human answers, and the agent can work. No
  // token pasted anywhere.
  //
  // The daemon cannot do this part. It runs as its own uid and the state file
  // belongs to the human — that is the boundary the design rests on — so
  // whichever client they approved with collects and records it. The MCP bridge
  // re-reads that file on every request, so this reaches an agent that is
  // already running, on its next call.
  const d = mkdtempSync(join(tmpdir(), 'av-sr-record-'))
  let daemon2
  try {
    const v = Vault.create(d, { factor: 'none' })
    v.addCredential({
      slug: 'gh', kind: 'github', connector: { host: 'api.github.com' },
      fields: { token: 'ghp_RECORDTEST001122334455667788' },
      sites: { token: ['header:authorization:Bearer'] },
    })
    const s2 = join(d, 'c.sock')
    const statePath = join(d, 'cli-state.json')
    daemon2 = await new Daemon(v, { port: 0, socketPath: s2 }).start()
    const call = (method, path, body) => new Promise((resolve) => {
      const req = unixRequest({ socketPath: s2, path, method, headers: { 'content-type': 'application/json' } }, (res) => {
        const c = []
        res.on('data', (x) => c.push(x))
        res.on('end', () => resolve(JSON.parse(Buffer.concat(c).toString() || '{}')))
      })
      req.on('error', () => resolve({}))
      req.end(body ? JSON.stringify(body) : undefined)
    })

    const asked = await call('POST', '/v1/session-requests', {
      cred: 'gh', methods: ['GET'], paths: ['/user'], reason: 'to be recorded',
    })

    // Nothing recorded yet: asking is not getting, and it is not recording either.
    assert.equal(existsSync(statePath), false, 'asking wrote state')

    await call('POST', '/v1/session-requests/decide', { id: asked.id, granted: true })

    // The approving client's half, through the same shared step both the CLI
    // and the UI use.
    const collected = await collectApproved({ id: asked.id, kind: 'session' }, {
      get: (p) => call('GET', p),
      remember: (row) => rememberSession(row, statePath),
    })
    assert.ok(collected?.token, 'the approving client should have collected a token')

    // And it is where every local client looks, at the right mode.
    const state = JSON.parse(readFileSync(statePath, 'utf8'))
    assert.equal(state.token, collected.token, 'the session did not reach the shared store')
    assert.equal(state.session_id, collected.session_id)
    assert.equal(statSync(statePath).mode & 0o077, 0, 'the state file must not be readable by others')

    // The token is handed out once, so a later poll has nothing to give — and
    // must say something true rather than sounding like a failure.
    const again = await call('GET', `/v1/session-requests/collect?id=${asked.id}`)
    assert.equal(again.token, undefined, 'the token was handed out twice')
    assert.equal(again.state, 'collected')
  } finally {
    if (daemon2) await daemon2.stop()
    rmSync(d, { recursive: true, force: true })
  }
})

test('a denial records nothing', async () => {
  const d = mkdtempSync(join(tmpdir(), 'av-sr-deny-'))
  let daemon2
  try {
    const v = Vault.create(d, { factor: 'none' })
    v.addCredential({
      slug: 'gh', kind: 'github', connector: { host: 'api.github.com' },
      fields: { token: 'ghp_DENYTEST0011223344556677889' },
      sites: { token: ['header:authorization:Bearer'] },
    })
    const s2 = join(d, 'c.sock')
    const statePath = join(d, 'cli-state.json')
    daemon2 = await new Daemon(v, { port: 0, socketPath: s2 }).start()
    const call = (method, path, body) => new Promise((resolve) => {
      const req = unixRequest({ socketPath: s2, path, method, headers: { 'content-type': 'application/json' } }, (res) => {
        const c = []
        res.on('data', (x) => c.push(x))
        res.on('end', () => resolve(JSON.parse(Buffer.concat(c).toString() || '{}')))
      })
      req.on('error', () => resolve({}))
      req.end(body ? JSON.stringify(body) : undefined)
    })

    const asked = await call('POST', '/v1/session-requests', { cred: 'gh', methods: ['GET'], paths: ['/user'] })
    await call('POST', '/v1/session-requests/decide', { id: asked.id, granted: false })

    const collected = await collectApproved({ id: asked.id, kind: 'session' }, {
      get: (p) => call('GET', p),
      remember: () => assert.fail('a denied request must not be recorded'),
    })
    assert.equal(collected, null)
    assert.equal(existsSync(statePath), false, 'a denial wrote state')
  } finally {
    if (daemon2) await daemon2.stop()
    rmSync(d, { recursive: true, force: true })
  }
})
