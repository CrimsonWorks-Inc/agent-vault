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
import { mkdtempSync, rmSync, existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
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

test('a pending request survives a daemon restart', async () => {
  // These lived only in memory, so every restart threw them away — and a
  // restart is not rare: `agent-vault upgrade` does one and launchd will too.
  // In practice this was the feature's dominant failure mode rather than an
  // edge case. Eric lost the same request three times in a row: sent it, the
  // daemon restarted, and it vanished with nothing to say it had existed.
  //
  // A pending request holds no secret — a credential slug, a proposed policy,
  // and a sentence an agent wrote — so it persists, even while the vault is
  // locked, because none of it needs the key.
  const d = mkdtempSync(join(tmpdir(), 'av-sr-restart-'))
  let first, second
  try {
    const v = Vault.create(d, { factor: 'none' })
    v.addCredential({
      slug: 'gh', kind: 'github', connector: { host: 'api.github.com' },
      fields: { token: 'ghp_RESTART00112233445566778899' },
      sites: { token: ['header:authorization:Bearer'] },
    })
    const s2 = join(d, 'c.sock')
    const call = (sock) => (method, path, body) => new Promise((resolve) => {
      const req = unixRequest({ socketPath: sock, path, method, headers: { 'content-type': 'application/json' } }, (res) => {
        const c = []
        res.on('data', (x) => c.push(x))
        res.on('end', () => resolve(JSON.parse(Buffer.concat(c).toString() || '{}')))
      })
      req.on('error', () => resolve({}))
      req.end(body ? JSON.stringify(body) : undefined)
    })

    first = await new Daemon(v, { port: 0, socketPath: s2 }).start()
    const c1 = call(s2)
    const asked = await c1('POST', '/v1/session-requests', {
      cred: 'gh', methods: ['GET'], paths: ['/user'], reason: 'survive a restart',
    })
    assert.ok(asked.id)
    await first.stop()
    first = null

    // A new process, against the same vault on disk. This is `upgrade`. It
    // gets its own socket, because what has to survive is the vault, not the
    // path — and reusing a just-unlinked socket races the old listener.
    const s3 = join(d, 'c2.sock')
    const reopened = Vault.open(d)
    reopened.startInRecordedState(null)
    second = await new Daemon(reopened, { port: 0, socketPath: s3 }).start()
    const c2 = call(s3)

    const waiting = await c2('GET', '/v1/session-requests')
    assert.equal(waiting.length, 1, 'the request did not survive the restart')
    assert.equal(waiting[0].id, asked.id)
    assert.equal(waiting[0].summary, asked.summary, 'and it must come back saying the same thing')
    assert.equal(waiting[0].agent_reason_untrusted, 'survive a restart')

    // And it is still answerable, which is the point of keeping it.
    const decided = await c2('POST', '/v1/session-requests/decide', { id: asked.id, granted: true })
    assert.ok(decided.granted, `it should still be answerable: ${JSON.stringify(decided)}`)
  } finally {
    if (first) await first.stop()
    if (second) await second.stop()
    rmSync(d, { recursive: true, force: true })
  }
})

test('an approved token is never written to disk', async () => {
  // The other half of persisting: the question survives, the answer does not.
  // A session token on disk that nobody has asked for is a live capability
  // lying around, so `result` stays in memory — and if the daemon restarts
  // between an approval and its collection, the human approves once more.
  const d = mkdtempSync(join(tmpdir(), 'av-sr-notoken-'))
  let first, second
  try {
    const v = Vault.create(d, { factor: 'none' })
    v.addCredential({
      slug: 'gh', kind: 'github', connector: { host: 'api.github.com' },
      fields: { token: 'ghp_NOTOKEN00112233445566778899' },
      sites: { token: ['header:authorization:Bearer'] },
    })
    const s2 = join(d, 'c.sock')
    const call = (method, path, body) => new Promise((resolve) => {
      const req = unixRequest({ socketPath: s2, path, method, headers: { 'content-type': 'application/json' } }, (res) => {
        const c = []
        res.on('data', (x) => c.push(x))
        res.on('end', () => resolve(JSON.parse(Buffer.concat(c).toString() || '{}')))
      })
      req.on('error', () => resolve({}))
      req.end(body ? JSON.stringify(body) : undefined)
    })

    first = await new Daemon(v, { port: 0, socketPath: s2 }).start()
    const asked = await call('POST', '/v1/session-requests', { cred: 'gh', methods: ['GET'], paths: ['/user'] })
    await call('POST', '/v1/session-requests/decide', { id: asked.id, granted: true })

    // Approved and NOT collected. The token exists in memory right now.
    const onDisk = readFileSync(join(d, 'vault.json'), 'utf8')
    assert.ok(!onDisk.includes('avs1.'), 'a session token was written to disk')
    assert.ok(!/"result":\s*\{/.test(onDisk), 'the approval result was persisted')

    await first.stop()
    first = null

    const s3 = join(d, 'c2.sock')
    const reopened = Vault.open(d)
    reopened.startInRecordedState(null)
    second = await new Daemon(reopened, { port: 0, socketPath: s3 }).start()
    const call2 = (method, path) => new Promise((resolve) => {
      const req = unixRequest({ socketPath: s3, path, method }, (res) => {
        const c = []
        res.on('data', (x) => c.push(x))
        res.on('end', () => resolve(JSON.parse(Buffer.concat(c).toString() || '{}')))
      })
      req.on('error', () => resolve({}))
      req.end()
    })
    const collect = await call2('GET', `/v1/session-requests/collect?id=${asked.id}`)
    assert.equal(collect.token, undefined, 'a token survived a restart on disk')
  } finally {
    if (first) await first.stop()
    if (second) await second.stop()
    rmSync(d, { recursive: true, force: true })
  }
})

// Every command a hint tells a human to run must be a command that exists.
//
// A session request's `next.human` answered with `agent-vault requests`, which
// was never a command. The person being asked to approve is the ONLY one who
// can, and the instruction handed to them printed "unknown command" — the same
// dead end as the two error paths that once named a `vault_request_session`
// tool that did not exist, which is why this file exists at all.
test('a session request tells the human a command they can actually run', async () => {
  const { COMMAND_NAMES } = await import('../../src/cli/index.js')

  // Its own vault, daemon and socket: an earlier test in this file deliberately
  // fills the pending store to its cap, so every later request on the shared
  // daemon is refused and this one would pass by never reaching the hint.
  const own = mkdtempSync(join(tmpdir(), 'av-hint-'))
  const v = Vault.create(own, { factor: 'none' })
  v.addCredential({
    slug: 'gh', kind: 'github', connector: { host: 'api.github.com' },
    fields: { token: 'ghp_HINTCHECK00112233445566778899' },
    sites: { token: ['header:authorization:Bearer'] },
  })
  const ownSock = join(own, 'c.sock')
  const d = await new Daemon(v, { port: 0, socketPath: ownSock }).start()
  try {
    const res = await new Promise((resolve) => {
      const req = unixRequest({ socketPath: ownSock, path: '/v1/session-requests', method: 'POST', headers: { 'content-type': 'application/json' } }, (r) => {
        const c = []
        r.on('data', (x) => c.push(x))
        r.on('end', () => resolve({ status: r.statusCode, body: JSON.parse(Buffer.concat(c).toString() || '{}') }))
      })
      req.on('error', () => resolve({ status: 0, body: {} }))
      req.end(JSON.stringify({ cred: 'gh', methods: ['GET'], paths: ['/user'] }))
    })
    assert.equal(res.status, 200, JSON.stringify(res.body))

    const hints = res.body.next?.human ?? []
    assert.ok(hints.length > 0, 'a request with no instruction for the human is a dead end')
    for (const hint of hints) {
      const words = hint.replace(/^agent-vault /, '').split(' ')
      assert.ok(
        COMMAND_NAMES.includes(words[0]) || COMMAND_NAMES.includes(words.slice(0, 2).join(' ')),
        `the human is told to run "${hint}", which is not a command`,
      )
    }
  } finally {
    await d.stop()
    rmSync(own, { recursive: true, force: true })
  }
})

// The same check over the whole source, because the next wrong hint will be
// written somewhere else.
test('no hint anywhere names an agent-vault command that does not exist', async () => {
  const { COMMAND_NAMES } = await import('../../src/cli/index.js')
  const firstWords = new Set(COMMAND_NAMES.map((n) => n.split(' ')[0]))

  // The binary name is not always followed by a command. It appears in
  // sentences ("agent-vault needs a passphrase", "agent-vault takes the token
  // away"), in an SSE comment line, and inside an X.509 subject. Each of these
  // words is listed rather than pattern-matched, so adding one is a visible
  // edit and a genuinely new bad hint still fails.
  const NOT_A_COMMAND = new Set([
    'needs', 'under', 'will', 'takes',   // prose
    'notification',                      // ': agent-vault notification stream'
    'localhost',                         // '/CN=agent-vault localhost'
  ])

  const files = []
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === 'node_modules') continue
      const p = join(dir, entry.name)
      if (entry.isDirectory()) walk(p)
      else if (/\.(js|html)$/.test(entry.name)) files.push(p)
    }
  }
  walk(new URL('../../src', import.meta.url).pathname)

  const bad = []
  for (const file of files) {
    readFileSync(file, 'utf8').split('\n').forEach((line, i) => {
      // Comments discuss commands, including ones that were removed on purpose.
      const t = line.trim()
      if (t.startsWith('*') || t.startsWith('//') || t.startsWith('<!--')) return
      for (const m of line.matchAll(/\bagent-vault ([a-z][a-z-]*)/g)) {
        if (NOT_A_COMMAND.has(m[1]) || firstWords.has(m[1])) continue
        bad.push(`${file.replace(/^.*\/src\//, 'src/')}:${i + 1} → "agent-vault ${m[1]}"`)
      }
    })
  }
  assert.deepEqual(bad, [], `hints naming commands that do not exist:\n${bad.join('\n')}`)
})
