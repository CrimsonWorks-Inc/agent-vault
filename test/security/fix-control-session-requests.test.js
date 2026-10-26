// Session requests: who may collect the answer, and what the waiting-room cap
// actually counts.
//
// - The token for an approved request went to whoever presented its id first,
//   and every pending id is listed on a socket other agents can reach. One
//   agent could poll another's request and walk off with the session a human
//   granted to someone else. The requester now holds a one-time secret, only
//   its hash is stored, and the approving human's own client gets the session
//   from the gated decision itself.
// - The 64-request cap counted every request ever settled, and denied ones
//   are persisted, so after 64 decisions in a vault's life nothing could ask
//   for a session again, restart or not.
// - A tokenless MCP `initialize` opened a transport session and wrote an audit
//   record, with no bound: any local process could grow both forever.
// - POST /v1/placeholders with no live session threw a TypeError.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { SessionRequests, MAX_PENDING } from '../../src/daemon/session-requests.js'
import { startDaemon, PASSPHRASE } from './fix-control-helpers.js'

let d
before(async () => { d = await startDaemon({ passphrase: PASSPHRASE }) })
after(() => d?.stop())

const present = () => { d.daemon.presenceGraceUntil = Date.now() + 60_000 }
const absent = () => { d.daemon.presenceGraceUntil = 0 }
const ask = (body = {}) => d.control('POST', '/v1/session-requests', { cred: 'demo', methods: ['GET'], paths: ['/user'], ...body })
const mcpCall = async (args) => {
  const r = await d.daemon.mcp.handle({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'vault_request_session', arguments: args } }, null, '')
  return JSON.parse(r.result.content[0].text)
}

test('asking returns a collect secret, and nothing lists it', async () => {
  const asked = await ask()
  assert.equal(asked.status, 200, JSON.stringify(asked.body))
  assert.match(asked.body.collect_secret, /^[A-Za-z0-9_-]{20,}$/)
  const listed = await d.control('GET', '/v1/session-requests')
  const text = JSON.stringify(listed.body)
  assert.ok(!text.includes(asked.body.collect_secret), 'the secret is listed')
  assert.ok(!/collect_(hash|secret)/.test(text), 'nor any form of it')
  const audit = JSON.stringify(d.vault.audit.read({ limit: 100 }))
  assert.ok(!audit.includes(asked.body.collect_secret), 'the secret reached the audit log')
})

test('another agent cannot collect a token by knowing the request id', async () => {
  const asked = await ask()
  const { id, collect_secret: secret } = asked.body
  present()
  // The bulk route: several sessions, so nobody's client collects for them.
  const other = (await ask({ paths: ['/other'] })).body
  const decided = await d.control('POST', '/v1/pending/decide-many', {
    decisions: [{ id, kind: 'session', granted: true }, { id: other.id, kind: 'session', granted: true }],
  })
  absent()
  assert.equal(decided.status, 200, JSON.stringify(decided.body))

  for (const tried of [`id=${id}`, `id=${id}&secret=`, `id=${id}&secret=${'A'.repeat(32)}`]) {
    const thief = await d.control('GET', `/v1/session-requests/collect?${tried}`)
    assert.ok(thief.status >= 400, `collected with ${tried}: ${JSON.stringify(thief.body)}`)
    assert.ok(!JSON.stringify(thief.body).includes('avs1.'))
  }
  // And trying did not use the requester's one collection up.
  const mine = await d.control('GET', `/v1/session-requests/collect?id=${id}&secret=${encodeURIComponent(secret)}`)
  assert.equal(mine.status, 200, JSON.stringify(mine.body))
  assert.match(mine.body.token, /^avs1\./)
  const twice = await d.control('GET', `/v1/session-requests/collect?id=${id}&secret=${encodeURIComponent(secret)}`)
  assert.ok(!twice.body.token, 'and it is still handed out once')
})

test('over MCP, polling needs the secret the request returned', async () => {
  const asked = await mcpCall({ cred: 'demo', reason: 'test', methods: ['GET'] })
  assert.equal(asked.state, 'pending')
  assert.ok(asked.poll_secret, JSON.stringify(asked))
  const stranger = await mcpCall({ poll_id: asked.request_id, reason: 'peeking' })
  assert.ok(stranger.error, `polled without the secret: ${JSON.stringify(stranger)}`)
  const owner = await mcpCall({ poll_id: asked.request_id, poll_secret: asked.poll_secret, reason: 'checking' })
  assert.equal(owner.state, 'pending')
})

test('the human who approves gets the session in the gated decision itself', async () => {
  const asked = (await ask()).body
  present()
  const decided = await d.control('POST', '/v1/session-requests/decide', { id: asked.id, granted: true })
  absent()
  assert.equal(decided.status, 200, JSON.stringify(decided.body))
  assert.match(decided.body.session?.token, /^avs1\./)
  assert.ok(d.vault.sessionByToken(decided.body.session.token))
  // It counts as the one collection: the agent's poll is told, not handed a copy.
  const poll = await d.control('GET', `/v1/session-requests/collect?id=${asked.id}&secret=${encodeURIComponent(asked.collect_secret)}`)
  assert.equal(poll.body.state, 'collected')
  assert.ok(!poll.body.token)
})

test('settled requests do not fill the waiting room', () => {
  const vault = { db: { kv: {} }, audit: null, save() {} }
  const store = new SessionRequests(vault)
  for (let i = 0; i < MAX_PENDING; i++) {
    const opened = store.propose({ proposal: { cred: 'demo', paths: [`/d/${i}`] } })
    const record = opened.record ?? opened
    record.state = 'denied'
    record.decided_at = new Date().toISOString()
    store.persist()
  }
  assert.doesNotThrow(() => store.propose({ proposal: { cred: 'demo' } }), 'nothing is pending, so asking must work')
  // And after a restart, with the denials read back from disk.
  const again = new SessionRequests(vault)
  assert.doesNotThrow(() => again.propose({ proposal: { cred: 'demo' } }))
})

test('genuinely pending requests are still capped', () => {
  const store = new SessionRequests({ db: { kv: {} }, audit: null, save() {} })
  for (let i = 0; i < MAX_PENDING; i++) store.propose({ proposal: { cred: 'demo', paths: [`/p/${i}`] } })
  assert.throws(() => store.propose({ proposal: { cred: 'demo' } }), /too many/)
})

test('settled requests age out of memory', () => {
  const store = new SessionRequests({ db: { kv: {} }, audit: null, save() {} })
  const opened = store.propose({ proposal: { cred: 'demo' } })
  const record = opened.record ?? opened
  record.state = 'collected'
  record.decided_at = new Date(Date.now() - 24 * 3600_000).toISOString()
  assert.equal(store.get(record.id), null, 'a day-old settled request is still held')
})

test('tokenless MCP initialize cannot grow the session map or the audit log without bound', async () => {
  const init = (headers = {}) => fetch(`http://127.0.0.1:${d.daemon.gatewayPort}/mcp`, {
    method: 'POST', headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
  })
  const before = d.vault.audit.seq
  for (let i = 0; i < 600; i++) assert.equal((await init()).status, 200)
  assert.ok(d.daemon.mcp.sessions.size <= 256, `${d.daemon.mcp.sessions.size} transport sessions held`)
  assert.ok(d.vault.audit.seq - before < 50, `${d.vault.audit.seq - before} audit records for anonymous handshakes`)

  // An ordinary initialize still gets its session id, and a client with a
  // token is still recorded.
  present()
  const s = await d.control('POST', '/v1/sessions', { cred: 'demo', methods: ['GET'] })
  absent()
  const res = await init({ authorization: `Bearer ${s.body.token}` })
  const sid = res.headers.get('mcp-session-id')
  assert.ok(sid)
  assert.ok(d.daemon.mcp.hasSession(sid))
  assert.ok(d.vault.audit.read({ limit: 5 }).some((r) => r.kind === 'mcp.session_opened' && r.mcp_session_id === sid))
})

test('issuing a placeholder with no live session says so, not TypeError', async () => {
  const f = await startDaemon()
  try {
    const none = await f.control('POST', '/v1/placeholders', { cred: 'demo' })
    assert.equal(none.body.code, 'AV_SESSION_REQUIRED', JSON.stringify(none.body))
    const unknown = await f.control('POST', '/v1/placeholders', { cred: 'demo', sid: 'nope' })
    assert.equal(unknown.body.code, 'AV_NOT_FOUND', JSON.stringify(unknown.body))

    // An expired session that nothing has touched since is not "active".
    const a = await f.control('POST', '/v1/sessions', { cred: 'demo' })
    const b = await f.control('POST', '/v1/sessions', { cred: 'demo' })
    f.vault.db.sessions[a.body.session_id].expires_at = new Date(Date.now() - 1000).toISOString()
    const issued = await f.control('POST', '/v1/placeholders', { cred: 'demo' })
    assert.equal(issued.status, 200, `the dead session made this ambiguous: ${JSON.stringify(issued.body)}`)
    assert.ok(issued.body.placeholder.startsWith(`av1.${b.body.session_id}.`), 'issued for the live session')
  } finally { await f.stop() }
})

test('the web page never sees the token, single or batch', async () => {
  const { startUi, makeAuthenticator, enrol } = await import('./fix-control-helpers.js')
  const { operationFor } = await import('../../src/ui/webauthn.js')
  const u = await startUi(d)
  try {
    const auth = makeAuthenticator(u.ui.origin)
    enrol(d.vault, auth)
    const one = (await ask({ paths: ['/ui-one'] })).body
    let presence = await u.presence(auth, operationFor('session_request.decide', { id: one.id, granted: true }))
    const single = await u.api('POST', 'session-requests/decide', { id: one.id, granted: true, presence })
    const singleBody = await single.json()
    assert.equal(single.status, 200, JSON.stringify(singleBody))
    assert.ok(!JSON.stringify(singleBody).includes('avs1.'), 'the single decision leaked a token to the page')
    assert.ok(singleBody.recorded?.session_id, 'and it was recorded for local clients')

    const two = (await ask({ paths: ['/ui-two'] })).body
    const decisions = [{ id: two.id, kind: 'session', granted: true }]
    presence = await u.presence(auth, operationFor('pending.decide_many', { decisions }))
    const batch = await u.api('POST', 'pending/decide-many', { decisions, presence })
    const batchBody = await batch.json()
    assert.equal(batch.status, 200, JSON.stringify(batchBody))
    assert.ok(!JSON.stringify(batchBody).includes('avs1.'), 'the batch leaked a token to the page')
    assert.equal(batchBody.recorded, two.id)
  } finally {
    delete d.vault.db.kv.webauthn
    await u.stop()
  }
})

// Round 2. Closing needs no token either, and every close was recorded, so an
// initialize and DELETE loop wrote a record per cycle while holding no memory.
const mcpAt = (method, headers = {}, body) => fetch(`http://127.0.0.1:${d.daemon.gatewayPort}/mcp`, {
  method, headers: { 'content-type': 'application/json', ...headers }, body,
})
const initBody = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} })

test('anonymous MCP open and close cycles write nothing to the audit log', async () => {
  const before = d.vault.audit.seq
  for (let i = 0; i < 100; i++) {
    const res = await mcpAt('POST', {}, initBody)
    const sid = res.headers.get('mcp-session-id')
    assert.ok(sid)
    assert.equal((await mcpAt('DELETE', { 'mcp-session-id': sid })).status, 204)
    assert.ok(!d.daemon.mcp.hasSession(sid), 'the close still closes')
  }
  const written = d.vault.audit.seq - before
  assert.ok(written < 10, `${written} audit records for 100 anonymous open/close cycles`)
})

test('an authenticated client\'s MCP session is recorded when it opens and when it closes', async () => {
  present()
  const s = await d.control('POST', '/v1/sessions', { cred: 'demo', methods: ['GET'] })
  absent()
  const auth = { authorization: `Bearer ${s.body.token}` }
  const sid = (await mcpAt('POST', auth, initBody)).headers.get('mcp-session-id')
  assert.equal((await mcpAt('DELETE', { ...auth, 'mcp-session-id': sid })).status, 204)
  const kinds = d.vault.audit.read({ limit: 20 }).filter((r) => r.mcp_session_id === sid).map((r) => r.kind)
  assert.deepEqual(kinds, ['mcp.session_opened', 'mcp.session_closed'])

  // Recorded at the open, so the close is recorded whoever sends it.
  const sid2 = (await mcpAt('POST', auth, initBody)).headers.get('mcp-session-id')
  await mcpAt('DELETE', { 'mcp-session-id': sid2 })
  assert.ok(d.vault.audit.read({ limit: 20 }).some((r) => r.kind === 'mcp.session_closed' && r.mcp_session_id === sid2))
})
