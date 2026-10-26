// vault_http, the tool the instructions tell agents to prefer.
//
// - A streamed (text/event-stream) response crashed it after the request had
//   run and been charged: `res.body` is absent on the streaming path.
// - It never sent the session token. `#tokenFor` was called without it, so
//   every call authenticated by falling back on the placeholder as carrier,
//   and a credential whose site is not a header could not be used at all.
// - It minted a placeholder per call and left each one active after use, so
//   the ledger grew by a live row per request with nothing to collect it.
// - vault_request_session advertised ttl_minutes and dropped it.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { Readable } from 'node:stream'
import { startDaemon, SECRET, PASSPHRASE } from './fix-control-helpers.js'

async function sessionFor(d, body) {
  d.daemon.presenceGraceUntil = Date.now() + 60_000
  // Auto-approved writes need a fresh proof (R1), so the fixture vault has a
  // passphrase and the create call carries it.
  const s = await d.control('POST', '/v1/sessions', { cred: 'demo', methods: ['GET', 'POST'], paths: ['/**'], approval: 'auto', ...body, presence: { passphrase: PASSPHRASE } })
  d.daemon.presenceGraceUntil = 0
  assert.equal(s.status, 200, JSON.stringify(s.body))
  return { token: s.body.token, session: d.vault.sessionByToken(s.body.token), grantId: s.body.grant_id }
}

async function call(d, s, name, args) {
  const r = await d.daemon.mcp.handle({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }, s.session, s.token)
  assert.ok(!r.error, `JSON-RPC error: ${JSON.stringify(r.error)}`)
  return { ...r.result, json: JSON.parse(r.result.content[0].text) }
}

let d, s, seen = []
before(async () => {
  d = await startDaemon({ passphrase: PASSPHRASE })
  s = await sessionFor(d)
})
after(() => d?.stop())

test('a streamed response comes back as a body, and the stream is read to the end', async () => {
  let drained = false
  const events = ['data: {"n":1}\n\n', 'data: {"n":2}\n\n']
  d.daemon.pipeline.upstream = async () => {
    const res = Readable.from(events.map((e) => Buffer.from(e)))
    res.on('end', () => { drained = true })
    return { status: 200, headers: { 'content-type': 'text/event-stream' }, res }
  }
  const r = await call(d, s, 'vault_http', { cred: 'demo', method: 'GET', path: '/stream', reason: 'test' })
  assert.equal(r.json.status, 200, JSON.stringify(r.json))
  assert.match(r.json.body, /"n":1/)
  assert.match(r.json.body, /"n":2/)
  assert.ok(drained, 'the upstream stream must be consumed, not left open')
})

test('a buffered response is unchanged', async () => {
  d.daemon.pipeline.upstream = async ({ headers }) => {
    seen.push(headers)
    return { status: 200, headers: { 'content-type': 'application/json' }, body: Buffer.from('{"ok":true}') }
  }
  const r = await call(d, s, 'vault_http', { cred: 'demo', method: 'GET', path: '/user', reason: 'test' })
  assert.equal(r.json.status, 200)
  assert.equal(r.json.body, '{"ok":true}')
  const auth = seen.at(-1).authorization ?? seen.at(-1).Authorization
  assert.equal(auth, `Bearer ${SECRET}`, 'the credential reaches the upstream at its site')
})

test('vault_http does not leave a live placeholder behind per call', async () => {
  d.daemon.pipeline.upstream = async () => ({ status: 200, headers: { 'content-type': 'text/plain' }, body: Buffer.from('ok') })
  const live = () => d.vault.listPlaceholders(s.session.id).filter((p) => p.state === 'active' && p.grant_id === s.grantId).length
  const before = live()
  for (let i = 0; i < 20; i++) {
    const r = await call(d, s, 'vault_http', { cred: 'demo', method: 'GET', path: `/n/${i}`, reason: 'test' })
    assert.equal(r.json.status, 200)
  }
  assert.ok(live() <= before, `live placeholders grew from ${before} to ${live()}`)
})

test('the session token is what authenticates, so a query-site credential works', async () => {
  const q = await startDaemon({ sites: ['query:api_key'], passphrase: PASSPHRASE })
  try {
    const qs = await sessionFor(q)
    let url
    q.daemon.pipeline.upstream = async (req) => {
      url = req.url
      return { status: 200, headers: { 'content-type': 'text/plain' }, body: Buffer.from('ok') }
    }
    const r = await call(q, qs, 'vault_http', { cred: 'demo', method: 'GET', path: '/things', reason: 'test' })
    assert.equal(r.json.status, 200, JSON.stringify(r.json))
    assert.match(String(url), new RegExp(`api_key=${SECRET}`))
  } finally { await q.stop() }
})

test('vault_request_session carries ttl_minutes and uses to the human', async () => {
  const r = await call(d, { session: null, token: '' }, 'vault_request_session', {
    cred: 'demo', reason: 'short job', methods: ['GET'], ttl_minutes: 15, uses: 3,
  })
  assert.equal(r.json.state, 'pending', JSON.stringify(r.json))
  const record = d.daemon.sessionRequests.get(r.json.request_id)
  assert.equal(record.proposal.ttl_minutes, 15)
  assert.equal(record.proposal.uses, 3)
  assert.deepEqual(record.proposal.methods, ['GET'])
})
