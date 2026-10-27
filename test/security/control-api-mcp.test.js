// The agent's side of wave 3: vault_describe_access and vault_preflight (and
// the gateway's POST /v1/preflight), the new vault_request_session arguments,
// and what the existing tools now show. No tool returns a secret, creates a
// credential, approves anything or changes a policy; a preflight changes
// nothing at all; the approval preview stays on the human's side (F13).

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { startApi, SECRET } from './control-api-helpers.js'
import { fetchPending } from '../../src/pending.js'

const auth = (s) => ({ authorization: `Bearer ${s.token}` })

test('vault_describe_access says what the session may do, with no token, placeholder, fingerprint or size, and records nothing', async () => {
  const a = await startApi()
  try {
    const s = a.session({ policy: { methods: ['GET'], rate: { count: 5, per: 'second' } }, grantTtlMs: 600_000 })
    a.vault.saveTemplate('read', { cred: 'demo', methods: ['GET'] })
    const records = a.audit().length
    const r = await a.tool('vault_describe_access', {}, { token: s.token })
    assert.equal(r.isError, false, JSON.stringify(r.body))
    assert.equal(a.audit().length, records, 'describing wrote an audit record')
    assert.equal(r.body.session.id, s.session.id)
    assert.equal(r.body.session.infinite, false)
    const [g] = r.body.grants
    assert.equal(g.cred, 'demo')
    assert.deepEqual(g.effective.methods, ['GET'])
    assert.deepEqual(g.effective.rate, { count: 5, per: 'second' })
    assert.equal(g.budget_remaining, 100)
    assert.equal(g.spend_remaining, null)
    assert.equal(g.quarantined, false)
    assert.ok(g.expires_at)
    assert.ok(g.put_it_at.length >= 1)
    assert.deepEqual(r.body.templates.map((t) => t.name), ['read'])
    assert.match(r.body.next, /vault_request_session/)
    const text = JSON.stringify(r.body)
    for (const [what, value] of [['placeholder', s.placeholder], ['token', s.token], ['secret', SECRET], ['placeholder prefix', 'av1.']]) {
      assert.ok(!text.includes(value), `${what} in vault_describe_access`)
    }
    for (const key of ['fp8', 'size', 'length', 'token_hash']) assert.ok(!text.includes(`"${key}"`), `${key} in vault_describe_access`)
    // An infinite session says so.
    const forever = a.session({ infinite: true })
    const fd = await a.tool('vault_describe_access', {}, { token: forever.token })
    assert.equal(fd.body.session.infinite, true)
    assert.equal(fd.body.session.expires_at, null)
    // No session, no description.
    assert.equal((await a.tool('vault_describe_access', {})).isError, true)
  } finally { await a.stop() }
})

test('vault_preflight changes nothing: no approval, no use, no budget, no touch, and no upstream connection', async () => {
  const a = await startApi()
  try {
    const s = a.session({ policy: { approval: 'on-write' } })
    const row = Object.values(a.vault.db.placeholders).find((p) => p.sid === s.session.id)
    const before = JSON.stringify({ g: a.vault.db.grants[s.grant.id], s: a.vault.db.sessions[s.session.id], row })
    const hits = a.seen.length
    const held = await a.tool('vault_preflight', { cred: 'demo', method: 'POST', path: '/repos/x', body: '{"a":1}' }, { token: s.token })
    assert.equal(held.isError, false, JSON.stringify(held.body))
    assert.equal(held.body.would, 'hold')
    assert.match(held.body.advisory, /A prediction, not a permission/)
    const allowed = await a.tool('vault_preflight', { cred: 'demo', method: 'GET', path: '/repos/x' }, { token: s.token })
    assert.equal(allowed.body.would, 'allow', JSON.stringify(allowed.body))
    const denied = await a.tool('vault_preflight', { cred: 'demo', method: 'DELETE', path: '/repos/x' }, { token: s.token })
    assert.equal(denied.body.would, 'deny')
    assert.equal(a.daemon.pipeline.pendingApprovals().length, 0, 'a preflight created an approval')
    assert.equal(a.seen.length, hits, 'a preflight reached the upstream')
    assert.equal(JSON.stringify({ g: a.vault.db.grants[s.grant.id], s: a.vault.db.sessions[s.session.id], row: a.vault.db.placeholders[row.id] }), before, 'a preflight changed the grant, the session or a placeholder')
    assert.equal(a.audit('request.preflighted').length, 3)
    assert.equal(a.audit('placeholder.issued').filter((r) => r.session_id === s.session.id).length, 1, 'a preflight minted a placeholder')
  } finally { await a.stop() }
})

test('vault_preflight refuses what it cannot read, an unknown credential, and an eleventh call in a second', async () => {
  const a = await startApi()
  try {
    const s = a.session()
    const unknown = await a.tool('vault_preflight', { cred: 'missing', method: 'GET', path: '/x' }, { token: s.token })
    assert.equal(unknown.body.code, 'AV_NOT_FOUND')
    for (const args of [{ cred: 'demo', method: 'GET', path: 'x' }, { cred: 'demo', method: 'G E T', path: '/x' }, { cred: 'demo', method: 'GET', path: '/x', headers: ['a'] }]) {
      const r = await a.tool('vault_preflight', args, { token: s.token })
      assert.equal(r.body.rule, 'preflight_shape', JSON.stringify(args))
    }
    assert.equal((await a.tool('vault_preflight', { cred: 'demo', method: 'GET', path: '/x' })).isError, true, 'no session, yet answered')
    let throttled = null
    for (let i = 0; i < 12 && !throttled; i++) {
      const r = await a.tool('vault_preflight', { cred: 'demo', method: 'GET', path: '/x' }, { token: s.token })
      if (r.body.code === 'AV_QUOTA_EXCEEDED') throttled = r.body
    }
    assert.ok(throttled, 'eleven preflights in a second were all answered')
    assert.equal(throttled.rule, 'preflight_rate')
    assert.ok(Number.isInteger(throttled.retry_after))
  } finally { await a.stop() }
})

test('a preflight with a placeholder in the wrong place says deny, and never trips a tripwire', async () => {
  const a = await startApi()
  try {
    a.vault.updateSettings({ tripwires: { enabled: true, rules: [{ id: 'loc', codes: ['AV_BAD_LOCATION'], threshold: 1, window_s: 600, action: 'revoke_session' }] } })
    const s = a.session()
    const r = await a.gateway('/v1/preflight', {
      method: 'POST', headers: { ...auth(s), 'content-type': 'application/json' },
      body: JSON.stringify({ method: 'GET', path: `/p/demo/items/${s.placeholder}`, headers: [['authorization', `Bearer ${s.placeholder}`]] }),
    })
    assert.equal(r.status, 200, r.text)
    assert.equal(r.json.would, 'deny')
    assert.equal(r.json.checks.at(-1).code, 'AV_BAD_LOCATION')
    assert.equal(a.audit('tripwire.fired').length, 0)
    assert.equal(a.vault.db.sessions[s.session.id].state, 'active')
  } finally { await a.stop() }
})

test('the gateway preflight route authenticates like a real request, reads its body strictly, and touches nothing', async () => {
  const a = await startApi()
  try {
    const s = a.session({ policy: { approval: 'on-write' } })
    const seenAt = a.vault.db.sessions[s.session.id].last_seen_at
    const expires = a.vault.db.sessions[s.session.id].expires_at
    const post = (body, headers = auth(s)) => a.gateway('/v1/preflight', {
      method: 'POST', headers: { ...headers, 'content-type': 'application/json' }, body: typeof body === 'string' ? body : JSON.stringify(body),
    })
    // The route describes a whole request, carrier included: unlike the MCP
    // tool, it assumes no placeholder.
    const bare = await post({ method: 'POST', path: '/p/demo/repos/x' })
    assert.equal(bare.json.would, 'deny', bare.text)
    const ok = await post({
      method: 'post', path: '/p/demo/repos/x', body: '{}',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${s.placeholder}` },
    })
    assert.equal(ok.status, 200, ok.text)
    assert.equal(ok.json.would, 'hold')
    const b64 = await post({ method: 'GET', path: '/p/demo/x', body_base64: Buffer.from('hi').toString('base64'), headers: [['authorization', `Bearer ${s.placeholder}`]] })
    assert.equal(b64.json.would, 'allow', b64.text)
    assert.equal(a.vault.db.sessions[s.session.id].last_seen_at, seenAt, 'a preflight touched the session')
    assert.equal(a.vault.db.sessions[s.session.id].expires_at, expires)
    assert.equal(a.daemon.pipeline.pendingApprovals().length, 0)
    for (const body of [
      { method: 'GET', path: '/p/demo/x', body: 'a', body_base64: 'YQ==' },
      { method: 'GET', path: '/v1/status' }, { method: 'GET' }, { method: 5, path: '/p/demo/x' },
      { method: 'GET', path: '/p/demo/x', headers: [['a']] }, { method: 'GET', path: '/p/demo/x', query: 1 },
      { method: 'GET', path: '/p/demo/x', body_base64: 'not base64!' }, 'not json', '[]',
    ]) {
      const r = await post(body)
      assert.equal(r.status, 403, `${JSON.stringify(body)}: ${r.text}`)
      assert.equal(r.json.rule, 'preflight_shape')
    }
    assert.equal((await post({ method: 'GET', path: '/p/demo/x' }, {})).status, 401)
    assert.equal((await post({ method: 'GET', path: '/p/demo/x' }, { ...auth(s), origin: 'http://evil.example' })).status, 403)
    assert.equal((await a.gateway('/v1/preflight', { headers: auth(s) })).status, 404)
  } finally { await a.stop() }
})

test('vault_request_session forwards routes, uses and a grant lifetime, and nothing it does not offer', async () => {
  const a = await startApi()
  try {
    const r = await a.tool('vault_request_session', {
      cred: 'demo', reason: 'x', methods: ['GET', 'POST'], uses: 5, grant_ttl_minutes: 15,
      routes: [{ methods: ['POST'], paths: ['/repos/*/issues'] }], hosts: ['evil.example'], rate: '1000/s',
    })
    assert.equal(r.body.state, 'pending', JSON.stringify(r.body))
    const { proposal } = a.daemon.sessionRequests.get(r.body.request_id)
    assert.equal(proposal.uses, 5)
    assert.equal(proposal.grant_ttl_minutes, 15)
    assert.deepEqual(proposal.routes, [{ methods: ['POST'], paths: ['/repos/*/issues'] }])
    assert.equal(proposal.hosts, undefined)
    assert.equal(proposal.rate, undefined)
    assert.match(r.body.asked_for, /routes POST \/repos\/\*\/issues/)
    // A proposal that could never be created is refused while the agent is
    // still there to hear why, and nothing is opened.
    const before = a.daemon.sessionRequests.pending().length
    const bad = await a.tool('vault_request_session', { cred: 'demo', reason: 'x', grant_ttl_minutes: 0 })
    assert.equal(bad.body.rule, 'grant_ttl')
    assert.equal(a.daemon.sessionRequests.pending().length, before)
  } finally { await a.stop() }
})

test('the existing tools show lifetimes; the preview stays with the human (F13)', async () => {
  const a = await startApi()
  try {
    const forever = a.session({ infinite: true })
    const status = await a.tool('vault_status', {}, { token: forever.token })
    assert.equal(status.body.session.infinite, true)
    assert.equal(status.body.session.expires_at, null)
    const s = a.session({ policy: { approval: 'each' } })
    const held = await a.gateway('/p/demo/repos/x', {
      method: 'POST', headers: { authorization: `Bearer ${s.placeholder}`, 'content-type': 'application/json' },
      body: JSON.stringify({ title: 'hello', note: `a pasted ${SECRET}` }),
    })
    assert.equal(held.status, 202)
    const id = held.json.approval_id
    const agentView = await a.tool('vault_approval_status', { approval_id: id }, { token: s.token })
    assert.equal(agentView.body.preview, undefined, 'the agent sees the preview')
    const humanView = await a.control('GET', '/v1/approvals')
    const preview = humanView.body.find((x) => x.id === id).preview
    assert.ok(preview, 'the human does not see the preview')
    assert.equal(preview.untrusted, true)
    assert.ok(!JSON.stringify(preview).includes(s.placeholder))
    assert.ok(!JSON.stringify(preview).includes(SECRET), 'a pasted secret is in the preview')
    assert.ok(!preview.headers.some(([n]) => n.toLowerCase() === 'authorization'))
    assert.match(preview.body.text, /hello/)
    const pending = await fetchPending(async (path) => (await a.control('GET', path)).body)
    assert.deepEqual(pending.find((x) => x.id === id).preview, preview)
    assert.equal(pending.find((x) => x.kind === 'request').narrowable.length, 0)
  } finally { await a.stop() }
})

test('the server instructions point at the two new tools', async () => {
  const a = await startApi()
  try {
    const r = await a.daemon.mcp.handle({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }, null, '')
    assert.match(r.result.instructions, /Before a write you are unsure of, call vault_preflight; to learn your limits, call vault_describe_access\./)
  } finally { await a.stop() }
})
