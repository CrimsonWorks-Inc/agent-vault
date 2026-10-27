import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Readable } from 'node:stream'
import { createServer } from 'node:http'
import { Vault } from '../../src/store/vault.js'
import { Pipeline, approvalPreview } from '../../src/daemon/pipeline.js'
import { deny } from '../../src/core/errors.js'
import { meterRequest, reservationFor } from '../../src/core/model-usage.js'
import { requestView, foldedNames, isOverrideField, isStrayName } from '../../src/core/request-view.js'
import { evaluatePayload } from '../../src/core/payload.js'

const SECRET = 'fixture_secret_gateway_only_0123456789'
function fixture(t, policy = {}, { kind = 'http', upstream, options = {} } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'av-gw-w2-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const vault = Vault.create(dir, { factor: 'none' })
  const added = vault.addCredential({ slug: 'test', kind, connector: { host: { openai: 'api.openai.com', anthropic: 'api.anthropic.com' }[kind] ?? 'api.example.test' }, fields: { token: SECRET }, sites: { token: ['header:authorization:Bearer'] } })
  const cred = vault.findCredential(added.slug)
  const { session, token } = vault.createSession({ label: 'gateway', policy: {} })
  const grant = vault.createGrant({ sessionId: session.id, credentialId: cred.id, fields: ['token'], policy: { hosts: [cred.connector.host], methods: ['GET', 'POST', 'HEAD'], paths: ['/**'], budget: { unit: 'requests', limit: 100 }, approval: 'auto', ...policy } })
  const ph = vault.issuePlaceholder({ grantId: grant.id, field: 'token', maxUses: 100 }).placeholder
  const row = Object.values(vault.db.placeholders)[0]
  const sent = []
  const expiryMs = value => value == null ? Infinity : (Number.isNaN(Date.parse(value)) ? -Infinity : Date.parse(value))
  const sessionExpiryMs = value => value.infinite === true && value.expires_at === null ? Infinity : value.expires_at == null ? -Infinity : expiryMs(value.expires_at)
  const pipeline = new Pipeline(vault, { expiryMs, sessionExpiryMs, ...options, fetchImpl: async (input) => { sent.push(input); return upstream ? upstream(input) : { status: 200, headers: { 'content-type': 'application/json' }, body: Buffer.from('{"ok":true}') } } })
  const req = (over = {}) => ({ method: 'GET', path: '/p/test/ok', query: '', headers: [['host', 'localhost'], ['av-session', token], ['authorization', `Bearer ${ph}`]], body: null, ...over })
  // Slice-A seams: use the real methods when integration has supplied them.
  vault.chargeGrant ??= (id) => { const g = vault.db.grants[id]; if (g.budget_used >= g.policy.budget.limit) return false; g.budget_used++; g.counters.requests++; return true }
  return { dir, vault, cred, session, token, grant, ph, row, sent, pipeline, req }
}
const problem = result => JSON.parse(result.body)
const streamText = async stream => { let out = ''; for await (const chunk of stream) out += chunk; return out }
const modelBody = Buffer.from(JSON.stringify({ model: 'gpt-4.1-mini', max_tokens: 30, messages: [{ role: 'user', content: 'hi' }] }))
const modelReq = f => f.req({ method: 'POST', path: '/p/test/v1/chat/completions', headers: [...f.req().headers, ['content-type', 'application/json']], body: modelBody })

test('rate allows capacity, limits pending requests, and never spends a refused use', async t => {
  const f = fixture(t, { rate: { count: 2, per: 'hour' } })
  assert.equal((await f.pipeline.handle(f.req())).status, 200)
  assert.equal((await f.pipeline.handle(f.req())).status, 200)
  const uses = f.row.uses, budget = f.grant.budget_used
  const result = await f.pipeline.handle(f.req())
  assert.equal(result.status, 429); assert.equal(problem(result).rule, 'rate')
  assert.ok(Number(result.headers['retry-after']) >= 1)
  assert.equal(f.row.uses, uses); assert.equal(f.grant.budget_used, budget)
  const held = fixture(t, { approval: 'each', rate: { count: 1, per: 'hour' } })
  assert.equal((await held.pipeline.handle(held.req())).status, 202)
  assert.equal((await held.pipeline.handle(held.req())).status, 429)
})

test('malformed limits and persisted counters fail closed without an upstream', async t => {
  for (const policy of [{ rate: { count: NaN, per: 'second' } }, { rate: { count: '5', per: 'min' } }, { max_concurrent: 1.5 }, { quota: { count: NaN, window: 'day' } }, { budget: { limit: NaN } }]) {
    const f = fixture(t)
    Object.assign(f.grant.policy, policy)
    const result = await f.pipeline.handle(f.req())
    assert.equal(result.status, 403); assert.match(problem(result).rule, /_invalid$/)
    assert.equal(f.row.uses, 0); assert.equal(f.sent.length, 0)
  }
  const f = fixture(t, { quota: { count: 10, window: 'hour' } })
  f.grant.quota_state = { window_ms: 3600000, start: Date.now(), count: NaN, prev: 0 }
  assert.equal(problem(await f.pipeline.handle(f.req())).rule, 'quota_invalid')
})

test('quota charges one per call, survives restart and rollback, refunds pre-connect errors', async t => {
  const f = fixture(t, { quota: { count: 1, window: 'hour' } })
  assert.equal((await f.pipeline.handle(f.req())).status, 200)
  assert.equal(problem(await f.pipeline.handle(f.req())).rule, 'quota')
  const reopened = Vault.open(f.dir); reopened.unlock()
  const fresh = new Pipeline(reopened, { fetchImpl: async () => { throw Error('must not send') } })
  assert.equal(problem(await fresh.handle(f.req())).rule, 'quota')
  f.grant.quota_state.start += 3600000
  assert.equal(problem(await f.pipeline.handle(f.req())).rule, 'quota')
  const retry = fixture(t, { quota: { count: 1, window: 'hour' } }, { upstream: () => { throw Object.assign(Error('refused'), { code: 'ECONNREFUSED' }) } })
  assert.equal((await retry.pipeline.handle(retry.req())).status, 502)
  assert.equal(retry.grant.quota_state.count, 0); assert.equal(retry.row.uses, 0)
})

test('concurrency releases after success, pre-connect failure and post-connect failure', async t => {
  for (const code of ['ECONNREFUSED', 'ECONNRESET']) {
    let unblock
    const f = fixture(t, { max_concurrent: 1 }, { upstream: () => new Promise((resolve, reject) => { unblock = () => reject(Object.assign(Error('failed'), { code })) }) })
    const first = f.pipeline.handle(f.req())
    const denied = await f.pipeline.handle(f.req())
    assert.equal(problem(denied).rule, 'max_concurrent')
    unblock(); await first
    assert.equal(f.pipeline.limitsFor(f.grant.id).max_concurrent.in_flight, 0)
  }
  const f = fixture(t, { max_concurrent: 1 })
  await f.pipeline.handle(f.req())
  assert.equal(f.pipeline.limitsFor(f.grant.id).max_concurrent.in_flight, 0)
})

test('SSE slots release on completion, immediate close and scrubber cut', async t => {
  for (const mode of ['complete', 'abort', 'cut']) {
    const f = fixture(t, { max_concurrent: 1 }, { upstream: () => ({ status: 200, headers: { 'content-type': 'text/event-stream' }, res: Readable.from([Buffer.from(mode === 'cut' ? `data: {"delta":"${SECRET.slice(0, 15)}"}\n\ndata: {"delta":"${SECRET.slice(15)}"}\n\n` : 'data: {"ok":true}\n\n')]) }) })
    const result = await f.pipeline.handle(f.req())
    assert.equal(f.pipeline.limitsFor(f.grant.id).max_concurrent.in_flight, 1)
    if (mode === 'abort') await result.stream.return()
    else await streamText(result.stream)
    assert.equal(f.pipeline.limitsFor(f.grant.id).max_concurrent.in_flight, 0)
  }
})

test('payload and method-bound routes run before approval and consume', async t => {
  const f = fixture(t, { approval: 'each', routes: [{ methods: ['GET'], paths: ['/ok'] }, { methods: ['POST'], paths: ['/comment'] }], payload: { json: { '/channel': { one_of: ['safe'] } } } })
  const result = await f.pipeline.handle(f.req({ method: 'POST', path: '/p/test/comment', body: Buffer.from('{"channel":"bad"}'), headers: [...f.req().headers, ['content-type', 'application/json']] }))
  assert.equal(problem(result).rule, 'payload:json:/channel:one_of')
  assert.equal(f.pipeline.pendingApprovals().length, 0); assert.equal(f.row.uses, 0)
  assert.equal(problem(await f.pipeline.handle(f.req({ method: 'POST' }))).rule, 'routes')
  assert.equal((await f.pipeline.handle(f.req())).status, 202)
})

test('custom patterns from every credential scrub bodies, headers and errors; corrupt pattern withholds', async t => {
  const f = fixture(t, {}, { upstream: () => ({ status: 200, headers: { 'x-test': 'xyz_CUSTOM123456' }, body: Buffer.from('xyz_CUSTOM123456 ordinary') }) })
  f.cred.scrub_patterns = [{ id: 'sp_test', source: 'xyz_[A-Z0-9]{6,30}' }]
  const result = await f.pipeline.handle(f.req())
  assert.ok(!result.body.toString().includes('xyz_CUSTOM')); assert.ok(!result.headers['x-test'].includes('xyz_CUSTOM'))
  f.cred.scrub_patterns[0].source = '(a+)+'
  assert.equal(problem(await f.pipeline.handle(f.req())).rule, 'scrub_pattern_invalid')
})

test('token reservations block concurrent overspend and settle buffered usage', async t => {
  const reserve = reservationFor('openai', meterRequest('openai', { method: 'POST', path: '/v1/chat/completions', contentType: 'application/json', body: modelBody })).tokens
  // Every upstream call is held until released, and none waits on another,
  // so a second call that wrongly got through shows up as a send, not a hang.
  const held = []
  const f = fixture(t, { spend: { tokens: reserve + 1 } }, { kind: 'openai', upstream: () => new Promise(resolve => { held.push(() => resolve({ status: 200, headers: { 'content-type': 'application/json' }, body: Buffer.from('{"usage":{"prompt_tokens":5,"completion_tokens":7}}') })) }) })
  const first = f.pipeline.handle(modelReq(f))
  assert.equal(f.pipeline.spendFor(f.grant.id).reserved_tokens, reserve)
  const second = f.pipeline.handle(modelReq(f))
  const outcome = await Promise.race([second, new Promise((resolve) => setTimeout(() => resolve('sent'), 500))])
  for (const release of held) release()
  assert.notEqual(outcome, 'sent', 'the second call reached the upstream')
  assert.equal(problem(outcome).rule, 'spend'); assert.equal(f.sent.length, 1)
  assert.equal((await first).status, 200)
  assert.equal(f.grant.spend.tokens_used, 12)
  assert.equal(f.pipeline.spendFor(f.grant.id).reserved_tokens, 0)
})

test('unpriced and unmodeled spend refuses while ordinary free GET passes', async t => {
  const f = fixture(t, { spend: { tokens: 100000, usd_micros: 100000 } }, { kind: 'openai' })
  const req = modelReq(f); req.body = Buffer.from('{"model":"unknown","max_tokens":1}')
  assert.equal(problem(await f.pipeline.handle(req)).rule, 'spend_unpriced')
  assert.equal(problem(await f.pipeline.handle({ ...req, path: '/p/test/v1/unknown' })).rule, 'spend_unmodeled')
  assert.equal((await f.pipeline.handle(f.req())).status, 200)
  assert.equal(f.grant.spend, undefined)
})

test('missing usage and aborted SSE charge full reservation; completed SSE uses usage', async t => {
  for (const mode of ['buffer', 'abort', 'complete']) {
    const f = fixture(t, { spend: { tokens: 10000 } }, { kind: 'openai', upstream: () => mode === 'buffer' ? { status: 200, headers: {}, body: Buffer.from('ok') } : { status: 200, headers: { 'content-type': 'text/event-stream' }, res: Readable.from([Buffer.from('data: {"usage":{"prompt_tokens":3,"completion_tokens":4}}\n\n')]) } })
    const result = await f.pipeline.handle(modelReq(f))
    const reservation = result.spend.reserved_tokens
    if (mode === 'abort') await result.stream.return()
    if (mode === 'complete') await streamText(result.stream)
    assert.equal(f.grant.spend.tokens_used, mode === 'complete' ? 7 : reservation)
    assert.deepEqual(f.grant.spend.reserved, {})
  }
})

test('restart charges outstanding reservation and pre-connect failure releases it', async t => {
  const f = fixture(t, { spend: { tokens: 10000 } }, { kind: 'openai', upstream: () => { throw Object.assign(Error('refused'), { code: 'ENOTFOUND' }) } })
  await f.pipeline.handle(modelReq(f)); assert.equal(f.grant.spend.tokens_used, 0); assert.deepEqual(f.grant.spend.reserved, {})
  f.grant.spend.reserved.rid = { tokens: 50, usd_micros: 6, at: Date.now() }
  new Pipeline(f.vault)
  assert.equal(f.grant.spend.tokens_used, 50); assert.equal(f.grant.spend.usd_micros_used, 6)
  assert.deepEqual(f.grant.spend.reserved, {})
})

test('redirects check hosts, paths, scheme, method, approval and max before sending', async t => {
  for (const [policy, method, location, expected] of [
    [{ redirects: { max: 2 } }, 'GET', 'https://evil.test/stolen', 'host'],
    [{ redirects: { max: 2 }, paths: ['/ok'] }, 'GET', '/other', 'path'],
    [{ redirects: { max: 2 } }, 'GET', 'http://api.example.test/ok', 'scheme'],
    [{ redirects: { max: 2 } }, 'POST', '/ok', 'approval'],
    [{ redirects: { max: NaN } }, 'GET', '/ok', 'max'],
  ]) {
    const f = fixture(t, policy, { upstream: () => ({ status: 302, headers: { location }, body: Buffer.from('redirect') }) })
    const result = await f.pipeline.handle(f.req({ method }))
    assert.equal(result.status, 302); assert.equal(result.headers['av-redirect-stopped'], expected); assert.equal(f.sent.length, 1)
  }
  const f = fixture(t, { redirects: { max: 2 }, approval: 'each' }, { upstream: () => ({ status: 302, headers: { location: '/ok' }, body: Buffer.alloc(0) }) })
  await f.pipeline.handle(f.req()); f.pipeline.decideApproval(f.pipeline.pendingApprovals()[0].id, true)
  const result = await f.pipeline.handle(f.req())
  assert.equal(result.headers['av-redirect-stopped'], 'approval'); assert.equal(f.sent.length, 1)
})

test('allowed redirect follows, charges each hop and forwards correct pins without body', async t => {
  let count = 0
  const f = fixture(t, { redirects: { max: 2 } }, { upstream: () => ++count < 3 ? { status: 302, headers: { location: '/ok' }, body: Buffer.alloc(0) } : { status: 200, headers: {}, body: Buffer.from('done') } })
  f.cred.pins = { 'api.example.test': ['sha256/example'] }
  const result = await f.pipeline.handle(f.req())
  assert.equal(result.body.toString(), 'done'); assert.equal(f.sent.length, 3); assert.equal(f.grant.budget_used, 3)
  assert.deepEqual(f.sent[1].pins, f.cred.pins['api.example.test']); assert.equal(f.sent[1].body, null)
  count = 0; f.pipeline.upstream = async () => ({ status: 302, headers: { location: '/ok' }, body: Buffer.alloc(0) })
  assert.equal((await f.pipeline.handle(f.req())).headers['av-redirect-stopped'], 'max')
})

test('pins map to safe problem and refund; health observer receives response metadata', async t => {
  const health = []
  const f = fixture(t, {}, { upstream: () => { throw Object.assign(Error(SECRET), { code: 'AV_PIN_MISMATCH', presented: ['sha256/presented'] }) } })
  const result = await f.pipeline.handle(f.req())
  assert.equal(problem(result).code, 'AV_PIN_MISMATCH'); assert.equal(f.row.uses, 0); assert.ok(!result.body.includes(SECRET))
  f.vault.recordHealth = (id, patch) => health.push({ id, ...patch })
  f.pipeline.extractHealth = () => ({ observed_expires_at: '2027-01-01T00:00:00.000Z' })
  f.pipeline.upstream = async () => ({ status: 401, headers: {}, body: Buffer.from('{}') })
  await f.pipeline.handle(f.req())
  assert.equal(health[0].status, 'unauthorized'); assert.equal(health[0].observed_expires_at, '2027-01-01T00:00:00.000Z')
})

test('approval preview scrubs secrets and placeholders and notifications fire once', async t => {
  const f = fixture(t, { approval: 'each' })
  const notices = []; f.pipeline.onPending = e => notices.push(e)
  const request = f.req({ method: 'POST', body: Buffer.from(JSON.stringify({ comment: `hello ${SECRET}` })), headers: [...f.req().headers, ['content-type', 'application/json']] })
  await f.pipeline.handle(request); await f.pipeline.handle(request)
  const approval = f.pipeline.pendingApprovals()[0]
  assert.equal(notices.length, 1); assert.equal(notices[0].id, approval.id)
  assert.ok(approval.preview.body.text.includes('hello'))
  assert.ok(!JSON.stringify(approval.preview).includes(SECRET)); assert.ok(!JSON.stringify(approval.preview).includes(f.ph))
  assert.ok(!approval.preview.headers.some(([name]) => name === 'authorization'))
  assert.equal(f.pipeline.approvalStatus(approval.id).preview, undefined)
  assert.ok(Buffer.byteLength(JSON.stringify(approval.preview)) <= 8192)
})

test('quarantine and grant expiry stop before consume, and denyApprovals returns only a count', async t => {
  const f = fixture(t, { approval: 'each' })
  await f.pipeline.handle(f.req())
  assert.equal(f.pipeline.denyApprovals({ sessionId: f.session.id }, 'panic'), 1)
  assert.equal(f.pipeline.pendingApprovals().length, 0)
  f.cred.quarantine = { by: 'control' }
  assert.equal(problem(await f.pipeline.handle(f.req())).code, 'AV_QUARANTINED')
  assert.equal(problem(await f.pipeline.handle(f.req({ path: '/t/https/api.example.test/ok' }))).code, 'AV_QUARANTINED')
  f.cred.quarantine = null
  f.vault.assertGrantLive = () => { throw deny('AV_GRANT_EXPIRED', 'expired') }
  assert.equal(problem(await f.pipeline.handle(f.req())).code, 'AV_GRANT_EXPIRED'); assert.equal(f.row.uses, 0)
})

test('preflight is observational, peeks limits and reports a hold without creating approval', async t => {
  const f = fixture(t, { approval: 'each', rate: { count: 2, per: 'hour' }, quota: { count: 2, window: 'hour' } })
  const before = JSON.stringify(f.vault.db)
  const result = await f.pipeline.preflight(f.req())
  assert.equal(result.would, 'hold'); assert.equal(f.pipeline.pendingApprovals().length, 0)
  assert.equal(JSON.stringify(f.vault.db), before); assert.equal(f.sent.length, 0)
  assert.equal(f.pipeline.limitsFor(f.grant.id).rate.tokens_now, 2)
  assert.equal((await f.pipeline.preflight(f.req({ headers: [['av-session', f.token]] }), { assumePlaceholder: true })).would, 'hold')
  f.grant.policy.methods = ['HEAD']
  assert.equal((await f.pipeline.handle(f.req())).status, 403)
})

test('preflight denial never trips and the eleventh call is throttled', async t => {
  const f = fixture(t)
  let observed = 0; f.pipeline.tripwires.observe = () => { observed++ }
  const request = f.req({ method: 'POST', body: Buffer.from(f.ph) })
  for (let i = 0; i < 10; i++) assert.equal((await f.pipeline.preflight(request)).would, 'deny')
  await assert.rejects(f.pipeline.preflight(request), e => e.rule === 'preflight_rate')
  assert.equal(observed, 0)
})

test('tripwires revoke only authenticated matching session and deny its approvals', async t => {
  const f = fixture(t, { approval: 'each' })
  await f.pipeline.handle(f.req())
  f.vault.getSettings = () => ({ tripwires: { enabled: true } })
  const second = f.vault.createSession({ label: 'other' }).session
  assert.equal(f.pipeline.tripwires.observe({ sessionId: null, code: 'AV_PH_REPLAY' }), null)
  f.vault.burnPlaceholder(f.row.id)
  // Approval is granted so this replay reaches the consume check.
  f.pipeline.decideApproval(f.pipeline.pendingApprovals()[0].id, true)
  assert.equal(problem(await f.pipeline.handle(f.req())).code, 'AV_PH_REPLAY')
  assert.equal(f.session.state, 'revoked'); assert.equal(second.state, 'active')
  assert.equal(f.pipeline.pendingApprovals().length, 0)
  assert.equal(problem(await f.pipeline.handle(f.req())).code, 'AV_SESSION_REVOKED')
})

test('tripwires default off; panic hook awaits and reports unwired or failed denial honestly', async t => {
  for (const mode of ['off', 'unwired', 'wired', 'failed']) {
    const f = fixture(t)
    f.vault.getSettings = () => ({ tripwires: { enabled: mode !== 'off', rules: [{ id: 'panic', codes: ['AV_PH_REPLAY'], threshold: 1, window_s: 10, action: 'panic' }] } })
    if (mode === 'wired') f.pipeline.onPanic = async () => ({ session_requests_denied: 3 })
    if (mode === 'failed') f.pipeline.onPanic = async () => { throw Error('failure') }
    await f.pipeline.tripwires.observe({ sessionId: f.session.id, code: 'AV_PH_REPLAY' })
    assert.equal(f.session.state, mode === 'off' ? 'active' : 'revoked')
    if (mode !== 'off') assert.equal(f.pipeline.tripwires.lastPanic.denied_session_requests, mode === 'wired' ? 3 : null)
    const partial = f.vault.audit.read().filter((r) => r.kind === 'tripwire.panic_partial')
    assert.equal(partial.length, mode === 'failed' ? 1 : 0)
  }
})

test('legacy decimal budgets work while noncanonical values never reach comparisons', async t => {
  const f = fixture(t, { budget: { unit: 'requests', limit: '2' } })
  assert.equal((await f.pipeline.handle(f.req())).status, 200)
  assert.equal((await f.pipeline.handle(f.req())).status, 200)
  assert.equal(problem(await f.pipeline.handle(f.req())).rule, 'budget')
  for (const bad of ['', '5.5', '-1', '1e3', 'abc', NaN, Infinity]) {
    f.grant.policy.budget.limit = bad
    const denied = await f.pipeline.handle(f.req())
    assert.equal(problem(denied).rule, 'budget_invalid')
  }
})

test('a held request previews its label, a redacted secret and no placeholder, token or audit body', async t => {
  const f = fixture(t, { approval: 'each' })
  f.cred.fields[0].sites.push('json:/auth')
  const text = `private comment ${SECRET} ${f.token}`
  const result = await f.pipeline.handle(f.req({ method: 'POST', body: Buffer.from(JSON.stringify({ auth: f.ph, text })), headers: [...f.req().headers, ['content-type', 'application/json'], ['x-trace', 'ordinary-header']] }))
  assert.equal(result.status, 202, result.body.toString())
  const preview = f.pipeline.pendingApprovals()[0].preview
  assert.ok(preview.body.text.includes('«test.token @ JSON body at /auth»'), preview.body.text)
  assert.ok(preview.body.text.includes('[[av:redacted:test]]'))
  assert.ok(preview.body.text.includes('«session token»'))
  assert.ok(preview.body.text.includes('private comment'), 'an ordinary comment is shown')
  assert.deepEqual(preview.headers.find(([n]) => n === 'x-trace'), ['x-trace', 'ordinary-header'])
  assert.ok(!preview.headers.some(([n]) => n === 'authorization' || n.startsWith('av-')))
  for (const value of [f.ph, SECRET, f.token]) assert.ok(!JSON.stringify(preview).includes(value))
  assert.ok(!JSON.stringify(f.vault.audit.read()).includes('private comment'))
  assert.equal(f.pipeline.approvalStatus(f.pipeline.pendingApprovals()[0].id).preview, undefined)
})

// The pipeline refuses an encoded placeholder before any approval exists, so
// the preview's own handling of one is tested on the builder directly.
test('the preview builder replaces encoded placeholders, keeps duplicate JSON keys as sent, and stays under 8 KiB', async t => {
  const f = fixture(t, { approval: 'each' })
  const encoded = encodeURIComponent(f.ph).replace(/\./g, '%2E')
  const base64 = Buffer.from(f.ph).toString('base64')
  const scrub = (text) => text.split(SECRET).join('[[av:redacted:test]]')
  const build = (body, extra = {}) => approvalPreview({
    req: { method: 'POST', path: '/x', query: `q=${encoded}`, headers: [['content-type', 'application/json'], ['authorization', `Bearer ${f.ph}`], ['x-carrier', `Bearer ${f.ph}`]], body: Buffer.from(body), ...extra },
    decision: { method: 'POST', host: 'api.example.test', path: '/x' },
    substitutions: [{ text: f.ph, label: 'test.token', location: 'header authorization', part: 'headers' }],
    scrub,
  })
  const preview = build(JSON.stringify({ a: encoded, b: base64, c: SECRET }))
  const all = JSON.stringify(preview)
  assert.ok(preview.body.text.includes('«placeholder»'))
  for (const value of [f.ph, encoded, base64, SECRET]) assert.ok(!all.includes(value), value)
  assert.deepEqual(preview.headers.find(([n]) => n === 'x-carrier'), ['x-carrier', 'Bearer «test.token @ header authorization»'])
  assert.deepEqual(preview.query, [['q', '«test.token @ header authorization»']])
  // Two values under one key: shown as sent, both of them, not pretty-printed to one.
  const dup = build('{"channel":"general","channel":"secret-ops"}')
  assert.ok(dup.body.text.includes('general') && dup.body.text.includes('secret-ops'))
  const big = build(JSON.stringify({ x: 'y'.repeat(50_000) }), { query: 'q=' + 'z'.repeat(20_000) })
  assert.ok(Buffer.byteLength(JSON.stringify(big)) <= 8192)
  assert.equal(big.body.truncated, true)
})

test('preflight expiration has no state changes and uses the shared expiry predicates', async t => {
  const f = fixture(t, { approval: 'each' })
  for (const [expires_at, infinite, live] of [
    [new Date(Date.now() + 60000).toISOString(), false, true],
    [new Date(Date.now() - 60000).toISOString(), false, false],
    [null, true, true], [null, false, false], ['invalid', false, false],
  ]) {
    f.session.expires_at = expires_at; f.session.infinite = infinite
    const before = JSON.stringify(f.vault.db)
    if (live) assert.equal((await f.pipeline.preflight(f.req())).would, 'hold')
    else await assert.rejects(f.pipeline.preflight(f.req()), e => e.code === 'AV_SESSION_EXPIRED')
    assert.equal(JSON.stringify(f.vault.db), before)
  }
  f.session.infinite = true; f.session.expires_at = null
  f.grant.expires_at = new Date(Date.now() - 60000).toISOString()
  const before = JSON.stringify(f.vault.db)
  const result = await f.pipeline.preflight(f.req())
  assert.equal(result.would, 'deny'); assert.equal(result.checks.at(-1).code, 'AV_GRANT_EXPIRED')
  assert.equal(JSON.stringify(f.vault.db), before)
})

test('expired grant fallback keeps its specific error after store marked it expired', async t => {
  const f = fixture(t)
  f.grant.state = 'expired'
  f.vault.findGrant = () => f.grant
  assert.equal(problem(await f.pipeline.handle(f.req())).code, 'AV_GRANT_EXPIRED')
})

test('quarantine tripwire pauses only its credential and leaves other sessions active', t => {
  const f = fixture(t)
  f.vault.getSettings = () => ({ tripwires: { enabled: true, rules: [{ id: 'quarantine', codes: ['AV_BAD_LOCATION'], threshold: 1, window_s: 10, action: 'quarantine_credential' }] } })
  f.vault.setQuarantine = (slug, patch) => { f.vault.findCredential(slug).quarantine = patch }
  const rule = f.pipeline.tripwires.observe({ sessionId: f.session.id, credentialId: f.cred.id, code: 'AV_BAD_LOCATION' })
  assert.equal(rule.id, 'quarantine'); assert.equal(f.cred.quarantine.by, 'tripwire'); assert.equal(f.session.state, 'active')
})

// ------------------------------------- round 2: checked one, sent another

// A hop is a body-less GET, and every payload rule that can read one applies
// to it. Only the query rules were kept, so a Location could carry a GraphQL
// document the grant denies, and it went out with the credential.
test('a redirect hop is held to the GraphQL rules a direct request is held to', async t => {
  const graphql = { operations: ['query'], deny_fields: ['createDeployKey'] }
  for (const document of [
    'mutation { createDeployKey(input:{title:"x"}) { id } }',
    'mutation { innocent: createDeployKey(input:{title:"x"}) { id } }',
    'query A { viewer { id } } mutation B { createDeployKey(input:{title:"x"}) { id } }',
  ]) {
    const location = `https://api.example.test/graphql?query=${encodeURIComponent(document)}`
    const f = fixture(t, { redirects: { max: 2 }, payload: { graphql } }, { upstream: () => ({ status: 302, headers: { location }, body: Buffer.from('go') }) })
    const result = await f.pipeline.handle(f.req())
    assert.equal(result.status, 302); assert.equal(result.headers['av-redirect-stopped'], 'path', document)
    assert.equal(f.sent.length, 1, document); assert.equal(f.grant.budget_used, 1)
  }
  // The operation type alone, with no field denied.
  const op = fixture(t, { redirects: { max: 2 }, payload: { graphql: { operations: ['query'] } } }, { upstream: () => ({ status: 302, headers: { location: `/graphql?query=${encodeURIComponent('mutation { a }')}` }, body: Buffer.alloc(0) }) })
  assert.equal((await op.pipeline.handle(op.req())).headers['av-redirect-stopped'], 'path'); assert.equal(op.sent.length, 1)
  // Control: a query the grant allows is followed.
  let n = 0
  const ok = fixture(t, { redirects: { max: 2 }, payload: { graphql } }, { upstream: () => (++n === 1 ? { status: 302, headers: { location: `/graphql?query=${encodeURIComponent('{ viewer { id } }')}` }, body: Buffer.alloc(0) } : { status: 200, headers: {}, body: Buffer.from('done') }) })
  const followed = await ok.pipeline.handle(ok.req())
  assert.equal(followed.status, 200); assert.equal(followed.body.toString(), 'done'); assert.equal(ok.sent.length, 2)
})

test('a redirect hop answers to the body rules as a body-less request, not to none', async t => {
  const hop = (payload) => {
    let n = 0
    return fixture(t, { redirects: { max: 2 }, payload }, { upstream: () => (++n === 1 ? { status: 302, headers: { location: '/next' }, body: Buffer.alloc(0) } : { status: 200, headers: {}, body: Buffer.from('done') }) })
  }
  // The first request has a body; the hop has none, so a required field is missing.
  const required = hop({ json: { '/confirm': { required: true } } })
  const result = await required.pipeline.handle(required.req({ method: 'GET', headers: [...required.req().headers, ['content-type', 'application/json']], body: Buffer.from('{"confirm":true}') }))
  assert.equal(result.headers['av-redirect-stopped'], 'path'); assert.equal(required.sent.length, 1)
  // A rule that an absent body satisfies leaves the hop alone.
  const absent = hop({ json: { '/force': { absent: true } }, form: { mode: { one_of: ['safe'] } } })
  const done = await absent.pipeline.handle(absent.req())
  assert.equal(done.status, 200); assert.equal(absent.sent.length, 2)
})

// Content-Type was read from the first copy and sent from the last.
test('a single-valued header sent twice, differently, is refused before anything is sent', async t => {
  const json = ['content-type', 'application/json']
  for (const [label, extra] of [
    ['same case, different value', [json, ['content-type', 'application/x-www-form-urlencoded']]],
    ['different case, different value', [json, ['Content-Type', 'application/x-www-form-urlencoded']]],
    ['different case, same value', [json, ['Content-Type', 'application/json']]],
    ['one entry holding two values', [['content-type', ['application/json', 'application/x-www-form-urlencoded']]]],
    ['content-encoding', [json, ['content-encoding', 'identity'], ['Content-Encoding', 'gzip']]],
    ['content-length', [json, ['content-length', '18'], ['content-length', '2']]],
    ['transfer-encoding', [json, ['transfer-encoding', 'chunked'], ['Transfer-Encoding', 'identity']]],
  ]) {
    const f = fixture(t, { payload: { json: { '/channel': { one_of: ['safe'] } } } })
    const result = await f.pipeline.handle(f.req({ method: 'POST', headers: [...f.req().headers, ...extra], body: Buffer.from('{"channel":"safe"}') }))
    assert.equal(result.status, 403, label); assert.equal(problem(result).code, 'AV_POLICY_DENIED'); assert.equal(problem(result).rule, 'header_duplicate', label)
    assert.equal(f.sent.length, 0, label); assert.equal(f.row.uses, 0, label); assert.equal(f.grant.budget_used, 0, label)
  }
  // Two Authorization headers: one checked for a session, the other sent.
  const auth = fixture(t)
  const twice = await auth.pipeline.handle(auth.req({ headers: [['host', 'localhost'], ['authorization', `Bearer ${auth.token}`], ['Authorization', `Bearer ${auth.ph}`]] }))
  assert.equal(problem(twice).rule, 'header_duplicate'); assert.equal(auth.sent.length, 0)
  // Preflight folds the same way, and refuses such a request outright, as it
  // does one it cannot authenticate.
  const pre = fixture(t, { payload: { json: { '/channel': { one_of: ['safe'] } } } })
  const before = JSON.stringify(pre.vault.db)
  await assert.rejects(pre.pipeline.preflight(pre.req({ method: 'POST', headers: [...pre.req().headers, json, ['Content-Type', 'text/plain']], body: Buffer.from('{"channel":"safe"}') })), (e) => e.rule === 'header_duplicate')
  assert.equal(JSON.stringify(pre.vault.db), before)
})

test('one Content-Type, or an exact repeat of it, is checked and sent as that one value', async t => {
  const json = fixture(t, { payload: { json: { '/channel': { one_of: ['safe'] } } } })
  for (const extra of [[['content-type', 'application/json']], [['content-type', 'application/json'], ['content-type', 'application/json']]]) {
    const result = await json.pipeline.handle(json.req({ method: 'POST', headers: [...json.req().headers, ...extra], body: Buffer.from('{"channel":"safe"}') }))
    assert.equal(result.status, 200, result.body.toString())
    assert.deepEqual(Object.entries(json.sent.at(-1).headers).filter(([k]) => k.toLowerCase() === 'content-type'), [['content-type', 'application/json']])
  }
  const form = fixture(t, { payload: { form: { channel: { one_of: ['safe'] } } } })
  const ok = await form.pipeline.handle(form.req({ method: 'POST', headers: [...form.req().headers, ['Content-Type', 'application/x-www-form-urlencoded']], body: Buffer.from('channel=safe') }))
  assert.equal(ok.status, 200, ok.body.toString()); assert.equal(form.sent[0].headers['Content-Type'], 'application/x-www-form-urlencoded')
  const refused = await form.pipeline.handle(form.req({ method: 'POST', headers: [...form.req().headers, ['content-type', 'application/x-www-form-urlencoded']], body: Buffer.from('channel=other') }))
  assert.equal(refused.status, 403); assert.equal(form.sent.length, 1)
})

// Two keys differing only in case reached the client, and Node kept the last.
test('a repeated list header goes upstream once per name, carrying every value', async t => {
  const f = fixture(t)
  const result = await f.pipeline.handle(f.req({ headers: [...f.req().headers, ['X-Trace', 'checked'], ['x-trace', 'other'], ['accept', 'a/b']] }))
  assert.equal(result.status, 200)
  const names = Object.keys(f.sent[0].headers).filter((k) => k.toLowerCase() === 'x-trace')
  assert.deepEqual(names, ['X-Trace']); assert.deepEqual(f.sent[0].headers['X-Trace'], ['checked', 'other'])
  assert.equal(f.sent[0].headers.accept, 'a/b')
  // A placeholder in the second copy is substituted there, and only there.
  f.cred.fields[0].sites.push('header:x-api-key')
  const ph = f.vault.issuePlaceholder({ grantId: f.grant.id, field: 'token', maxUses: 5 }).placeholder
  const keyed = await f.pipeline.handle(f.req({ headers: [...f.req().headers, ['x-api-key', 'not-a-secret'], ['X-Api-Key', ph]] }))
  assert.equal(keyed.status, 200, keyed.body.toString())
  assert.deepEqual(f.sent[1].headers['x-api-key'], ['not-a-secret', SECRET])
  assert.ok(!JSON.stringify(f.sent[1].headers).includes(ph))
})

// The query rules read the string as written; the URL holds less of it.
test('a query a URL would cut or rewrite is refused before the payload rules read it', async t => {
  const policy = { payload: { query: { dry_run: { required: true }, force: { absent: true }, op: {} }, query_strict: true } }
  for (const query of ['op=delete#&dry_run=true', 'dry_run=true&fo\nrce=true', 'dry_run=true&fo\trce=true', 'dry_run=true&fo\rrce=true', 'dry_run=true&op=x ']) {
    const f = fixture(t, policy)
    const result = await f.pipeline.handle(f.req({ query }))
    assert.equal(result.status, 403, JSON.stringify(query)); assert.equal(problem(result).rule, 'query_unsendable')
    assert.equal(f.sent.length, 0); assert.equal(f.row.uses, 0)
  }
  // Control: the same characters percent-encoded are values like any other.
  const f = fixture(t, policy)
  const result = await f.pipeline.handle(f.req({ query: 'dry_run=true&op=a%23b%0A%20' }))
  assert.equal(result.status, 200, result.body.toString()); assert.ok(f.sent[0].url.endsWith('?dry_run=true&op=a%23b%0A%20'))
})

// ------------------------------------- round 3: a hop sends what it was checked as

// A hop copied the request's headers. It was checked as a GET and sent with
// X-HTTP-Method-Override: DELETE, which plenty of frameworks run as a DELETE.
const ROUTES = [{ methods: ['GET', 'DELETE'], paths: ['/public/**'] }, { methods: ['GET'], paths: ['/admin/**'] }]
const hopFixture = (t, policy, location, status = 302) => {
  let n = 0
  return fixture(t, { methods: ['GET', 'HEAD', 'POST', 'DELETE'], redirects: { max: 2 }, ...policy }, { upstream: () => (++n === 1 ? { status, headers: { location }, body: Buffer.alloc(0) } : { status: 200, headers: {}, body: Buffer.from('done') }) })
}
const lowerKeys = headers => Object.keys(headers).map(k => k.toLowerCase()).sort()

test('a request a method override made a write does not have its redirect followed', async t => {
  // Grok's probe: GET /public/start carrying a DELETE override, sent to
  // /admin/keys where the grant allows only GET. The upstream ran the first
  // request as a DELETE, and F6 follows nothing but a GET or HEAD.
  for (const override of ['X-HTTP-Method-Override', 'x-http-method', 'X-Method-Override']) {
    const f = hopFixture(t, { routes: ROUTES }, 'https://api.example.test/admin/keys')
    const result = await f.pipeline.handle(f.req({ path: '/p/test/public/start', headers: [...f.req().headers, [override, 'DELETE']] }))
    assert.equal(result.status, 302, override); assert.equal(result.headers['av-redirect-stopped'], 'approval', override)
    assert.equal(f.sent.length, 1, override); assert.equal(f.grant.budget_used, 1)
  }
  // Under on-write, the human granted the first request only, not its hop.
  const held = hopFixture(t, { methods: ['GET', 'DELETE'], approval: 'on-write' }, '/other')
  const req = () => held.req({ headers: [...held.req().headers, ['X-HTTP-Method-Override', 'DELETE']] })
  assert.equal((await held.pipeline.handle(req())).status, 202)
  held.pipeline.decideApproval(held.pipeline.pendingApprovals()[0].id, true)
  const result = await held.pipeline.handle(req())
  assert.equal(result.headers['av-redirect-stopped'], 'approval'); assert.equal(held.sent.length, 1)
})

test('a followed redirect sends nothing of the agent\'s but the credential and the hop allowlist', async t => {
  // An override that names GET leaves the request a GET, so it is followed,
  // and the override is not carried to the hop either.
  const f = hopFixture(t, { routes: ROUTES }, 'https://api.example.test/admin/keys')
  const result = await f.pipeline.handle(f.req({
    path: '/p/test/public/start',
    headers: [...f.req().headers, ['X-HTTP-Method-Override', 'GET'], ['content-type', 'application/json'], ['range', 'bytes=0-1'], ['if-match', '"x"'], ['x-custom', 'dropped'], ['accept', 'application/json'], ['user-agent', 'probe/1']],
  }))
  assert.equal(result.status, 200); assert.equal(f.sent.length, 2)
  const hop = f.sent[1]
  assert.equal(hop.method, 'GET'); assert.equal(hop.body, null); assert.equal(new URL(hop.url).pathname, '/admin/keys')
  // No override, no body or conditional header, nothing the agent chose
  // beyond Accept and User-Agent.
  assert.deepEqual(lowerKeys(hop.headers), ['accept', 'accept-encoding', 'authorization', 'host', 'user-agent'])
  assert.equal(hop.headers.authorization, `Bearer ${SECRET}`); assert.equal(hop.headers['accept-encoding'], 'identity')
  assert.equal(hop.headers.host, 'api.example.test'); assert.equal(hop.headers.accept, 'application/json'); assert.equal(hop.headers['user-agent'], 'probe/1')
})

test('a credential declared at a body or framing header is not sent on a hop', async t => {
  const f = hopFixture(t, {}, '/next')
  f.vault.db.credentials[f.cred.id].fields.find(x => x.name === 'token').sites = ['header:content-type']
  const result = await f.pipeline.handle(f.req({ headers: [['host', 'localhost'], ['av-session', f.token], ['content-type', f.ph]] }))
  assert.equal(result.status, 200, result.body?.toString()); assert.equal(f.sent[0].headers['content-type'], SECRET)
  assert.deepEqual(lowerKeys(f.sent[1].headers), ['accept-encoding', 'host'])
})

test('a Location carrying _method is not followed', async t => {
  for (const location of ['/next?_method=DELETE', '/next?a=1&%5Fmethod=delete', '/next?_METHOD=PUT']) {
    const f = hopFixture(t, {}, location)
    const result = await f.pipeline.handle(f.req())
    assert.equal(result.status, 302, location); assert.equal(result.headers['av-redirect-stopped'], 'path', location); assert.equal(f.sent.length, 1)
  }
})

test('a hop is checked as the method it is sent with: 307 and 308 keep it, 301 to 303 send a GET', async t => {
  // A POST that gets a 307 or 308 is a POST to the new location, and F6 never
  // follows one. It is not turned into a GET to slip past that.
  for (const status of [303, 307, 308]) {
    const f = hopFixture(t, { routes: [{ methods: ['POST', 'GET'], paths: ['/**'] }] }, '/next', status)
    const result = await f.pipeline.handle(f.req({ method: 'POST', headers: [...f.req().headers, ['content-type', 'application/json']], body: Buffer.from('{}') }))
    assert.equal(result.status, status); assert.equal(result.headers['av-redirect-stopped'], 'approval', String(status)); assert.equal(f.sent.length, 1)
  }
  // A HEAD stays a HEAD, and a 307 HEAD is checked as a HEAD: a route that
  // allows only GET there stops it.
  for (const status of [302, 303, 307, 308]) {
    const f = hopFixture(t, {}, '/next', status)
    assert.equal((await f.pipeline.handle(f.req({ method: 'HEAD' }))).status, 200); assert.equal(f.sent[1].method, 'HEAD', String(status))
    const g = hopFixture(t, { routes: [{ methods: ['HEAD'], paths: ['/ok'] }, { methods: ['GET'], paths: ['/next'] }] }, '/next', status)
    const stopped = await g.pipeline.handle(g.req({ method: 'HEAD' }))
    assert.equal(stopped.headers['av-redirect-stopped'], 'path', String(status)); assert.equal(g.sent.length, 1)
  }
  for (const status of [301, 302, 303, 307, 308]) {
    const f = hopFixture(t, {}, '/next', status)
    assert.equal((await f.pipeline.handle(f.req())).status, 200); assert.equal(f.sent[1].method, 'GET')
  }
})

test('a method override on a direct request is still refused, and an ordinary redirect still follows', async t => {
  const f = hopFixture(t, { routes: ROUTES }, '/public/next')
  const denied = await f.pipeline.handle(f.req({ path: '/p/test/admin/keys', headers: [...f.req().headers, ['X-HTTP-Method-Override', 'DELETE']] }))
  assert.equal(denied.status, 403); assert.equal(problem(denied).rule, 'routes'); assert.equal(f.sent.length, 0)
  // Control: a redirect within policy, the credential carried to the hop.
  const result = await f.pipeline.handle(f.req({ path: '/p/test/public/start' }))
  assert.equal(result.status, 200); assert.equal(result.body.toString(), 'done'); assert.equal(f.sent.length, 2)
  assert.equal(f.sent[1].url, 'https://api.example.test/public/next'); assert.equal(f.sent[1].headers.authorization, `Bearer ${SECRET}`)
})

// ------------------------------------- round 4: an override in a field, and what a hop keeps

// Rails and Laravel run a POST whose form body says `_method=DELETE` as a
// DELETE, and Laravel reads `_method` from the query and a JSON body too.
// Only the override headers were read, so the request was checked as a POST.
const form = ['content-type', 'application/x-www-form-urlencoded']
const json = ['content-type', 'application/json']
const multipart = ['content-type', 'multipart/form-data; boundary=XyZ']
const part = (name, value) => `--XyZ\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`

test('a method-override field naming another method is refused, and nothing is sent', async t => {
  for (const [label, over] of [
    ['query _method=DELETE', { query: '_method=DELETE' }],
    ['form body _method=DELETE', { extra: [form], body: 'a=1&_method=DELETE' }],
    ['JSON {"_method":"DELETE"}', { extra: [json], body: '{"_method":"DELETE"}' }],
    ['lower case value', { query: 'x=1&_method=delete' }],
    ['__method', { query: '__method=DELETE' }],
    ['percent-encoded name', { query: '%5Fmethod=DELETE' }],
    ['upper case name', { extra: [form], body: '_METHOD=DELETE' }],
    ['PHP reads .method as _method', { query: '.method=DELETE' }],
    ['PHP reads " method" as _method', { query: '+method=DELETE' }],
    ['bracketed', { extra: [form], body: '_method[]=DELETE' }],
    ['semicolon-separated', { query: 'a=1;_method=DELETE' }],
    ['override header spelled as a field', { query: 'X-HTTP-Method-Override=DELETE' }],
    ['form copy after a matching one', { extra: [form], body: '_method=POST&_method=DELETE' }],
    ['JSON duplicate, last matches', { extra: [json], body: '{"_method":"DELETE","_method":"POST"}' }],
    ['JSON duplicate, first matches', { extra: [json], body: '{"_method":"POST", "a":{"b":[1,"}"]},"_method":"DELETE"}' }],
    ['JSON non-string value', { extra: [json], body: '{"_method":["DELETE"]}' }],
    ['JSON escaped key', { extra: [json], body: ' { "a" : "x\\"," , "\\u005fmethod" : "DELETE" } ' }],
    ['JSON +json type', { extra: [['content-type', 'application/vnd.api+json']], body: '{"_method":"PUT"}' }],
    ['multipart', { extra: [multipart], body: `${part('a', '1')}${part('_method', 'DELETE')}--XyZ--\r\n` }],
  ]) {
    await t.test(label, async t => {
      // DELETE is allowed: the refusal is the override's, not the methods list's.
      const f = fixture(t, { methods: ['GET', 'POST', 'DELETE'] })
      const result = await f.pipeline.handle(f.req({ method: 'POST', query: over.query ?? '', headers: [...f.req().headers, ...(over.extra ?? [])], body: over.body == null ? null : Buffer.from(over.body) }))
      assert.equal(result.status, 403); assert.equal(problem(result).code, 'AV_POLICY_DENIED'); assert.equal(problem(result).rule, 'method_override')
      assert.equal(f.sent.length, 0); assert.equal(f.row.uses, 0); assert.equal(f.grant.budget_used, 0)
    })
  }
  // On a GET too, and preflight says the same without changing anything.
  const g = fixture(t)
  assert.equal(problem(await g.pipeline.handle(g.req({ query: '_method=DELETE' }))).rule, 'method_override'); assert.equal(g.sent.length, 0)
  const before = JSON.stringify(g.vault.db)
  const predicted = await g.pipeline.preflight(g.req({ query: '_method=DELETE' }))
  assert.equal(predicted.would, 'deny'); assert.equal(predicted.checks.at(-1).rule, 'method_override')
  assert.equal(JSON.stringify(g.vault.db), before)
})

test('a method-override field naming the request\'s own method is sent as it is', async t => {
  for (const [label, over] of [
    ['query _method=POST', { query: '_method=POST' }],
    ['form _method=post', { extra: [form], body: '_method=post&a=1' }],
    ['JSON {"_method":"POST"}', { extra: [json], body: '{"_method":"POST"}' }],
    ['multipart', { extra: [multipart], body: `${part('_method', 'POST')}--XyZ--\r\n` }],
    // Not an override to anything that reads one: nested, a value, another name.
    ['nested JSON field', { extra: [json], body: '{"a":{"_method":"DELETE"}}' }],
    ['a value, not a name', { query: 'note=_method%3DDELETE' }],
    ['another name', { query: 'my_method=DELETE' }],
    ['a body no framework reads as form', { extra: [['content-type', 'text/plain']], body: '_method=DELETE' }],
  ]) {
    await t.test(label, async t => {
      const f = fixture(t)
      const result = await f.pipeline.handle(f.req({ method: 'POST', query: over.query ?? '', headers: [...f.req().headers, ...(over.extra ?? [])], body: over.body == null ? null : Buffer.from(over.body) }))
      assert.equal(result.status, 200, result.body.toString()); assert.equal(f.sent.length, 1); assert.equal(f.sent[0].method, 'POST')
    })
  }
})

// A hop carried only Accept and User-Agent, so an upstream that requires an
// API-version header answered the redirected request with an error.
test('a hop keeps the API-version headers a provider needs, and never a cookie, override or forwarding header', async t => {
  let n = 0
  const f = fixture(t, { hosts: ['api.anthropic.com'], redirects: { max: 2 } }, { kind: 'anthropic', upstream: () => (++n === 1 ? { status: 302, headers: { location: '/v1/models?limit=5' }, body: Buffer.alloc(0) } : { status: 200, headers: {}, body: Buffer.from('done') }) })
  f.vault.db.credentials[f.cred.id].fields.find(x => x.name === 'token').sites = ['header:x-api-key']
  const result = await f.pipeline.handle(f.req({
    path: '/p/test/v1/models',
    headers: [
      ['host', 'localhost'], ['av-session', f.token], ['x-api-key', f.ph],
      ['anthropic-version', '2023-06-01'], ['anthropic-beta', 'tools-2024'], ['accept-language', 'en'], ['cache-control', 'no-cache'],
      ['if-none-match', '"e"'], ['if-modified-since', 'Mon, 26 Oct 2026 00:00:00 GMT'],
      ['cookie', 'session=agent'], ['X-HTTP-Method-Override', 'GET'], ['x-forwarded-for', '10.0.0.1'], ['x-forwarded-host', 'evil.test'], ['range', 'bytes=0-1'], ['authorization', 'Bearer agent-chosen'],
    ],
  }))
  assert.equal(result.status, 200, result.body.toString()); assert.equal(f.sent.length, 2)
  const hop = f.sent[1].headers
  assert.deepEqual(lowerKeys(hop), ['accept-encoding', 'accept-language', 'anthropic-beta', 'anthropic-version', 'cache-control', 'host', 'if-modified-since', 'if-none-match', 'x-api-key'])
  assert.equal(hop['anthropic-version'], '2023-06-01'); assert.equal(hop['x-api-key'], SECRET); assert.equal(hop.host, 'api.anthropic.com')
  // The OpenAI-shaped ones too.
  let m = 0
  const o = fixture(t, { redirects: { max: 2 } }, { upstream: () => (++m === 1 ? { status: 302, headers: { location: '/next' }, body: Buffer.alloc(0) } : { status: 200, headers: {}, body: Buffer.from('done') }) })
  await o.pipeline.handle(o.req({ headers: [...o.req().headers, ['OpenAI-Beta', 'assistants=v2'], ['openai-organization', 'org'], ['openai-project', 'p'], ['x-api-version', '1'], ['api-version', '2'], ['Cookie', 'a=b']] }))
  assert.deepEqual(lowerKeys(o.sent[1].headers), ['accept-encoding', 'api-version', 'authorization', 'host', 'openai-beta', 'openai-organization', 'openai-project', 'x-api-version'])
})

// ------------------------------------- round 5: one view of the request, checked and sent

// Round 4 refused `.method=DELETE` on a direct request and followed a hop to
// `?.method=DELETE` as a GET, because the hop looked for `_method` alone. And
// the payload rules read a query with URLSearchParams, which does not split
// on `;`, while Rack does. Both are one request read two ways. The fix reads
// every request into one view (src/core/request-view.js) that every check
// reads and every send is built from, so these tests hold each check to that
// view on the direct path and on a hop alike.

// Each spelling a framework reads as `_method`, or as an override header
// spelled as a field.
const SPELLINGS = [
  '_method=DELETE', '%5Fmethod=DELETE', '_METHOD=PUT', '__method=DELETE', '.method=DELETE', '%2Emethod=DELETE',
  '_method[]=DELETE', '_method%5B%5D=DELETE', '_method[0]=DELETE', '+method=DELETE', '%20method=DELETE',
  'x-http-method-override=DELETE', 'X-HTTP-Method-Override=DELETE', 'x_http_method=DELETE', 'X-Method-Override=PATCH',
  'a=1;_method=DELETE', 'a=1;__method=DELETE', '__method=DELETE&__method=GET',
  // GET to a reader that splits on `;`, and `GET;force=1` to one that does not.
  '.method=GET;force=1',
]
const EVERY_METHOD = { methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'] }
const FORCE = { payload: { query: { force: { absent: true }, dry_run: { required: true } } } }

test('Grok round 5, finding 1: a Location naming another method in a folded spelling is not followed', async t => {
  // The routes scenario: /admin allows only GET, and the hop was checked as
  // GET /admin/keys and sent with `.method=DELETE` and the credential.
  const f = hopFixture(t, { routes: ROUTES }, 'https://api.example.test/admin/keys?.method=DELETE')
  const result = await f.pipeline.handle(f.req({ path: '/p/test/public/start' }))
  assert.equal(result.status, 302); assert.equal(result.headers['av-redirect-stopped'], 'path'); assert.equal(f.sent.length, 1)
  // Under on-write a GET needs no human, so the hop was a DELETE no one approved.
  for (const query of ['.method=DELETE', 'a=1;_method=DELETE', '_method[]=DELETE', '__method=DELETE']) {
    const g = hopFixture(t, { methods: ['GET', 'DELETE'], approval: 'on-write', redirects: { max: 1 } }, `https://api.example.test/other?${query}`)
    const stopped = await g.pipeline.handle(g.req())
    assert.equal(stopped.status, 302, query); assert.equal(stopped.headers['av-redirect-stopped'], 'path', query)
    assert.equal(g.sent.length, 1, query); assert.equal(g.pipeline.pendingApprovals().length, 0, query)
  }
})

test('Grok round 5, finding 2: a ; in the query cannot hide a parameter from the payload rules', async t => {
  for (const policy of [FORCE, { payload: { ...FORCE.payload, query_strict: true } }]) {
    const f = fixture(t, policy)
    const result = await f.pipeline.handle(f.req({ query: 'dry_run=true;force=true' }))
    assert.equal(result.status, 403); assert.equal(problem(result).rule, 'request_ambiguous')
    assert.equal(f.sent.length, 0); assert.equal(f.row.uses, 0); assert.equal(f.grant.budget_used, 0)
  }
  // The same query in a Location, after a request that satisfied the rules.
  const h = hopFixture(t, FORCE, 'https://api.example.test/next?dry_run=true;force=true')
  const result = await h.pipeline.handle(h.req({ query: 'dry_run=true' }))
  assert.equal(result.status, 302); assert.equal(result.headers['av-redirect-stopped'], 'path'); assert.equal(h.sent.length, 1)
})

test('every override spelling is refused on a direct request and stops a hop', async t => {
  for (const query of SPELLINGS) {
    await t.test(query, async t => {
      const f = fixture(t, EVERY_METHOD)
      const direct = await f.pipeline.handle(f.req({ query }))
      assert.equal(direct.status, 403); assert.equal(problem(direct).rule, 'method_override'); assert.equal(f.sent.length, 0)
      const h = hopFixture(t, EVERY_METHOD, `/next?${query}`)
      const hop = await h.pipeline.handle(h.req())
      assert.equal(hop.status, 302); assert.equal(hop.headers['av-redirect-stopped'], 'path'); assert.equal(h.sent.length, 1)
    })
  }
  // A spelling that names the request's own method is no override at all,
  // on either path, and goes out as written.
  const f = fixture(t)
  assert.equal((await f.pipeline.handle(f.req({ query: 'a=1;.method=get' }))).status, 200); assert.ok(f.sent[0].url.endsWith('?a=1;.method=get'))
  const h = hopFixture(t, {}, '/next?_method[]=GET')
  assert.equal((await h.pipeline.handle(h.req())).status, 200); assert.equal(h.sent[1].url, 'https://api.example.test/next?_method[]=GET')
})

test('a ; query is refused under any payload rule on both paths, and goes out unchanged under none', async t => {
  // A rule that has nothing to do with the query still means the query is read.
  const rules = { payload: { json: { '/model': { max_length: 64 } } } }
  const f = fixture(t, rules)
  const result = await f.pipeline.handle(f.req({ query: 'a=1;b=2' }))
  assert.equal(result.status, 403); assert.equal(problem(result).rule, 'request_ambiguous'); assert.equal(f.sent.length, 0)
  const h = hopFixture(t, rules, '/next?a=1;b=2')
  assert.equal((await h.pipeline.handle(h.req())).headers['av-redirect-stopped'], 'path'); assert.equal(h.sent.length, 1)
  // No rules to disagree about: sent byte for byte, and the hop followed.
  const g = fixture(t)
  assert.equal((await g.pipeline.handle(g.req({ query: 'a=1;b=2' }))).status, 200); assert.ok(g.sent[0].url.endsWith('/ok?a=1;b=2'))
  const k = hopFixture(t, {}, '/next?a=1;b=2')
  assert.equal((await k.pipeline.handle(k.req())).status, 200); assert.equal(k.sent[1].url, 'https://api.example.test/next?a=1;b=2')
  // `%3B` is a character in a value after one decode, to every reader.
  const v = fixture(t, FORCE)
  assert.equal((await v.pipeline.handle(v.req({ query: 'dry_run=true&note=a%3Bforce%3Dtrue' }))).status, 200)
  assert.ok(v.sent[0].url.endsWith('?dry_run=true&note=a%3Bforce%3Dtrue'))
})

test('a name a server could fold onto a rule\'s name is refused, and a repeated name is a duplicate', async t => {
  for (const [query, rule] of [
    ['dry_run=true&FORCE=true', 'request_ambiguous'],
    ['dry_run=true&%66orce=true', 'request_ambiguous'],
    ['dry_run=true&force[]=true', 'request_ambiguous'],
    ['dry_run=true&Force=1', 'request_ambiguous'],
    // Satisfied for this reader and missing for one that does not decode
    // names, or that does not fold `.` into `_`.
    ['%64ry_run=true', 'request_ambiguous'],
    ['dry.run=true', 'request_ambiguous'],
    ['DRY_RUN=true', 'request_ambiguous'],
    ['dry_run=true&dry_run=false', 'payload_duplicate_key'],
    ['dry_run=true&%64ry_run=true', 'payload_duplicate_key'],
    ['dry_run=true&force=1&force=1', 'payload_duplicate_key'],
  ]) {
    const f = fixture(t, FORCE)
    const result = await f.pipeline.handle(f.req({ query }))
    assert.equal(result.status, 403, query); assert.equal(problem(result).rule, rule, query); assert.equal(f.sent.length, 0, query)
  }
  // A form body and a JSON body are read the same way.
  for (const [policy, type, body] of [
    [{ payload: { form: { force: { absent: true } } } }, form, 'a=1&FORCE=1'],
    [{ payload: { form: { force: { absent: true } } } }, form, 'a=1;force=1'],
    [{ payload: { json: { '/force': { absent: true } } } }, json, '{"a":1,"Force":true}'],
    [{ payload: { json: { '/opts/force': { absent: true } } } }, json, '{"opts":{"FORCE":true}}'],
  ]) {
    const f = fixture(t, policy)
    const result = await f.pipeline.handle(f.req({ method: 'POST', headers: [...f.req().headers, type], body: Buffer.from(body) }))
    assert.equal(result.status, 403, body); assert.equal(problem(result).rule, 'request_ambiguous', body); assert.equal(f.sent.length, 0, body)
  }
  // Controls: names that only look alike are other names.
  const f = fixture(t, FORCE)
  assert.equal((await f.pipeline.handle(f.req({ query: 'dry_run=true&forced=1&my_force=1&force_x=1' }))).status, 200)
  const j = fixture(t, { payload: { json: { '/force': { absent: true } } } })
  assert.equal((await j.pipeline.handle(j.req({ method: 'POST', headers: [...j.req().headers, json], body: Buffer.from('{"forced":true,"opts":{"Force":1}}') }))).status, 200)
})

// The property behind all of the above: whatever the gateway sends, every
// common reader of that request reads it within the policy. Requests are
// generated, sent through the real client to a local upstream, and what
// arrived there is read the way WHATWG, Rack, PHP and a case-blind binder
// read a query.
const OVERRIDE_NAMES = new Set(['_method', '__method', 'x-http-method-override', 'x_http_method_override', 'x-http-method', 'x_http_method', 'x-method-override', 'x_method_override'])
const decode = s => new URLSearchParams(`x=${s}`).get('x')
const pairsOf = (query, separator) => query.split(separator).filter(Boolean).map(p => { const i = p.indexOf('='); return i === -1 ? [decode(p), ''] : [decode(p.slice(0, i)), decode(p.slice(i + 1))] })
const READERS = {
  whatwg: q => [...new URLSearchParams(q)],
  rack: q => pairsOf(q, /[&;]/),
  // PHP: `&` only; a name read up to its first NUL with its leading spaces
  // dropped, then space and `.` read as `_`, and `name[...]` is the array
  // `name`.
  php: q => pairsOf(q, '&').map(([k, v]) => [k.split('\0')[0].replace(/^ +/, '').replace(/[ .]/g, '_').replace(/\[.*$/s, ''), v]),
  caseBlind: q => [...new URLSearchParams(q)].map(([k, v]) => [k.toLowerCase(), v]),
}
const random = seed => () => { seed = (seed + 0x6D2B79F5) | 0; let x = Math.imul(seed ^ (seed >>> 15), 1 | seed); x = (x + Math.imul(x ^ (x >>> 7), 61 | x)) ^ x; return ((x ^ (x >>> 14)) >>> 0) / 4294967296 }
function generatedQueries(n) {
  const next = random(5)
  const pick = list => list[Math.floor(next() * list.length)]
  const names = ['a', 'dry_run', 'force', 'note', '_method', '.method', '%5Fmethod', 'FORCE', '%66orce', 'dry.run', 'force[]', 'x-http-method-override', '__method', 'b+c', 'q%20x', '%64ry_run',
    // Names readers cut, trim or decode differently: a NUL, a space or `+`
    // at either end, a tab, another control character, non-ASCII, none.
    'force%00', 'force%00x', '_method%00', '+force', '++force', '%20force', '%20%20_method', '+_method', 'force+', 'force%20', '%09force', 'force%09', '%01_method', '%7Fforce', 'forc%C3%A9', '%C3%A9', '']
  const values = ['1', 'true', 'GET', 'DELETE', 'x%3By', 'a+b', '', '%26force%3D1']
  const out = []
  for (let i = 0; i < n; i++) {
    let q = next() < 0.6 ? 'dry_run=true' : ''
    for (let k = 1 + Math.floor(next() * 3); k > 0; k--) q += `${q ? pick(['&', '&', '&', ';']) : ''}${pick(names)}${next() < 0.9 ? `=${pick(values)}` : ''}`
    out.push(q)
  }
  return out
}
async function localUpstream(t) {
  const seen = []
  const server = createServer((req, res) => {
    seen.push({ method: req.method, url: req.url })
    const target = new URL(req.url, 'http://upstream').searchParams.get('to')
    if (req.url.startsWith('/start') && target !== null) { res.writeHead(302, { location: `/next?${target}` }); res.end(); return }
    res.writeHead(200, { 'content-type': 'text/plain' }); res.end('ok')
  })
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  t.after(() => { server.closeAllConnections(); server.close() })
  return { seen, host: `127.0.0.1:${server.address().port}` }
}
function localFixture(t, host, policy) {
  const dir = mkdtempSync(join(tmpdir(), 'av-gw-w2-view-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const vault = Vault.create(dir, { factor: 'none' })
  const added = vault.addCredential({ slug: 'test', kind: 'http', connector: { host }, fields: { token: SECRET }, sites: { token: ['header:authorization:Bearer'] } })
  const cred = vault.findCredential(added.slug)
  cred.connector.scheme = 'http'
  const { session, token } = vault.createSession({ label: 'view', policy: {} })
  const grant = vault.createGrant({ sessionId: session.id, credentialId: cred.id, fields: ['token'], policy: { hosts: ['127.0.0.1'], methods: ['GET', 'HEAD'], paths: ['/**'], budget: { unit: 'requests', limit: 100000 }, approval: 'auto', redirects: { max: 1 }, ...policy } })
  const ph = vault.issuePlaceholder({ grantId: grant.id, field: 'token' }).placeholder
  vault.chargeGrant ??= (id) => { const g = vault.db.grants[id]; g.budget_used++; g.counters.requests++; return true }
  const pipeline = new Pipeline(vault, { expiryMs: v => v == null ? Infinity : Date.parse(v), sessionExpiryMs: s => s.infinite === true && s.expires_at === null ? Infinity : s.expires_at == null ? -Infinity : Date.parse(s.expires_at) })
  return (path, query) => pipeline.handle({ method: 'GET', path, query, headers: [['host', 'localhost'], ['av-session', token], ['authorization', `Bearer ${ph}`]], body: null })
}
// What a reader of `query` sees that the policy forbids: an override naming
// another method, and under FORCE a `force` or a missing `dry_run`.
function violations(query, rules) {
  const out = []
  for (const [reader, read] of Object.entries(READERS)) {
    const pairs = read(query)
    if (pairs.some(([k, v]) => OVERRIDE_NAMES.has(k.toLowerCase()) && v.toUpperCase() !== 'GET')) out.push(`${reader}: override`)
    if (rules && pairs.some(([k]) => k === 'force')) out.push(`${reader}: force`)
    if (rules && !pairs.some(([k]) => k === 'dry_run')) out.push(`${reader}: no dry_run`)
  }
  return out
}

test('generated requests: what the policy read is what a local upstream received, and every reader reads it within the policy', async t => {
  const upstream = await localUpstream(t)
  const queries = generatedQueries(160)
  const tally = { sent: 0, refused: 0, hops: 0, hopsStopped: 0 }
  for (const policy of [FORCE, {}]) {
    const rules = !!policy.payload
    const send = localFixture(t, upstream.host, policy)
    for (const query of queries) {
      // Direct.
      const before = upstream.seen.length
      const result = await send('/p/test/ok', query)
      const arrived = upstream.seen.slice(before)
      if (result.status === 200) {
        tally.sent++
        assert.equal(arrived.length, 1, query)
        const sent = arrived[0].url.slice('/ok'.length).replace(/^\?/, '')
        // Byte for byte the query the view read, so the view's parameters
        // are the parameters that arrived.
        assert.equal(sent, requestView({ query }).query, query)
        assert.deepEqual(requestView({ query: sent }).params, requestView({ query }).params, query)
        assert.deepEqual(violations(sent, rules), [], query)
      } else {
        tally.refused++
        assert.equal(result.status, 403, `${query}: ${result.body}`); assert.equal(arrived.length, 0, query)
      }
      // The same query in a Location, after a request within the policy.
      const hopBefore = upstream.seen.length
      const hop = await send('/p/test/start', `dry_run=true&to=${encodeURIComponent(query)}`)
      const hopArrived = upstream.seen.slice(hopBefore)
      assert.equal(hopArrived[0]?.url.startsWith('/start?'), true, query)
      if (hopArrived.length === 2) {
        tally.hops++
        assert.equal(hop.status, 200, query)
        const sent = hopArrived[1].url.slice('/next'.length).replace(/^\?/, '')
        assert.equal(sent, new URL(`/next?${query}`, 'http://x').search.slice(1), query)
        assert.deepEqual(violations(sent, rules), [], query)
      } else {
        tally.hopsStopped++
        assert.equal(hopArrived.length, 1, query); assert.ok(hop.headers['av-redirect-stopped'], query)
      }
    }
  }
  // The generator has to have produced both outcomes on both paths, or
  // the assertions above were never reached.
  for (const [k, n] of Object.entries(tally)) assert.ok(n >= 20, `${k}: ${n}`)
})

test('ordinary traffic is untouched: & queries, provider APIs, and a redirect that keeps its version headers', async t => {
  const f = fixture(t, FORCE)
  const query = 'dry_run=true&limit=5&cursor=abc%3D%3D&tag=a+b&empty=&flag'
  assert.equal((await f.pipeline.handle(f.req({ query }))).status, 200); assert.ok(f.sent[0].url.endsWith(`/ok?${query}`))
  // An OpenAI-shaped JSON POST and an Anthropic-shaped GET with a query.
  const o = fixture(t, { hosts: ['api.openai.com'] }, { kind: 'openai' })
  assert.equal((await o.pipeline.handle(modelReq(o))).status, 200); assert.equal(o.sent[0].body.toString(), modelBody.toString())
  const a = fixture(t, { hosts: ['api.anthropic.com'] }, { kind: 'anthropic' })
  assert.equal((await a.pipeline.handle(a.req({ path: '/p/test/v1/models', query: 'limit=20&after_id=model_1' }))).status, 200)
  assert.equal(a.sent[0].url, 'https://api.anthropic.com/v1/models?limit=20&after_id=model_1')
  // GitHub needs its API version on every request, a redirected one included.
  const g = hopFixture(t, {}, '/repos/o/r/contents?ref=main')
  const result = await g.pipeline.handle(g.req({ headers: [...g.req().headers, ['X-GitHub-Api-Version', '2022-11-28'], ['accept', 'application/vnd.github+json']] }))
  assert.equal(result.status, 200); assert.equal(g.sent[1].url, 'https://api.example.test/repos/o/r/contents?ref=main')
  assert.equal(g.sent[1].headers['X-GitHub-Api-Version'], '2022-11-28')
})

test('the view reads a query as the union of its readers', () => {
  const view = requestView({ method: 'post', query: '?a=1;b=2&%5Fmethod=DELETE&c+d=e%20f&flag', headers: [['X-HTTP-Method-Override', 'put, PATCH']] })
  assert.equal(view.method, 'POST'); assert.equal(view.query, 'a=1;b=2&%5Fmethod=DELETE&c+d=e%20f&flag'); assert.equal(view.semicolon, true)
  assert.deepEqual(view.params.map(p => [p.rawName, p.name, p.value]), [['a', 'a', '1'], ['b', 'b', '2'], ['%5Fmethod', '_method', 'DELETE'], ['c+d', 'c d', 'e f'], ['flag', 'flag', '']])
  // Each reading's copy: split on `;` too, and on `&` alone.
  assert.deepEqual(view.overrides, { headers: ['PUT', 'PATCH'], fields: ['DELETE', 'DELETE'] })
  assert.deepEqual(requestView({ query: '.method=GET;force=1' }).overrides.fields, ['GET', 'GET;force=1'])
  // A loose request and its view are refused alike by the payload rules.
  assert.throws(() => evaluatePayload([FORCE.payload], { query: 'dry_run=true;force=true' }), { rule: 'request_ambiguous' })
  assert.throws(() => evaluatePayload([FORCE.payload], requestView({ query: 'dry_run=true;force=true' })), { rule: 'request_ambiguous' })
})

// ------------------------------------- round 6: a name its readers do not agree on

// PHP registers a name only up to a NUL and without its leading spaces, so
// it read `force%00` and `+force` as `force`, and `_method%00` and
// `%20%20_method` as `_method`, where the view saw other names. The grant
// was satisfied and the credential was sent. Two layers close the class: a
// name no API sends (a control character, a NUL, non-ASCII, a space at
// either end, or none at all) is refused on every path whatever the rules,
// and foldedNames reads a name the way PHP registers it.
const FORM_FORCE = { payload: { form: { force: { absent: true }, amount: { required: true } } } }
const QUERY_AMOUNT = { payload: { query: { force: { absent: true }, amount: { required: true } } } }
// Grok's payload table. A body row's hop carries the same pairs in the
// Location's query, under the same rules for the query: a hop has no body.
const PAYLOAD_ROWS = [
  ['query', 'dry_run=true&force%00=true'],
  ['query', 'dry_run=true&force%00x=true'],
  ['query', 'dry_run=true&force%00[]=true'],
  ['query', 'dry_run=true&+force=true'],
  ['query', 'dry_run=true&%20force=true'],
  ['query', 'dry_run=true&++force=true'],
  ['form', 'amount=2000&force%00=1'],
  ['form', 'amount=2000&+force=1'],
]
// Grok's method table: a POST, where the grant allows GET and POST and not DELETE.
const METHOD_ROWS = [
  ['query', '_method%00=DELETE'],
  ['form', 'a=1&_method%00=DELETE'],
  ['form', 'a=1&%20%20_method=DELETE'],
]

test('Grok round 6, payload: a name PHP reads as a ruled one is refused, and nothing is sent', async t => {
  for (const [where, pairs] of PAYLOAD_ROWS) {
    await t.test(`${where} ${pairs}`, async t => {
      const f = where === 'query' ? fixture(t, FORCE) : fixture(t, FORM_FORCE)
      const result = await f.pipeline.handle(where === 'query' ? f.req({ query: pairs }) : f.req({ method: 'POST', headers: [...f.req().headers, form], body: Buffer.from(pairs) }))
      assert.equal(result.status, 403, result.body.toString()); assert.equal(problem(result).rule, 'request_ambiguous')
      assert.equal(f.sent.length, 0); assert.equal(f.row.uses, 0); assert.equal(f.grant.budget_used, 0)
      // On a hop, after a first request the rules allowed.
      const h = hopFixture(t, where === 'query' ? FORCE : QUERY_AMOUNT, `https://api.example.test/next?${pairs}`)
      const hop = await h.pipeline.handle(h.req({ query: where === 'query' ? 'dry_run=true' : 'amount=1' }))
      assert.equal(hop.status, 302); assert.equal(hop.headers['av-redirect-stopped'], 'path'); assert.equal(h.sent.length, 1)
    })
  }
})

// The override check runs before the name check, so a stray name that is
// also an override naming another method is refused as the override it is.
test('Grok round 6, method: a name PHP reads as _method is refused, and a hop to it is not followed', async t => {
  for (const [where, pairs] of METHOD_ROWS) {
    await t.test(`${where} ${pairs}`, async t => {
      const f = fixture(t, { methods: ['GET', 'POST'] })
      const result = await f.pipeline.handle(where === 'query' ? f.req({ method: 'POST', query: pairs }) : f.req({ method: 'POST', headers: [...f.req().headers, form], body: Buffer.from(pairs) }))
      assert.equal(result.status, 403, result.body.toString()); assert.equal(problem(result).rule, 'method_override')
      assert.equal(f.sent.length, 0); assert.equal(f.row.uses, 0)
      // The /admin hop: checked as GET /admin/keys, where DELETE is not allowed.
      const h = hopFixture(t, { routes: ROUTES }, `https://api.example.test/admin/keys?${pairs}`)
      const hop = await h.pipeline.handle(h.req({ path: '/p/test/public/start' }))
      assert.equal(hop.status, 302); assert.equal(hop.headers['av-redirect-stopped'], 'path'); assert.equal(h.sent.length, 1)
    })
  }
})

// Every shape the hygiene check covers, with no payload rule at all: a name
// none of the rules or override fields would fold onto is refused all the
// same, because whether one does is the question the check stops asking.
const STRAY = ['force%00=1', '+force=1', '%20%20force=1', 'x%00=1','%00x=1', 'x%01=1', '%1Fx=1', 'x%7F=1', '%09x=1', 'x%09=1', '+x=1', 'x+=1', '%20x=1', 'x%20=1', 'x%0Ay=1', '%C3%A9=1', 'caf%C3%A9=1', 'x%FF=1', '=1', 'a=1&=2', 'a=1;%20b=2']
test('a stray name is refused on every path under any rules, and a hop to one is not followed', async t => {
  for (const query of STRAY) {
    await t.test(query, async t => {
      const f = fixture(t)
      const result = await f.pipeline.handle(f.req({ query }))
      assert.equal(result.status, 403, result.body.toString()); assert.equal(problem(result).rule, 'request_ambiguous'); assert.equal(f.sent.length, 0)
      const h = hopFixture(t, {}, `/next?${query}`)
      const hop = await h.pipeline.handle(h.req())
      assert.equal(hop.status, 302); assert.equal(hop.headers['av-redirect-stopped'], 'path'); assert.equal(h.sent.length, 1)
    })
  }
  // A form body, a multipart part's name or name*, and a top-level JSON key.
  // The stray names that are overrides naming another method are refused as
  // that; the rest as names no reader agrees on.
  for (const [type, body, rule] of [
    [form, 'a=1&%09b=2', 'request_ambiguous'],
    [form, 'a=1&b%C3%A9=2', 'request_ambiguous'],
    [form, 'a=1&force%00=1', 'request_ambiguous'],
    [multipart, `${part(' force', '1')}--XyZ--\r\n`, 'request_ambiguous'],
    [multipart, `${part('a\x01', '1')}--XyZ--\r\n`, 'request_ambiguous'],
    [multipart, `--XyZ\r\nContent-Disposition: form-data; name="a"; name*=utf-8''%C3%A9\r\n\r\n1\r\n--XyZ--\r\n`, 'request_ambiguous'],
    [json, '{"a":1," force":true}', 'request_ambiguous'],
    [json, '{"force\\u0000":true}', 'request_ambiguous'],
    [json, '{"model":"x","":1}', 'request_ambiguous'],
    [json, '{"modèle":"x"}', 'request_ambiguous'],
    [multipart, `${part(' _method', 'DELETE')}--XyZ--\r\n`, 'method_override'],
    [json, '{"a":1," _method":"DELETE"}', 'method_override'],
    [json, '{"_method\\u0000":"DELETE"}', 'method_override'],
  ]) {
    await t.test(`${type[1]} ${JSON.stringify(body)}`, async t => {
      const f = fixture(t)
      const result = await f.pipeline.handle(f.req({ method: 'POST', headers: [...f.req().headers, type], body: Buffer.from(body) }))
      assert.equal(result.status, 403, result.body.toString()); assert.equal(problem(result).rule, rule); assert.equal(f.sent.length, 0)
    })
  }
  // Preflight says the same and changes nothing.
  const g = fixture(t)
  const before = JSON.stringify(g.vault.db)
  const predicted = await g.pipeline.preflight(g.req({ query: '+force=1' }))
  assert.equal(predicted.would, 'deny'); assert.equal(predicted.checks.at(-1).rule, 'request_ambiguous')
  assert.equal(JSON.stringify(g.vault.db), before)
})

test('a multipart name* is read as busboy decodes it', async t => {
  const f = fixture(t, { methods: ['GET', 'POST', 'DELETE'] })
  const body = `--XyZ\r\nContent-Disposition: form-data; name="a"; name*=utf-8''%5Fmethod\r\n\r\nDELETE\r\n--XyZ--\r\n`
  const result = await f.pipeline.handle(f.req({ method: 'POST', headers: [...f.req().headers, multipart], body: Buffer.from(body) }))
  assert.equal(result.status, 403); assert.equal(problem(result).rule, 'method_override'); assert.equal(f.sent.length, 0)
})

// The second layer, read without the first: the payload rules and the
// override fields see the name PHP registers.
test('a name is folded the way PHP registers it: cut at NUL, leading spaces dropped', () => {
  for (const name of ['_method\0', '_method\0x', ' _method', '  _method', '   _method[]', ' .method', '_METHOD\0[]']) assert.equal(isOverrideField(name), true, JSON.stringify(name))
  for (const name of ['my_method', 'x\0_method', 'method']) assert.equal(isOverrideField(name), false, JSON.stringify(name))
  assert.ok(foldedNames('force\0x').includes('force')); assert.ok(foldedNames('  force[]').includes('force'))
  for (const query of ['dry_run=true&force%00=true', 'dry_run=true&force%00x=true', 'dry_run=true&force%00[]=true', 'dry_run=true&+force=true', 'dry_run=true&%20force=true', 'dry_run=true&++force=true', '%20dry_run=true']) {
    assert.throws(() => evaluatePayload([FORCE.payload], { query }), { rule: 'request_ambiguous' }, query)
  }
  assert.throws(() => evaluatePayload([FORM_FORCE.payload], { method: 'POST', contentType: 'application/x-www-form-urlencoded', body: Buffer.from('amount=2000&force%00=1') }), { rule: 'request_ambiguous' })
  for (const query of ['_method%00=DELETE', '%20%20_method=DELETE', '+_method=DELETE']) assert.deepEqual(requestView({ method: 'POST', query }).overrides.fields, ['DELETE'], query)
  // The view marks each stray name, and nothing else.
  for (const query of STRAY) assert.equal(requestView({ query }).strayName, true, query)
  for (const query of ['a=1', 'flag', 'a=1&&b=2', 'q=caf%C3%A9&tag=a+b', 'c+d=e', 'expand[]=data', 'metadata[order id]=1', 'a=1;b=2']) assert.equal(requestView({ query }).strayName, false, query)
  assert.equal(isStrayName(''), true); assert.equal(isStrayName('a b'), false)
})

test('ordinary provider traffic is sent unchanged under the name check', async t => {
  // OpenAI and Anthropic JSON, non-ASCII in values and in nested keys.
  const o = fixture(t, { hosts: ['api.openai.com'] }, { kind: 'openai' })
  const openai = Buffer.from(JSON.stringify({ model: 'gpt-4.1-mini', messages: [{ role: 'user', content: 'héllo ✓ 日本' }], metadata: { 'clé': 'v' }, response_format: { type: 'json_object' } }))
  const sent = await o.pipeline.handle(o.req({ method: 'POST', path: '/p/test/v1/chat/completions', headers: [...o.req().headers, json], body: openai }))
  assert.equal(sent.status, 200, sent.body.toString()); assert.ok(o.sent[0].body.equals(openai))
  const a = fixture(t, { hosts: ['api.anthropic.com'] }, { kind: 'anthropic' })
  a.vault.db.credentials[a.cred.id].fields.find(x => x.name === 'token').sites = ['header:x-api-key']
  const anthropic = Buffer.from(JSON.stringify({ model: 'claude-sonnet-4-5', max_tokens: 32, system: 'Réponds.', messages: [{ role: 'user', content: 'ping' }] }))
  const msg = await a.pipeline.handle(a.req({ method: 'POST', path: '/p/test/v1/messages', headers: [['host', 'localhost'], ['av-session', a.token], ['x-api-key', a.ph], ['anthropic-version', '2023-06-01'], json], body: anthropic }))
  assert.equal(msg.status, 200, msg.body.toString()); assert.equal(a.sent[0].headers['anthropic-version'], '2023-06-01'); assert.equal(a.sent[0].headers['x-api-key'], SECRET)
  // GitHub and Stripe queries, brackets included, with and without rules.
  for (const [policy, path, query] of [
    [{}, '/p/test/v1/models', 'limit=20&after_id=model_1'],
    [{}, '/p/test/repos/o/r/contents', 'ref=main'],
    [{}, '/p/test/search/issues', 'q=org%3Afoo+language%3Ago&per_page=30'],
    [{}, '/p/test/search/code', 'q=caf%C3%A9+in%3Afile'],
    [{}, '/p/test/v1/charges', 'limit=10&starting_after=ch_123&expand[]=data'],
    [{}, '/p/test/v1/charges', 'expand[]=data.customer&expand[]=data.invoice'],
    [{ payload: { query: { starting_after: { max_length: 64 } } } }, '/p/test/v1/charges', 'limit=10&starting_after=ch_123&expand[]=data'],
  ]) {
    const f = fixture(t, policy)
    const result = await f.pipeline.handle(f.req({ path, query }))
    assert.equal(result.status, 200, `${query}: ${result.body}`); assert.ok(f.sent[0].url.endsWith(`?${query}`), query)
  }
  for (const policy of [{}, { payload: { form: { amount: { required: true }, currency: { one_of: ['usd'] } } } }]) {
    const f = fixture(t, policy)
    const body = 'amount=2000&currency=usd&source=tok_visa&metadata[order_id]=6735&metadata[note]=caf%C3%A9&description=Order+6735'
    const result = await f.pipeline.handle(f.req({ method: 'POST', path: '/p/test/v1/charges', headers: [...f.req().headers, form], body: Buffer.from(body) }))
    assert.equal(result.status, 200, result.body.toString()); assert.equal(f.sent[0].body.toString(), body)
  }
  // A multipart upload with a filename, and a redirect to an ordinary query.
  const u = fixture(t)
  const upload = Buffer.from(`--XyZ\r\nContent-Disposition: form-data; name="purpose"\r\n\r\nfine-tune\r\n--XyZ\r\nContent-Disposition: form-data; name="file"; filename="données.jsonl"\r\nContent-Type: application/jsonl\r\n\r\n{"é":1}\r\n--XyZ--\r\n`)
  assert.equal((await u.pipeline.handle(u.req({ method: 'POST', headers: [...u.req().headers, multipart], body: upload }))).status, 200)
  const h = hopFixture(t, {}, '/v1/charges?limit=10&expand[]=data')
  assert.equal((await h.pipeline.handle(h.req())).status, 200); assert.equal(h.sent[1].url, 'https://api.example.test/v1/charges?limit=10&expand[]=data')
})
