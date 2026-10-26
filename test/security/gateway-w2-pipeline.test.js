import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Readable } from 'node:stream'
import { Vault } from '../../src/store/vault.js'
import { Pipeline, approvalPreview } from '../../src/daemon/pipeline.js'
import { deny } from '../../src/core/errors.js'
import { meterRequest, reservationFor } from '../../src/core/model-usage.js'

const SECRET = 'fixture_secret_gateway_only_0123456789'
function fixture(t, policy = {}, { kind = 'http', upstream, options = {} } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'av-gw-w2-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const vault = Vault.create(dir, { factor: 'none' })
  const added = vault.addCredential({ slug: 'test', kind, connector: { host: kind === 'openai' ? 'api.openai.com' : 'api.example.test' }, fields: { token: SECRET }, sites: { token: ['header:authorization:Bearer'] } })
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
