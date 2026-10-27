// Wave 2, gateway: the seams other batches build against, and the places the
// first draft of this batch got wrong. Each protection is shown firing AND
// not firing on ordinary input.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createServer } from 'node:http'
import { Readable } from 'node:stream'
import { Vault } from '../../src/store/vault.js'
import { Pipeline } from '../../src/daemon/pipeline.js'
import { evaluatePayload } from '../../src/core/payload.js'
import * as phMod from '../../src/core/placeholder.js'

const SECRET = 'fixture_secret_gateway_seams_0123456789'
const problem = (result) => JSON.parse(result.body)
const streamText = async (stream) => { let out = ''; for await (const chunk of stream) out += chunk; return out }

function fixture(t, policy = {}, { kind = 'http', host = 'api.example.test', upstream, options = {}, fetchImpl } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'av-gw-seams-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const vault = Vault.create(dir, { factor: 'none' })
  const added = vault.addCredential({ slug: 'test', kind, connector: { host }, fields: { token: SECRET }, sites: { token: ['header:authorization:Bearer'] } })
  const cred = vault.findCredential(added.slug)
  const { session, token } = vault.createSession({ label: 'seams', policy: {} })
  const grant = vault.createGrant({ sessionId: session.id, credentialId: cred.id, fields: ['token'], policy: { hosts: [policyHost(host)], methods: ['GET', 'POST', 'HEAD'], paths: ['/**'], budget: { unit: 'requests', limit: 100 }, approval: 'auto', ...policy } })
  const ph = vault.issuePlaceholder({ grantId: grant.id, field: 'token', maxUses: 100 }).placeholder
  const row = Object.values(vault.db.placeholders)[0]
  const sent = []
  const pipeline = new Pipeline(vault, {
    ...options,
    ...(fetchImpl === null ? {} : { fetchImpl: fetchImpl ?? (async (input) => { sent.push(input); return upstream ? upstream(input) : { status: 200, headers: { 'content-type': 'application/json' }, body: Buffer.from('{"ok":true}') } }) }),
  })
  const req = (over = {}) => ({ method: 'GET', path: '/p/test/ok', query: '', headers: [['host', 'localhost'], ['av-session', token], ['authorization', `Bearer ${ph}`]], body: null, ...over })
  return { dir, vault, cred, session, token, grant, ph, row, sent, pipeline, req }
}
const policyHost = (host) => host.split(':')[0]

// ------------------------------------------------------------------ F11 pins

test('pins on a plaintext credential refuse before any connection; no pins still connects', async (t) => {
  let connections = 0
  const server = createServer((req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"ok":true}') })
  server.on('connection', () => { connections++ })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  t.after(() => server.close())
  const host = `127.0.0.1:${server.address().port}`
  const f = fixture(t, {}, { host, fetchImpl: null })
  f.cred.connector.scheme = 'http'
  // The default upstream is the connectors' pinnedRequest: a pin cannot be
  // checked over plaintext, so it is refused unsent rather than dropped.
  f.cred.pins = { '127.0.0.1': ['sha256/' + 'A'.repeat(43) + '='] }
  const refused = await f.pipeline.handle(f.req())
  assert.equal(problem(refused).code, 'AV_PIN_MISMATCH')
  assert.equal(problem(refused).rule, 'pin_plaintext')
  assert.equal(problem(refused).refunded, true)
  assert.equal(f.row.uses, 0)
  assert.equal(connections, 0)
  // No pins: the request goes out exactly as before.
  f.cred.pins = undefined
  const allowed = await f.pipeline.handle(f.req())
  assert.equal(allowed.status, 200, allowed.body.toString())
  assert.equal(connections, 1)
})

// ------------------------------------------------------------- F10 F14 hooks

test('a throwing health reader or recorder never turns an executed request into a failure', async (t) => {
  const f = fixture(t, {}, { upstream: () => ({ status: 401, headers: {}, body: Buffer.from('{}') }) })
  f.pipeline.extractHealth = () => { throw new Error('connector bug') }
  assert.equal((await f.pipeline.handle(f.req())).status, 401)
  f.pipeline.extractHealth = () => ({ observed_expires_at: '2027-01-01T00:00:00.000Z' })
  f.vault.recordHealth = () => { throw new Error('store bug') }
  assert.equal((await f.pipeline.handle(f.req())).status, 401)
  // Nothing to observe on an ordinary 200 with no header reader output.
  const calls = []
  f.vault.recordHealth = (...a) => calls.push(a)
  f.pipeline.extractHealth = () => null
  f.pipeline.upstream = async () => ({ status: 200, headers: {}, body: Buffer.from('{}') })
  await f.pipeline.handle(f.req())
  assert.equal(calls.length, 0)
})

test('onPending gets the id and headline only, and a throwing hook still holds the request', async (t) => {
  const f = fixture(t, { approval: 'each' })
  const events = []
  f.pipeline.onPending = (e) => { events.push(e); throw new Error('notifier down') }
  const held = await f.pipeline.handle(f.req({ headers: [...f.req().headers, ['av-reason', 'please <script>']] }))
  assert.equal(held.status, 202)
  assert.deepEqual(Object.keys(events[0]).sort(), ['created_at', 'headline', 'id', 'kind'])
  assert.equal(events[0].kind, 'request')
  assert.ok(!JSON.stringify(events[0]).includes('script'))
  assert.ok(!JSON.stringify(events[0]).includes(f.ph))
})

// --------------------------------------------------------- F16 deny / panic

test('denyApprovals filters by session, credential and grant ids, records the reason, and returns a count', async (t) => {
  const f = fixture(t, { approval: 'each' })
  await f.pipeline.handle(f.req({ path: '/p/test/a' }))
  await f.pipeline.handle(f.req({ path: '/p/test/b' }))
  assert.equal(f.pipeline.denyApprovals({ sessionId: 'ses_other' }, 'tripwire'), 0)
  assert.equal(f.pipeline.denyApprovals({ grantIds: ['grt_other'] }, 'tripwire'), 0)
  assert.equal(f.pipeline.pendingApprovals().length, 2)
  const count = f.pipeline.denyApprovals({ grantIds: [f.grant.id] }, 'credential_rotated')
  assert.equal(typeof count, 'number')
  assert.equal(count, 2)
  const denied = [...f.pipeline.approvals.values()]
  assert.ok(denied.every((a) => a.state === 'denied' && a.denied_reason === 'credential_rotated'))
  const records = f.vault.audit.read().filter((r) => r.kind === 'approval.denied')
  assert.deepEqual(records.map((r) => r.reason ?? r.data?.reason), ['credential_rotated', 'credential_rotated'])
  // A consumed approval has run; it is not denied after the fact.
  const g = fixture(t, { approval: 'each' })
  await g.pipeline.handle(g.req())
  g.pipeline.decideApproval(g.pipeline.pendingApprovals()[0].id, true)
  assert.equal((await g.pipeline.handle(g.req())).status, 200)
  assert.equal(g.pipeline.denyAllPending('panic'), 0)
})

test('panic denies held requests, revokes every session including an infinite one, then the hook, then the record, then the lock', async (t) => {
  const f = fixture(t, { approval: 'each' })
  await f.pipeline.handle(f.req())
  const infinite = f.vault.createSession({ label: 'forever', policy: {} }).session
  infinite.infinite = true; infinite.expires_at = null
  const order = []
  f.pipeline.onPanic = async ({ reason, at_ms }) => {
    order.push(['hook', f.session.state, infinite.state, f.pipeline.pendingApprovals().length, typeof at_ms, reason])
    return { session_requests_denied: 2 }
  }
  const out = await f.pipeline.panic({ reason: 'it looked wrong', lock: true })
  assert.deepEqual(out, { revoked_sessions: 2, denied_approvals: 1, denied_session_requests: 2, locked: true })
  assert.deepEqual(order, [['hook', 'revoked', 'revoked', 0, 'number', 'it looked wrong']])
  assert.equal(f.vault.locked, true)
  const reopened = Vault.open(f.dir); reopened.unlock()
  const record = reopened.audit.read().find((r) => r.kind === 'panic.triggered')
  assert.ok(record, 'panic.triggered was written before the lock')
  // An already locked vault cannot be panicked again; nothing is revoked twice.
  await assert.rejects(f.pipeline.panic({}), (e) => e.code === 'AV_LOCKED')
})

test('a panic whose hook fails still revokes everything and records a partial panic', async (t) => {
  const f = fixture(t)
  f.pipeline.onPanic = async () => { throw new Error('session requests unavailable') }
  const out = await f.pipeline.panic({})
  assert.equal(out.denied_session_requests, null)
  assert.equal(out.revoked_sessions, 1)
  assert.equal(f.session.state, 'revoked')
  assert.equal(f.vault.audit.read().filter((r) => r.kind === 'tripwire.panic_partial').length, 1)
  // No hook at all: null, and no partial record, because nothing failed.
  const g = fixture(t)
  assert.equal((await g.pipeline.panic({})).denied_session_requests, null)
  assert.equal(g.vault.audit.read().filter((r) => r.kind === 'tripwire.panic_partial').length, 0)
})

test('a tripwire that throws while firing cannot cost the agent its denial', async (t) => {
  const f = fixture(t)
  f.pipeline.tripwires.observe = () => { throw new Error('tripwire bug') }
  const result = await f.pipeline.handle(f.req({ path: '/t/https/elsewhere.test/x' }))
  assert.equal(result.status, 403)
  assert.equal(problem(result).code, 'AV_NO_GRANT')
})

test('with tripwires on, a bad-location run revokes the session; ordinary requests never count', async (t) => {
  const f = fixture(t)
  f.vault.getSettings = () => ({ tripwires: { enabled: true, rules: 'not a list' } })
  for (let i = 0; i < 10; i++) assert.equal((await f.pipeline.handle(f.req())).status, 200)
  assert.equal(f.session.state, 'active')
  const bad = f.req({ method: 'POST', body: Buffer.from(`{"x":"${f.ph}"}`), headers: [...f.req().headers, ['content-type', 'application/json']] })
  for (let i = 0; i < 2; i++) assert.equal(problem(await f.pipeline.handle(bad)).code, 'AV_BAD_LOCATION')
  assert.equal(f.session.state, 'active')
  assert.equal(problem(await f.pipeline.handle(bad)).code, 'AV_BAD_LOCATION')
  assert.equal(f.session.state, 'revoked', 'unreadable rules fall back to the defaults, which fire on the third')
})

test('an unauthenticated replay never counts against the session its placeholder names', async (t) => {
  const f = fixture(t)
  f.vault.getSettings = () => ({ tripwires: { enabled: true } })
  // Minted with the vault's key for this session, never issued: the carrier
  // check refuses it before there is an authenticated session.
  const forged = phMod.mint({ kPh: f.vault.kPh, sid: f.session.id, slug: 'test', field: 'token' }).text
  for (let i = 0; i < 3; i++) {
    const result = await f.pipeline.handle(f.req({ headers: [['host', 'localhost'], ['authorization', `Bearer ${forged}`]] }))
    assert.equal(problem(result).code, 'AV_PH_REPLAY')
  }
  assert.equal(f.session.state, 'active')
  // The same replay from an authenticated session does fire.
  f.vault.burnPlaceholder(f.row.id)
  assert.equal(problem(await f.pipeline.handle(f.req())).code, 'AV_PH_REPLAY')
  assert.equal(f.session.state, 'revoked')
})

test('a quarantined credential is refused before anything is spent, and works again once released', async (t) => {
  const f = fixture(t, { rate: { count: 5, per: 'hour' }, quota: { count: 5, window: 'day' } })
  f.cred.quarantine = { since: new Date().toISOString(), by: 'control', reason_untrusted: null }
  const refused = await f.pipeline.handle(f.req())
  assert.equal(problem(refused).code, 'AV_QUARANTINED')
  assert.equal(problem(refused).rule, 'quarantine')
  assert.equal(f.row.uses, 0)
  assert.equal(f.grant.budget_used, 0)
  assert.equal(f.grant.quota_state, undefined)
  assert.equal(f.pipeline.limitsFor(f.grant.id).rate.tokens_now, 5)
  assert.equal(f.sent.length, 0)
  f.cred.quarantine = null
  assert.equal((await f.pipeline.handle(f.req())).status, 200)
})

// ------------------------------------------------------------ F20 preflight

test('preflight and the real route agree on finite, expired, infinite and legacy sessions and grants', async (t) => {
  const cases = [
    ['finite', { expires_at: new Date(Date.now() + 3_600_000).toISOString(), infinite: false }, 'allow'],
    ['expired', { expires_at: new Date(Date.now() - 60_000).toISOString(), infinite: false }, 'AV_SESSION_EXPIRED'],
    ['infinite', { expires_at: null, infinite: true }, 'allow'],
    ['legacy', { expires_at: null }, 'AV_SESSION_EXPIRED'],
    ['garbage', { expires_at: 'not a date', infinite: false }, 'AV_SESSION_EXPIRED'],
  ]
  for (const [name, patch, expected] of cases) {
    const f = fixture(t)
    Object.assign(f.session, patch)
    if (!('infinite' in patch)) delete f.session.infinite
    let pre
    try { pre = (await f.pipeline.preflight(f.req())).would } catch (e) { pre = e.code }
    const real = await f.pipeline.handle(f.req())
    const actual = real.status === 200 ? 'allow' : problem(real).code
    assert.equal(pre, expected, `${name}: preflight`)
    assert.equal(actual, expected, `${name}: the real route`)
  }
  for (const [name, expires_at, expected] of [['no ttl', undefined, 'allow'], ['future', new Date(Date.now() + 60_000).toISOString(), 'allow'], ['past', new Date(Date.now() - 60_000).toISOString(), 'AV_GRANT_EXPIRED'], ['garbage', 'nope', 'AV_GRANT_EXPIRED']]) {
    const f = fixture(t)
    if (expires_at !== undefined) f.grant.expires_at = expires_at
    const pre = await f.pipeline.preflight(f.req())
    const real = await f.pipeline.handle(f.req())
    assert.equal(pre.would === 'allow' ? 'allow' : pre.checks.at(-1).code, expected, `grant ${name}: preflight`)
    assert.equal(real.status === 200 ? 'allow' : problem(real).code, expected, `grant ${name}: the real route`)
  }
})

test('preflight writes one record with nulls, not undefined, and puts no hint where there was none', async (t) => {
  const f = fixture(t)
  const allowed = await f.pipeline.preflight(f.req())
  assert.equal(allowed.would, 'allow')
  const denied = await f.pipeline.preflight(f.req({ method: 'DELETE' }))
  assert.equal(denied.would, 'deny')
  const records = f.vault.audit.read().filter((r) => r.kind === 'request.preflighted')
  assert.equal(records.length, 2)
  const flat = JSON.stringify(records)
  assert.ok(flat.includes('"code":null') && flat.includes('"rule":null'), flat)
  assert.ok(!flat.includes('DELETE'))
  const unhinted = await f.pipeline.preflight(f.req({ path: '/p/test/x', headers: [['host', 'localhost'], ['av-session', f.token]] }), { assumePlaceholder: false })
  assert.equal(unhinted.would, 'deny')
  for (const check of unhinted.checks) assert.ok(!('hint' in check) || typeof check.hint === 'string')
})

// ----------------------------------------------------------- F6 redirects

test('a redirect to another port on an allowed host is not followed; the same port is', async (t) => {
  for (const [location, expected, hops] of [['https://api.example.test:8443/ok', 'host', 1], ['https://api.example.test/ok2', undefined, 2]]) {
    let n = 0
    const f = fixture(t, { redirects: { max: 2 } }, { upstream: () => (++n === 1 ? { status: 302, headers: { location }, body: Buffer.alloc(0) } : { status: 200, headers: {}, body: Buffer.from('done') }) })
    const result = await f.pipeline.handle(f.req())
    assert.equal(result.headers['av-redirect-stopped'], expected)
    assert.equal(f.sent.length, hops)
  }
})

test('a redirect hop that cannot connect closes the redirect it was following and is not refunded', async (t) => {
  let destroyed = false
  const first = { status: 302, headers: { location: '/next' }, body: Buffer.alloc(0), res: { destroy: () => { destroyed = true } } }
  let n = 0
  const f = fixture(t, { redirects: { max: 2 } }, { upstream: () => { if (++n === 1) return first; throw Object.assign(new Error('reset'), { code: 'ECONNRESET' }) } })
  const result = await f.pipeline.handle(f.req())
  assert.equal(problem(result).code, 'AV_UPSTREAM_UNREACHABLE')
  assert.equal(problem(result).refunded, false)
  assert.equal(destroyed, true)
  assert.equal(f.row.uses, 1)
})

// ------------------------------------------------------- F2 payload in path

test('GraphQL rules read the URL query on a POST too, and the decided path ends the /graphql check', async (t) => {
  const f = fixture(t, { payload: { graphql: { operations: ['query'] } } })
  const post = (query, body, path = '/p/test/graphql') => f.pipeline.handle(f.req({ method: 'POST', path, query, body: Buffer.from(body), headers: [...f.req().headers, ['content-type', 'application/json']] }))
  // Some servers run the URL's document even when the body has one.
  assert.equal(problem(await post('query=mutation%7Bx%7D', '{"query":"{a}"}')).rule, 'payload:graphql:operation')
  assert.equal((await post('', '{"query":"{a}"}')).status, 200)
  // `/graphql/.` is sent as /graphql, so it is checked as /graphql.
  assert.equal(problem(await f.pipeline.handle(f.req({ method: 'POST', path: '/p/test/graphql/.', body: Buffer.from('x=1'), headers: [...f.req().headers, ['content-type', 'text/plain']] }))).rule, 'graphql_unreadable')
  assert.equal(f.sent.length, 1)
})

test('a binary upload passes a grant whose payload rules only constrain the query', async (t) => {
  const f = fixture(t, { payload: { query: { mode: { one_of: ['safe'] } } } })
  const upload = f.req({ method: 'POST', query: 'mode=safe', body: Buffer.from([0xff, 0xfe, 0x00, 0x81]), headers: [...f.req().headers, ['content-type', 'application/octet-stream']] })
  assert.equal((await f.pipeline.handle(upload)).status, 200)
  assert.equal(problem(await f.pipeline.handle({ ...upload, query: 'mode=unsafe' })).rule, 'payload:query:mode:one_of')
})

test('a strict-query refusal names the parameter safely and never echoes a value', async (t) => {
  const f = fixture(t, { payload: { query: { a: {} }, query_strict: true } })
  const result = await f.pipeline.handle(f.req({ query: `a=1&${encodeURIComponent('evil<> "name"')}=SECRETVALUE` }))
  const p = problem(result)
  assert.equal(p.rule, `payload:query:${encodeURIComponent('evil<> "name"')}:strict`)
  assert.ok(!JSON.stringify(p).includes('SECRETVALUE'))
  // A name with a line break or non-ASCII is refused by the gateway before
  // the payload rules read it (a stray name), and that refusal echoes
  // nothing either. The payload rules alone still encode it in the rule.
  const stray = problem(await f.pipeline.handle(f.req({ query: `a=1&${encodeURIComponent('évil\nname')}=SECRETVALUE` })))
  assert.equal(stray.rule, 'request_ambiguous')
  assert.ok(!JSON.stringify(stray).includes('SECRETVALUE') && !JSON.stringify(stray).includes('vil'))
  assert.throws(() => evaluatePayload([{ query: { a: {} }, query_strict: true }], { query: `a=1&${encodeURIComponent('évil\nname')}=SECRETVALUE` }), { rule: `payload:query:${encodeURIComponent('évil\nname')}:strict` })
})

// -------------------------------------------------------------- F5 spend

const chat = (f, body) => f.req({ method: 'POST', path: '/p/test/v1/chat/completions', headers: [...f.req().headers, ['content-type', 'application/json']], body: Buffer.from(JSON.stringify(body)) })

test('a spend refusal says what is left and what the call could cost; a call that fits passes', async (t) => {
  const f = fixture(t, { spend: { tokens: 1000 } }, { kind: 'openai', host: 'api.openai.com', upstream: () => ({ status: 200, headers: { 'content-type': 'application/json' }, body: Buffer.from('{"usage":{"prompt_tokens":5,"completion_tokens":7}}') }) })
  const refused = problem(await f.pipeline.handle(chat(f, { model: 'gpt-4.1-mini', messages: [] })))
  assert.equal(refused.rule, 'spend')
  assert.match(refused.hint, /may spend 1000 more tokens; this call could cost up to 16\d{3} tokens/)
  assert.equal(f.sent.length, 0)
  assert.equal((await f.pipeline.handle(chat(f, { model: 'gpt-4.1-mini', max_tokens: 50, messages: [] }))).status, 200)
  assert.equal(f.grant.spend.tokens_used, 12)
})

test('a CRLF-framed stream settles on its usage; a cut stream charges the full reservation', async (t) => {
  for (const mode of ['crlf', 'cut']) {
    const events = mode === 'crlf'
      ? 'data: {"usage":{"prompt_tokens":3,"completion_tokens":4}}\r\n\r\n'
      : `data: {"delta":"${SECRET.slice(0, 15)}"}\n\ndata: {"delta":"${SECRET.slice(15)}"}\n\ndata: {"usage":{"prompt_tokens":3,"completion_tokens":4}}\n\n`
    const f = fixture(t, { spend: { tokens: 100000 } }, { kind: 'openai', host: 'api.openai.com', upstream: () => ({ status: 200, headers: { 'content-type': 'text/event-stream' }, res: Readable.from([Buffer.from(events)]) }) })
    const result = await f.pipeline.handle(chat(f, { model: 'gpt-4.1-mini', max_tokens: 50, messages: [] }))
    const text = await streamText(result.stream)
    if (mode === 'cut') assert.ok(text.includes('AV_UNSCANNABLE'))
    assert.equal(f.grant.spend.tokens_used, mode === 'crlf' ? 7 : result.spend.reserved_tokens, mode)
    const settled = f.vault.audit.read().filter((r) => r.kind === 'spend.settled')
    assert.equal(settled.length, 1)
  }
})

test('a pipeline built while the vault is locked charges stale reservations at the first request after unlock', async (t) => {
  const f = fixture(t, { spend: { tokens: 100000 } }, { kind: 'openai', host: 'api.openai.com' })
  f.grant.spend = { tokens_used: 0, usd_micros_used: 0, reserved: { req_stale: { tokens: 40, usd_micros: 0, at: Date.now() } } }
  f.vault.save()
  const reopened = Vault.open(f.dir)
  const pipeline = new Pipeline(reopened, { fetchImpl: async () => ({ status: 200, headers: {}, body: Buffer.from('{}') }) })
  reopened.unlock()
  const grant = reopened.db.grants[f.grant.id]
  assert.equal(Object.keys(grant.spend.reserved).length, 1, 'nothing could be charged while locked')
  await pipeline.handle(f.req())
  assert.deepEqual(grant.spend.reserved, {})
  assert.equal(grant.spend.tokens_used, 40)
  assert.equal(reopened.audit.read().filter((r) => r.kind === 'spend.reservation_charged').length, 1)
})

// ------------------------------------------------------------ F4 patterns

test('an extra pattern scrubs an error detail, is redacted within an event, and cuts a stream that splits it', async (t) => {
  const custom = 'acme_' + 'K'.repeat(30)
  const f = fixture(t, {}, { upstream: () => { throw Object.assign(new Error(`refused for ${custom}`), { code: 'ECONNREFUSED' }) } })
  f.cred.scrub_patterns = [{ id: 'sp_1', source: 'acme_[A-Z]{20,40}', added_at: new Date().toISOString() }]
  const failed = await f.pipeline.handle(f.req())
  assert.equal(problem(failed).code, 'AV_UPSTREAM_UNREACHABLE')
  assert.ok(!failed.body.toString().includes(custom))
  assert.ok(!JSON.stringify(f.vault.audit.read()).includes(custom))
  for (const [events, cut] of [[`data: {"text":"${custom}"}\n\n`, false], [`data: {"d":"${custom.slice(0, 12)}"}\n\ndata: {"d":"${custom.slice(12)}"}\n\n`, true]]) {
    f.pipeline.upstream = async () => ({ status: 200, headers: { 'content-type': 'text/event-stream' }, res: Readable.from([Buffer.from(events)]) })
    const text = await streamText((await f.pipeline.handle(f.req())).stream)
    assert.ok(!text.includes(custom), text)
    assert.equal(text.includes('AV_UNSCANNABLE'), cut)
  }
  // Ordinary text that mentions the prefix flows through untouched.
  f.pipeline.upstream = async () => ({ status: 200, headers: { 'content-type': 'text/event-stream' }, res: Readable.from([Buffer.from('data: {"text":"we use acme_ tooling"}\n\n')]) })
  assert.equal(await streamText((await f.pipeline.handle(f.req())).stream), 'data: {"text":"we use acme_ tooling"}\n\n')
})

test('a method-override header is held to the route pairs as well as the methods list', async (t) => {
  const f = fixture(t, { methods: ['GET', 'POST', 'DELETE'], routes: [{ methods: ['GET', 'POST'], paths: ['/**'] }, { methods: ['DELETE'], paths: ['/tmp/**'] }] })
  const override = (path) => f.req({ method: 'POST', path, headers: [...f.req().headers, ['x-http-method-override', 'DELETE']] })
  assert.equal(problem(await f.pipeline.handle(override('/p/test/repos/x'))).rule, 'routes')
  assert.equal((await f.pipeline.handle(override('/p/test/tmp/x'))).status, 200)
  assert.equal(f.sent.length, 1)
})

test('a held request is recorded as held, an allowed one as allow, a refused one as deny (C11)', async (t) => {
  const f = fixture(t, { approval: 'on-write' })
  assert.equal((await f.pipeline.handle(f.req({ method: 'POST' }))).status, 202)
  assert.equal((await f.pipeline.handle(f.req())).status, 200)
  assert.equal((await f.pipeline.handle(f.req({ method: 'DELETE' }))).status, 403)
  const rows = f.vault.audit.read()
  const held = rows.filter((r) => r.kind === 'request.allowed' && r.decision === 'held')
  const allowed = rows.filter((r) => r.kind === 'request.allowed' && r.decision === 'allow')
  assert.equal(held.length, 1)
  assert.equal(held[0].req.status, 202)
  const requested = rows.find((r) => r.kind === 'approval.requested')
  assert.equal(held[0].request_id, requested.request_id)
  assert.equal(allowed.length, 1)
  assert.equal(allowed[0].req.status, 200)
  assert.equal(rows.filter((r) => r.decision === 'deny').length, 1)
})
